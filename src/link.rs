//! 与对端之间的消息通道，以及地址处理。
//!
//! 一条 TCP 连接上跑 protobuf 消息：先分帧，握手完成后再加一层对称加密。
//! 加密是在会话中途才启用的——握手本身必须明文，因为密钥就是那时候换的。

use crate::wire::{Cipher, FrameCodec};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use protobuf::Message as ProtoMessage;
use sodiumoxide::crypto::secretbox::Key;
use std::io;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

/// 建连与单次收发的超时。
pub const CONNECT_TIMEOUT: u64 = 18_000;
/// 中继服务器的默认端口。
pub const RELAY_PORT: i32 = 21117;
/// 公共信令服务器的签名公钥，用于验证对端身份。自建服务器用 `--key` 覆盖。
pub const RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";

/// 给 future 套一个超时，超时按错误返回。
pub async fn timeout<T: std::future::Future>(
    ms: u64,
    future: T,
) -> Result<T::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future).await
}

/// 形如 `host:port` 的地址里，冒号多于一个就只能是 IPv6。
fn is_ipv6(host: &str) -> bool {
    host.starts_with('[') || host.matches(':').count() > 1
}

/// 补上默认端口。已经带端口的原样返回。
pub fn check_port<T: ToString>(host: T, port: i32) -> String {
    let host = host.to_string();
    if is_ipv6(&host) {
        if host.starts_with('[') {
            return host;
        }
        return format!("[{host}]:{port}");
    }
    if !host.contains(':') {
        return format!("{host}:{port}");
    }
    host
}

/// 端口加上偏移。信令服务器的下一个端口就是中继端口，靠这个推出来。
pub fn increase_port<T: ToString>(host: T, offset: i32) -> String {
    let host = host.to_string();
    if let Some((addr, port)) = split_port(&host) {
        if let Ok(port) = port.parse::<i32>() {
            if port > 0 {
                return format!("{addr}:{}", port + offset);
            }
        }
    }
    host
}

/// 拆出地址和端口部分，IPv6 的 `[..]:port` 也能正确处理。
fn split_port(host: &str) -> Option<(&str, &str)> {
    if host.starts_with('[') {
        let (addr, port) = host.split_once("]:")?;
        return Some((&host[..addr.len() + 1], port));
    }
    if host.matches(':').count() == 1 {
        return host.split_once(':');
    }
    None
}

/// 解出信令服务器给的对端地址。
///
/// 地址不是直接放上去的，而是和一个微秒时间戳混在一起再截掉高位的零字节。
/// 时间戳本身也编码在里面，所以解的时候不需要知道它是什么。这是对端的编码
/// 方式，必须照它来。
///
/// 空字节串表示没有可直连的地址，返回 None——这是正常情况，不是错误。
pub fn decode_peer_addr(bytes: &[u8]) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    if bytes.is_empty() {
        return None;
    }
    // IPv6 是 16 字节地址加 2 字节小端端口，不做混淆。
    if bytes.len() > 16 {
        if bytes.len() != 18 {
            return None;
        }
        let ip: [u8; 16] = bytes[..16].try_into().ok()?;
        let port: [u8; 2] = bytes[16..].try_into().ok()?;
        return Some(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(ip)),
            u16::from_le_bytes(port),
        ));
    }
    let mut padded = [0u8; 16];
    padded[..bytes.len()].copy_from_slice(bytes);
    let number = u128::from_le_bytes(padded);
    let tm = (number >> 17) & (u32::MAX as u128);
    // 用 wrapping：字节是从网络上来的，算术溢出不该让进程崩掉。
    let ip = (((number >> 49).wrapping_sub(tm)) as u32).to_le_bytes();
    let port = (number & 0xFF_FFFF).wrapping_sub(tm & 0xFFFF) as u16;
    Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        port,
    ))
}

/// 一条 protobuf 消息通道。
pub struct Link {
    framed: Framed<TcpStream, FrameCodec>,
    /// 握手完成后才有。在此之前收发都是明文。
    cipher: Option<Cipher>,
}

impl Link {
    /// 建立 TCP 连接。地址可以是 `host:port`，也可以是已解析的地址。
    pub async fn connect(addr: &str, timeout_ms: u64) -> Result<Self> {
        let stream = timeout(timeout_ms, TcpStream::connect(addr))
            .await
            .with_context(|| format!("connecting to {addr} timed out"))?
            .with_context(|| format!("connecting to {addr}"))?;
        // 终端流量是很多很小的包，Nagle 会把它们攒起来，直接表现为按键延迟。
        stream.set_nodelay(true).ok();
        Ok(Self { framed: Framed::new(stream, FrameCodec::new()), cipher: None })
    }

    /// 启用对称加密。此后收发的每一帧都经过它。
    pub fn set_key(&mut self, key: Key) {
        self.cipher = Some(Cipher::new(key));
    }

    /// 发一条 protobuf 消息。
    pub async fn send(&mut self, msg: &impl ProtoMessage) -> Result<()> {
        let mut bytes = msg.write_to_bytes()?;
        if let Some(cipher) = self.cipher.as_mut() {
            bytes = cipher.seal(&bytes);
        }
        self.framed.send(Bytes::from(bytes)).await?;
        Ok(())
    }

    /// 收一帧。返回的是已解密的原始字节，由调用方决定解析成哪种消息。
    pub async fn next(&mut self) -> Option<Result<BytesMut, io::Error>> {
        let mut frame = self.framed.next().await;
        if let (Some(Ok(bytes)), Some(cipher)) = (frame.as_mut(), self.cipher.as_mut()) {
            if let Err(e) = cipher.open(bytes) {
                return Some(Err(e));
            }
        }
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_port_fills_in_a_missing_port() {
        assert_eq!(check_port("example.com", 21116), "example.com:21116");
        assert_eq!(check_port("1.2.3.4", 21117), "1.2.3.4:21117");
    }

    #[test]
    fn check_port_leaves_an_existing_port_alone() {
        assert_eq!(check_port("example.com:1234", 21116), "example.com:1234");
        assert_eq!(check_port("[::1]:1234", 21116), "[::1]:1234");
    }

    #[test]
    fn check_port_brackets_a_bare_ipv6_address() {
        assert_eq!(check_port("fe80::1", 21116), "[fe80::1]:21116");
    }

    #[test]
    fn increase_port_steps_the_port() {
        // How the relay port is derived from the rendezvous port.
        assert_eq!(increase_port("example.com:21116", 1), "example.com:21117");
        assert_eq!(increase_port("[::1]:21116", 1), "[::1]:21117");
    }

    /// 按对端的编码方式造一个地址，用来验证解码。
    fn encode_peer_addr(ip: [u8; 4], port: u16, tm: u32) -> Vec<u8> {
        let ip = u32::from_le_bytes(ip) as u128;
        let tm = tm as u128;
        let v = ((ip + tm) << 49) | (tm << 17) | (port as u128 + (tm & 0xFFFF));
        let bytes = v.to_le_bytes();
        let padding = bytes.iter().rev().take_while(|b| **b == 0).count();
        bytes[..16 - padding].to_vec()
    }

    #[test]
    fn a_mangled_ipv4_address_decodes_back() {
        use std::net::SocketAddr;
        // Several timestamps, because the encoding mixes one in and the
        // trailing-zero trim makes the length vary with it.
        for tm in [1u32, 0xFFFF, 0x1234_5678, u32::MAX] {
            let raw = encode_peer_addr([192, 168, 1, 50], 21118, tm);
            let got = decode_peer_addr(&raw).expect("decodes");
            assert_eq!(got, "192.168.1.50:21118".parse::<SocketAddr>().unwrap(), "tm={tm}");
        }
    }

    #[test]
    fn a_mangled_ipv6_address_decodes_back() {
        let mut raw = [0u8; 18];
        raw[..16].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        raw[16..].copy_from_slice(&21118u16.to_le_bytes());
        let got = decode_peer_addr(&raw).expect("decodes");
        assert_eq!(got.port(), 21118);
        assert!(got.is_ipv6());
    }

    #[test]
    fn no_address_is_not_an_error() {
        // An empty field means the server offered no direct address, which is
        // ordinary — the caller falls back to the relay.
        assert!(decode_peer_addr(&[]).is_none());
        // A length that cannot be either form is refused rather than guessed at.
        assert!(decode_peer_addr(&[0u8; 17]).is_none());
    }

    #[test]
    fn increase_port_leaves_an_address_without_a_port_alone() {
        assert_eq!(increase_port("example.com", 1), "example.com");
        // A bare IPv6 address is all colons and no port; stepping it would
        // corrupt the address.
        assert_eq!(increase_port("fe80::1", 1), "fe80::1");
    }
}
