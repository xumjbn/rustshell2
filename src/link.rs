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
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, FramedRead, FramedWrite};

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
        Ok(Self {
            framed: Framed::new(stream, FrameCodec::new()),
            cipher: None,
        })
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

    /// 拆成互不相干的收、发两半。
    ///
    /// 握手是严格的一问一答，用整条 `Link` 就够；进入终端会话之后不行。那时
    /// 两个方向是独立的：远端在不停地写，我们也要能随时发按键。只要收发共用
    /// 一个 `&mut`，一次写阻塞就会连带让读停下——而对端正好在等我们读，于是
    /// 两边各等各的，谁也不动。拆开之后读永远在跑，写再怎么堵也堵不住它，那
    /// 个环就成立不了。
    ///
    /// 必须用 `TcpStream::into_split` 而不是 `StreamExt::split`：后者两半共享
    /// 一把 `BiLock`，写在 flush 期间持锁，读照样被挡在外面，等于没拆。
    pub fn split(self) -> (LinkReader, LinkWriter) {
        use tokio_util::codec::Decoder;

        let cipher = self.cipher;
        let mut parts = self.framed.into_parts();

        // 先，把已经读进来但还没解出去的字节里的完整帧全部取出来。
        //
        // 这一步不能省。`FramedRead` 只有在**从 socket 又读到东西之后**才会去
        // 解自己的缓冲；直接把这段字节塞进它的缓冲，它会先去 socket 上等。而
        // 此刻对端很可能正等着我们先把这些处理完才继续发——于是双方对等，一
        // 个字节也不会再动。登录响应和它后面的终端数据经常落在同一次 TCP 读
        // 里，所以这不是边角情况。
        let mut ready: std::collections::VecDeque<Result<BytesMut, io::Error>> =
            std::collections::VecDeque::new();
        loop {
            match parts.codec.decode(&mut parts.read_buf) {
                Ok(Some(frame)) => ready.push_back(Ok(frame)),
                Ok(None) => break,
                // 坏帧照样排进队列，让它在轮到自己的位置上报出来，而不是在这里
                // 被吞掉。
                Err(e) => {
                    ready.push_back(Err(e));
                    break;
                }
            }
        }

        let (rx, tx) = parts.io.into_split();
        // codec 必须搬过去而不是新建一个：`FrameCodec` 记着自己是在等长度头
        // 还是在等某个已知长度的载荷，丢了这个状态，下一帧就从半截开始解。
        let mut read = FramedRead::new(rx, parts.codec);
        // 上面取剩下的是半截帧。它本来就要等 socket 再给点字节才能凑齐，所以
        // 放进 FramedRead 的缓冲里正合适。
        if !parts.read_buf.is_empty() {
            read.read_buffer_mut().unsplit(parts.read_buf);
        }
        // 编码器是无状态的，新建一个即可；待发字节仍要搬。
        let mut write = FramedWrite::new(tx, FrameCodec::new());
        if !parts.write_buf.is_empty() {
            write.write_buffer_mut().unsplit(parts.write_buf);
        }

        (
            LinkReader {
                framed: read,
                ready,
                cipher: cipher.clone(),
            },
            LinkWriter {
                framed: write,
                cipher,
            },
        )
    }
}

/// `Link` 的收半边。
pub struct LinkReader {
    framed: FramedRead<OwnedReadHalf, FrameCodec>,
    /// split 那一刻就已经在缓冲里、解得出来的帧，先于 socket 上的新帧交付。
    ready: std::collections::VecDeque<Result<BytesMut, io::Error>>,
    cipher: Option<Cipher>,
}

impl LinkReader {
    /// 收一帧，语义与 `Link::next` 完全一致。
    pub async fn next(&mut self) -> Option<Result<BytesMut, io::Error>> {
        // 顺序不能乱：解密的序号是按到达顺序推进的，插一帧或错一帧，之后每一
        // 条都解不开。
        let mut frame = match self.ready.pop_front() {
            Some(frame) => Some(frame),
            None => self.framed.next().await,
        };
        if let (Some(Ok(bytes)), Some(cipher)) = (frame.as_mut(), self.cipher.as_mut()) {
            if let Err(e) = cipher.open(bytes) {
                return Some(Err(e));
            }
        }
        frame
    }
}

/// `Link` 的发半边。
pub struct LinkWriter {
    framed: FramedWrite<OwnedWriteHalf, FrameCodec>,
    cipher: Option<Cipher>,
}

impl LinkWriter {
    /// 发一条 protobuf 消息，语义与 `Link::send` 完全一致。
    ///
    /// 序号由调用顺序决定，所以这一半必须由单独一个任务独占；多处并发调用会
    /// 让封包顺序和上线顺序对不上，对端从此一条也解不开。
    pub async fn send(&mut self, msg: &impl ProtoMessage) -> Result<()> {
        let mut bytes = msg.write_to_bytes()?;
        if let Some(cipher) = self.cipher.as_mut() {
            bytes = cipher.seal(&bytes);
        }
        self.framed.send(Bytes::from(bytes)).await?;
        Ok(())
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
            assert_eq!(
                got,
                "192.168.1.50:21118".parse::<SocketAddr>().unwrap(),
                "tm={tm}"
            );
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

    /// 建一对真的 TCP 连接。`Link` 只认 `TcpStream`,拿 duplex 之类的内存管道
    /// 替代不了——`split` 要做的正是 `TcpStream::into_split`。
    async fn connected_pair() -> (Link, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = Link::connect(&addr.to_string(), 5_000).await.unwrap();
        (client, accept.await.unwrap())
    }

    /// 按线格式打一个帧头。
    fn frame(payload: &[u8]) -> Vec<u8> {
        use bytes::BufMut;
        let mut buf = bytes::BytesMut::new();
        let n = payload.len();
        assert!(n < 0x40, "这个测试只用小帧");
        buf.put_u8((n << 2) as u8);
        buf.put_slice(payload);
        buf.to_vec()
    }

    #[tokio::test]
    async fn split_keeps_bytes_that_were_already_read() {
        use tokio::io::AsyncWriteExt;

        let (mut link, mut peer) = connected_pair().await;

        // 三帧一次写出去,极可能落在同一次 TCP 读里。
        let mut wire = frame(b"one");
        wire.extend(frame(b"two"));
        wire.extend(frame(b"three"));
        peer.write_all(&wire).await.unwrap();
        peer.flush().await.unwrap();

        // 只取第一帧。剩下两帧此时已经躺在 Framed 的读缓冲里了——真实场景就是
        // 登录响应和它后面的终端数据挤在同一次读里。
        let first = link.next().await.unwrap().unwrap();
        assert_eq!(&first[..], b"one");

        // 拆开。读缓冲不搬过去的话，后面两帧就凭空消失。
        let (mut reader, _writer) = link.split();
        let second = reader.next().await.unwrap().unwrap();
        assert_eq!(&second[..], b"two", "缓冲里的帧在 split 时丢了");
        let third = reader.next().await.unwrap().unwrap();
        assert_eq!(&third[..], b"three");
    }

    #[tokio::test]
    async fn split_keeps_a_half_arrived_frame() {
        use tokio::io::AsyncWriteExt;

        let (mut link, mut peer) = connected_pair().await;

        // 一个帧头加半截载荷。解码器读掉了头、正等着剩下的字节——split 时必须
        // 把这个「还差多少」的状态一起搬走,否则下一帧会从半截开始解。
        let whole = frame(b"payload");
        peer.write_all(&whole[..4]).await.unwrap();
        peer.flush().await.unwrap();

        // 逼 Framed 真的去读一次，从而进入等载荷的状态。
        let pending = timeout(150, link.next()).await;
        assert!(pending.is_err(), "半截帧不该解出东西来");

        let (mut reader, _writer) = link.split();
        peer.write_all(&whole[4..]).await.unwrap();
        peer.flush().await.unwrap();
        let frame = timeout(2_000, reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&frame[..], b"payload", "跨 split 边界的帧解错了");
    }

    #[tokio::test]
    async fn the_two_halves_keep_their_own_sequence_numbers() {
        use sodiumoxide::crypto::secretbox;

        let (mut link, peer) = connected_pair().await;
        let key = secretbox::gen_key();
        link.set_key(key.clone());

        // 对端的收方向:序号从 1 开始,与我们的发方向对齐。
        let mut peer_link = Link {
            framed: Framed::new(peer, FrameCodec::new()),
            cipher: None,
        };
        peer_link.set_key(key);

        let (_reader, mut writer) = link.split();
        for id in 0..5 {
            let mut msg = crate::proto::rustshell::CloseTerminal::new();
            msg.terminal_id = id;
            writer.send(&msg).await.unwrap();
        }
        // 序号错开一格,对端从此一条也解不开;顺序乱了则 id 对不上。两种都要挡住。
        for id in 0..5 {
            let got = peer_link
                .next()
                .await
                .unwrap()
                .expect("序号对不上就解不开了");
            let parsed = crate::proto::rustshell::CloseTerminal::parse_from_bytes(&got).unwrap();
            assert_eq!(parsed.terminal_id, id, "拆开之后发方向的顺序乱了");
        }
    }

    #[test]
    fn increase_port_leaves_an_address_without_a_port_alone() {
        assert_eq!(increase_port("example.com", 1), "example.com");
        // A bare IPv6 address is all colons and no port; stepping it would
        // corrupt the address.
        assert_eq!(increase_port("fe80::1", 1), "fe80::1");
    }
}
