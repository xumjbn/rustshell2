//! 线格式：长度前缀分帧，以及会话建立后的对称加密。
//!
//! 这一层必须与对端**字节精确**一致，错一个字节就什么都对不上，所以下面每
//! 条规则都注明了它是什么、以及为什么不能随手改。
//!
//! 分帧：长度左移 2 位，低 2 位表示头部自身占几个字节。这样小包的头只有 1
//! 字节——终端流量绝大多数是几十字节的按键和小段输出，省下的就是这部分。
//!
//! 加密：secretbox（XSalsa20-Poly1305），nonce 由序号推出。收发各自一个序
//! 号，互不相干。

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/// 一个帧最长 64 MiB。没有上限的话，一个坏掉或恶意的长度头就能让我们
/// 直接按它说的数字去分配内存。
const MAX_FRAME: usize = 64 << 20;

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    /// 还在等长度头。
    Head,
    /// 头已读到，正在等这么多字节的载荷。
    Body(usize),
}

/// 长度前缀分帧。
pub struct FrameCodec {
    state: DecodeState,
}

impl FrameCodec {
    pub fn new() -> Self {
        Self { state: DecodeState::Head }
    }

    /// 长度头，如果还没收满就返回 None。
    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<usize>> {
        if src.is_empty() {
            return Ok(None);
        }
        // 低 2 位就是「头部还有几个字节」，所以第一个字节永远够判断长度。
        let head_len = ((src[0] & 0x3) + 1) as usize;
        if src.len() < head_len {
            return Ok(None);
        }
        let mut n = src[0] as usize;
        for i in 1..head_len {
            n |= (src[i] as usize) << (8 * i);
        }
        n >>= 2;
        if n > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        src.advance(head_len);
        src.reserve(n);
        Ok(Some(n))
    }
}

impl Decoder for FrameCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let n = match self.state {
            DecodeState::Head => match self.decode_head(src)? {
                Some(n) => {
                    // 记下来：载荷可能要跨好几次读取才收齐，而头已经被消费掉了。
                    self.state = DecodeState::Body(n);
                    n
                }
                None => return Ok(None),
            },
            DecodeState::Body(n) => n,
        };
        if src.len() < n {
            return Ok(None);
        }
        self.state = DecodeState::Head;
        Ok(Some(src.split_to(n)))
    }
}

impl Encoder<Bytes> for FrameCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        let n = data.len();
        if n > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        // 头部宽度由长度决定，低 2 位写进宽度标记。三字节那档没有对应的整数
        // 类型，所以拆成 u16 + u8 两次写。
        buf.reserve(n + 4);
        if n < 0x40 {
            buf.put_u8((n << 2) as u8);
        } else if n < 0x4000 {
            buf.put_u16_le(((n << 2) | 0x1) as u16);
        } else if n < 0x40_0000 {
            let h = ((n << 2) | 0x2) as u32;
            buf.put_u16_le((h & 0xFFFF) as u16);
            buf.put_u8((h >> 16) as u8);
        } else {
            buf.put_u32_le(((n << 2) | 0x3) as u32);
        }
        buf.put_slice(&data);
        Ok(())
    }
}

/// 会话密钥与两个方向的序号。
pub struct Cipher {
    key: Key,
    sent: u64,
    received: u64,
}

impl Cipher {
    pub fn new(key: Key) -> Self {
        Self { key, sent: 0, received: 0 }
    }

    /// nonce 的前 8 字节是小端序号，其余为零。
    fn nonce(seq: u64) -> Nonce {
        let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
        nonce.0[..8].copy_from_slice(&seq.to_le_bytes());
        nonce
    }

    /// 序号**先自增再使用**，所以第一条消息用的是 1，不是 0。
    pub fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        self.sent += 1;
        secretbox::seal(data, &Self::nonce(self.sent), &self.key)
    }

    /// 长度 ≤1 的帧原样放过，且**不推进序号**。
    ///
    /// 保活消息序列化后是 0 字节，对端就是这么处理的；这里跟着推进序号的话，
    /// 两边的计数就会错开，之后每一条消息都解不开。
    pub fn open(&mut self, bytes: &mut BytesMut) -> Result<(), io::Error> {
        if bytes.len() <= 1 {
            return Ok(());
        }
        self.received += 1;
        match secretbox::open(bytes, &Self::nonce(self.received), &self.key) {
            Ok(plain) => {
                bytes.clear();
                bytes.put_slice(&plain);
                Ok(())
            }
            Err(()) => Err(io::Error::new(io::ErrorKind::Other, "decryption failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) -> (Vec<u8>, usize) {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        let payload = Bytes::from(vec![0xABu8; len]);
        codec.encode(payload, &mut buf).unwrap();
        let head_len = buf.len() - len;
        let raw = buf.to_vec();
        let decoded = codec.decode(&mut buf).unwrap().expect("a whole frame");
        assert_eq!(decoded.len(), len);
        (raw, head_len)
    }

    #[test]
    fn header_width_follows_the_payload_size() {
        // The four size classes, at their boundaries. A header that grows one
        // byte early or late puts every following byte in the wrong place.
        assert_eq!(roundtrip(0).1, 1);
        assert_eq!(roundtrip(0x3F).1, 1);
        assert_eq!(roundtrip(0x40).1, 2);
        assert_eq!(roundtrip(0x3FFF).1, 2);
        assert_eq!(roundtrip(0x4000).1, 3);
        assert_eq!(roundtrip(0x3F_FFFF).1, 3);
        assert_eq!(roundtrip(0x40_0000).1, 4);
    }

    #[test]
    fn header_bytes_are_exactly_as_specified() {
        // Known encodings, so a refactor cannot quietly change the wire.
        let (raw, _) = roundtrip(1);
        assert_eq!(raw[0], 0b100, "1 byte payload: len<<2, class 0");
        let (raw, _) = roundtrip(0x40);
        // 0x40 << 2 == 0x100, class 1 -> low byte 0x01, high byte 0x01
        assert_eq!(&raw[..2], &[0x01, 0x01]);
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(Bytes::from(vec![7u8; 5000]), &mut buf).unwrap();

        // Feed it in three pieces, including a split inside the header.
        let whole = buf.split().freeze();
        let mut incoming = BytesMut::new();
        incoming.put_slice(&whole[..1]);
        assert!(codec.decode(&mut incoming).unwrap().is_none(), "header incomplete");
        incoming.put_slice(&whole[1..100]);
        assert!(codec.decode(&mut incoming).unwrap().is_none(), "body incomplete");
        incoming.put_slice(&whole[100..]);
        let frame = codec.decode(&mut incoming).unwrap().expect("now complete");
        assert_eq!(frame.len(), 5000);
    }

    #[test]
    fn back_to_back_frames_decode_one_at_a_time() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(Bytes::from_static(b"first"), &mut buf).unwrap();
        codec.encode(Bytes::from_static(b"second"), &mut buf).unwrap();
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"first");
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"second");
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn an_oversized_length_is_refused_rather_than_allocated() {
        let mut codec = FrameCodec::new();
        // Class 3 header claiming a huge payload.
        let mut buf = BytesMut::new();
        buf.put_u32_le((u32::MAX << 2) | 0x3);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn sealing_starts_at_sequence_one() {
        // The counter increments before use. Starting at zero instead makes
        // every message undecryptable to the peer.
        let key = secretbox::gen_key();
        let mut a = Cipher::new(key.clone());
        let sealed = a.seal(b"hello");
        assert_eq!(a.sent, 1);

        let opened = secretbox::open(&sealed, &Cipher::nonce(1), &key).unwrap();
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn two_ciphers_stay_in_step_over_many_messages() {
        let key = secretbox::gen_key();
        let (mut send, mut recv) = (Cipher::new(key.clone()), Cipher::new(key));
        for i in 0..50u8 {
            let mut frame = BytesMut::from(&send.seal(&[i; 20])[..]);
            recv.open(&mut frame).expect("in step");
            assert_eq!(&frame[..], &[i; 20]);
        }
    }

    #[test]
    fn tiny_frames_bypass_decryption_without_moving_the_counter() {
        // A keepalive serialises to nothing. If it advanced the receive
        // counter, every message after it would fail to open.
        let key = secretbox::gen_key();
        let (mut send, mut recv) = (Cipher::new(key.clone()), Cipher::new(key));

        let mut empty = BytesMut::new();
        recv.open(&mut empty).unwrap();
        assert_eq!(recv.received, 0, "counter must not move");

        let mut one = BytesMut::from(&b"x"[..]);
        recv.open(&mut one).unwrap();
        assert_eq!(recv.received, 0, "counter must not move");
        assert_eq!(&one[..], b"x", "passed through untouched");

        // And a real message still opens.
        let mut frame = BytesMut::from(&send.seal(b"payload")[..]);
        recv.open(&mut frame).expect("still in step");
        assert_eq!(&frame[..], b"payload");
    }

    #[test]
    fn a_tampered_frame_is_rejected() {
        let key = secretbox::gen_key();
        let (mut send, mut recv) = (Cipher::new(key.clone()), Cipher::new(key));
        let mut frame = BytesMut::from(&send.seal(b"authentic")[..]);
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert!(recv.open(&mut frame).is_err());
    }
}
