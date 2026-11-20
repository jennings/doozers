//! The parts of the SSH transport the scan needs before encryption starts: the identification
//! string exchange (RFC 4253 section 4.2), the binary packet protocol without encryption or MAC
//! (section 6), and the data types of RFC 4251 section 5.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _};

/// The largest `packet_length` accepted (RFC 4253 section 6.1: implementations must handle 35000
/// bytes of packet; a longer one is refused).
pub(super) const MAX_PACKET: usize = 35_000;

/// The longest identification string, without its line ending (RFC 4253 section 4.2 allows 255
/// bytes including `CR LF`).
const MAX_IDENTIFICATION: usize = 253;

/// The longest line a server may send before its identification string.
const MAX_PRE_BANNER_LINE: usize = 4096;

/// The most lines a server may send before its identification string.
const MAX_PRE_BANNER_LINES: usize = 64;

/// Padding is aligned to this many bytes without a cipher (RFC 4253 section 6).
const BLOCK: usize = 8;

/// Why reading from the server failed.
#[derive(Debug)]
pub(super) enum WireError {
    /// The connection failed.
    Io(io::Error),
    /// The server closed the connection.
    Eof,
    /// A line or packet was longer than allowed.
    TooLong,
    /// The data isn't what the protocol says.
    Malformed(&'static str),
    /// The server's identification string names a protocol version other than 2.
    Version(Vec<u8>),
}

impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Self::Eof
        } else {
            Self::Io(error)
        }
    }
}

/// Reads up to and including the next `LF`, returning the line without `LF` or a `CR` before it.
/// Fails with [`WireError::TooLong`] when the line has more than `max` bytes before its `LF`.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<Vec<u8>, WireError> {
    let mut line = Vec::new();
    loop {
        let buffered = reader.fill_buf().await?;
        if buffered.is_empty() {
            return Err(WireError::Eof);
        }
        let (taken, done) = match buffered.iter().position(|&b| b == b'\n') {
            Some(at) => (at + 1, true),
            None => (buffered.len(), false),
        };
        line.extend_from_slice(&buffered[..taken]);
        reader.consume(taken);
        if done {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return if line.len() > max {
                Err(WireError::TooLong)
            } else {
                Ok(line)
            };
        }
        if line.len() > max + 1 {
            return Err(WireError::TooLong);
        }
    }
}

/// Reads the server's identification string, skipping the lines servers may send before it, and
/// returns it without its line ending (the `V_S` of the exchange hash).
///
/// Only `SSH-2.0-` and `SSH-1.99-` servers are accepted. A line that doesn't start with `SSH-` is
/// a pre-banner line and skipped, up to [`MAX_PRE_BANNER_LINES`] of them.
pub(super) async fn read_identification<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, WireError> {
    for _ in 0..=MAX_PRE_BANNER_LINES {
        let line = read_line(reader, MAX_PRE_BANNER_LINE).await?;
        if !line.starts_with(b"SSH-") {
            continue;
        }
        if line.len() > MAX_IDENTIFICATION {
            return Err(WireError::TooLong);
        }
        if !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
            return Err(WireError::Version(line));
        }
        return Ok(line);
    }
    Err(WireError::TooLong)
}

/// Frames `payload` as an unencrypted binary packet: `packet_length`, `padding_length`, the
/// payload, and random padding so the whole packet is a multiple of 8 bytes with at least 4 bytes
/// of padding.
pub(super) fn encode_packet(payload: &[u8]) -> Vec<u8> {
    let mut padding = BLOCK - (4 + 1 + payload.len()) % BLOCK;
    if padding < 4 {
        padding += BLOCK;
    }
    let packet_length = u32::try_from(1 + payload.len() + padding).unwrap_or(u32::MAX);
    let mut packet = Vec::with_capacity(4 + 1 + payload.len() + padding);
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(u8::try_from(padding).unwrap_or(u8::MAX));
    packet.extend_from_slice(payload);
    let start = packet.len();
    packet.resize(start + padding, 0);
    // Padding should be random, but nothing depends on it here: if the system's randomness fails
    // the zeros that are already in place are still a valid packet.
    let _ = aws_lc_rs::rand::fill(&mut packet[start..]);
    packet
}

/// Reads one unencrypted binary packet and returns its payload.
pub(super) async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, WireError> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_PACKET {
        return Err(WireError::TooLong);
    }
    // padding_length, at least one payload byte, and at least 4 bytes of padding.
    if length < 1 + 1 + 4 {
        return Err(WireError::Malformed("a packet too short to hold a message"));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).await?;
    let padding = usize::from(body[0]);
    if padding < 4 || 1 + padding >= length {
        return Err(WireError::Malformed("a packet with invalid padding"));
    }
    body.truncate(length - padding);
    body.remove(0);
    Ok(body)
}

/// Appends a `uint32`.
pub(super) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends a `string`: a `uint32` length and the bytes.
pub(super) fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(bytes);
}

/// Appends a `name-list`: the names joined by commas, as a `string`.
pub(super) fn put_name_list(out: &mut Vec<u8>, names: &[&str]) {
    put_string(out, names.join(",").as_bytes());
}

/// Appends an `mpint` holding the unsigned big-endian number `magnitude`: no leading zero bytes,
/// and a zero byte in front when the top bit is set so the value stays positive.
pub(super) fn put_mpint(out: &mut Vec<u8>, magnitude: &[u8]) {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len());
    let magnitude = &magnitude[start..];
    let pad = magnitude.first().is_some_and(|b| b & 0x80 != 0);
    put_u32(
        out,
        u32::try_from(magnitude.len() + usize::from(pad)).unwrap_or(u32::MAX),
    );
    if pad {
        out.push(0);
    }
    out.extend_from_slice(magnitude);
}

/// A cursor over a message payload.
pub(super) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(super) fn u8(&mut self) -> Option<u8> {
        let (&first, rest) = self.rest.split_first()?;
        self.rest = rest;
        Some(first)
    }

    pub(super) fn bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.rest.len() < count {
            return None;
        }
        let (taken, rest) = self.rest.split_at(count);
        self.rest = rest;
        Some(taken)
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        let bytes = self.bytes(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// A `string`.
    pub(super) fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        self.bytes(length)
    }

    /// A `name-list`, as the raw names between commas.
    pub(super) fn name_list(&mut self) -> Option<Vec<&'a [u8]>> {
        let list = self.string()?;
        Some(if list.is_empty() {
            Vec::new()
        } else {
            list.split(|&b| b == b',').collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn identification(input: &[u8]) -> Result<Vec<u8>, WireError> {
        let mut reader = input;
        read_identification(&mut reader).await
    }

    #[tokio::test]
    async fn identification_is_the_ssh_line_without_its_ending() {
        let line = identification(b"SSH-2.0-OpenSSH_10.3 Debian\r\nrest")
            .await
            .expect("banner");
        assert_eq!(line, b"SSH-2.0-OpenSSH_10.3 Debian");
        let line = identification(b"SSH-1.99-old\n")
            .await
            .expect("a bare LF ends the line");
        assert_eq!(line, b"SSH-1.99-old");
    }

    #[tokio::test]
    async fn lines_before_the_identification_are_skipped() {
        let line = identification(b"Welcome to the machine\r\n\r\nSSH-2.0-x\r\n")
            .await
            .expect("banner");
        assert_eq!(line, b"SSH-2.0-x");
    }

    #[tokio::test]
    async fn identification_stops_at_what_follows_it() {
        let mut reader: &[u8] = b"SSH-2.0-x\r\n\x00\x00\x00\x0c";
        read_identification(&mut reader).await.expect("banner");
        assert_eq!(reader, b"\x00\x00\x00\x0c");
    }

    #[tokio::test]
    async fn version_one_is_refused() {
        match identification(b"SSH-1.5-ancient\r\n").await {
            Err(WireError::Version(line)) => assert_eq!(line, b"SSH-1.5-ancient"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn too_long_or_too_many_lines_are_refused() {
        let mut long = b"SSH-2.0-".to_vec();
        long.extend(std::iter::repeat_n(b'a', 300));
        long.extend_from_slice(b"\r\n");
        assert!(matches!(
            identification(&long).await,
            Err(WireError::TooLong)
        ));

        let mut endless = vec![b'x'; MAX_PRE_BANNER_LINE + 10];
        endless.push(b'\n');
        assert!(matches!(
            identification(&endless).await,
            Err(WireError::TooLong)
        ));

        let chatter = b"hello\r\n".repeat(MAX_PRE_BANNER_LINES + 5);
        assert!(matches!(
            identification(&chatter).await,
            Err(WireError::TooLong)
        ));

        // A line that never ends mustn't be buffered without limit.
        let unterminated = vec![b'y'; 3 * MAX_PRE_BANNER_LINE];
        assert!(matches!(
            identification(&unterminated).await,
            Err(WireError::TooLong)
        ));
    }

    #[tokio::test]
    async fn end_of_stream_before_the_identification_is_eof() {
        assert!(matches!(
            identification(b"no newline").await,
            Err(WireError::Eof)
        ));
        assert!(matches!(identification(b"").await, Err(WireError::Eof)));
    }

    #[test]
    fn packets_are_padded_to_the_block_size_with_at_least_four_bytes() {
        for len in 0..40 {
            let payload = vec![0xab; len];
            let packet = encode_packet(&payload);
            assert_eq!(packet.len() % BLOCK, 0, "payload of {len}");
            let packet_length = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
            assert_eq!(packet_length as usize + 4, packet.len());
            let padding = usize::from(packet[4]);
            assert!(padding >= 4, "payload of {len}");
            assert_eq!(&packet[5..5 + len], payload.as_slice());
            assert_eq!(5 + len + padding, packet.len());
        }
    }

    #[test]
    fn a_packet_for_a_known_payload_has_the_expected_framing() {
        // 4 (packet_length) + 1 (padding_length) + 3 (payload) is already a multiple of 8, so the
        // 4 bytes of padding that are required become 8.
        let packet = encode_packet(&[20, 1, 2]);
        assert_eq!(&packet[..8], &[0, 0, 0, 12, 8, 20, 1, 2]);
        assert_eq!(packet.len(), 16);
        // 5 + 7 = 12; 4 bytes of padding make 16.
        assert_eq!(encode_packet(&[0; 7])[4], 4);
        // 5 + 8 = 13; 3 bytes would align it but 4 are required, so 11.
        assert_eq!(encode_packet(&[0; 8])[4], 11);
    }

    #[tokio::test]
    async fn packets_round_trip() {
        for len in [1, 2, 7, 8, 100, 1000] {
            let payload: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).expect("fits"))
                .collect();
            let packet = encode_packet(&payload);
            let mut reader = packet.as_slice();
            assert_eq!(read_packet(&mut reader).await.expect("packet"), payload);
            assert!(reader.is_empty());
        }
    }

    #[tokio::test]
    async fn oversized_and_malformed_packets_are_refused() {
        let mut reader: &[u8] = &(u32::try_from(MAX_PACKET).expect("fits") + 1).to_be_bytes();
        assert!(matches!(
            read_packet(&mut reader).await,
            Err(WireError::TooLong)
        ));

        let mut reader: &[u8] = &[0xff; 4];
        assert!(matches!(
            read_packet(&mut reader).await,
            Err(WireError::TooLong)
        ));

        // Shorter than padding_length, a payload byte, and 4 bytes of padding.
        let mut reader: &[u8] = &[0, 0, 0, 5, 4, 1, 0, 0, 0];
        assert!(matches!(
            read_packet(&mut reader).await,
            Err(WireError::Malformed(_))
        ));

        // Less padding than the minimum.
        let mut reader: &[u8] = &[0, 0, 0, 8, 3, 1, 2, 3, 0, 0, 0, 0];
        assert!(matches!(
            read_packet(&mut reader).await,
            Err(WireError::Malformed(_))
        ));

        // Padding that swallows the payload.
        let mut reader: &[u8] = &[0, 0, 0, 8, 7, 1, 2, 3, 0, 0, 0, 0];
        assert!(matches!(
            read_packet(&mut reader).await,
            Err(WireError::Malformed(_))
        ));

        // A packet cut short.
        let mut reader: &[u8] = &[0, 0, 0, 12, 8, 20];
        assert!(matches!(
            read_packet(&mut reader).await,
            Err(WireError::Eof)
        ));
    }

    #[test]
    fn mpints_drop_leading_zeros_and_keep_the_value_positive() {
        let encode = |magnitude: &[u8]| {
            let mut out = Vec::new();
            put_mpint(&mut out, magnitude);
            out
        };
        assert_eq!(encode(&[]), [0, 0, 0, 0]);
        assert_eq!(encode(&[0, 0]), [0, 0, 0, 0]);
        assert_eq!(encode(&[0x7f]), [0, 0, 0, 1, 0x7f]);
        assert_eq!(encode(&[0, 0, 0x7f, 1]), [0, 0, 0, 2, 0x7f, 1]);
        assert_eq!(encode(&[0x80]), [0, 0, 0, 2, 0, 0x80]);
        assert_eq!(encode(&[0, 0xff, 0xee]), [0, 0, 0, 3, 0, 0xff, 0xee]);
    }

    #[test]
    fn reader_stops_at_the_end_of_the_data() {
        let mut data = Vec::new();
        data.push(9);
        put_u32(&mut data, 258);
        put_string(&mut data, b"abc");
        put_name_list(&mut data, &["x", "yz"]);
        put_name_list(&mut data, &[]);
        let mut reader = Reader::new(&data);
        assert_eq!(reader.u8(), Some(9));
        assert_eq!(reader.u32(), Some(258));
        assert_eq!(reader.string(), Some(&b"abc"[..]));
        assert_eq!(reader.name_list(), Some(vec![&b"x"[..], b"yz"]));
        assert_eq!(reader.name_list(), Some(Vec::new()));
        assert_eq!(reader.u8(), None);
        assert_eq!(reader.u32(), None);
        assert_eq!(reader.string(), None);

        // A string whose length runs past the data.
        let mut reader = Reader::new(&[0, 0, 0, 9, 1, 2]);
        assert_eq!(reader.string(), None);
    }
}
