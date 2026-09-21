//! The desync strategies from the plan, as pure transforms.
//!
//! A strategy takes the one captured ClientHello packet and returns the sequence
//! of packets to send in its place. It never touches any other packet. Keeping
//! these as pure functions over bytes means the probe and the live filter engine
//! run the *exact same* code — what the probe measures is what production does —
//! and each strategy is unit-testable without a network.
//!
//! None of these hide or route traffic; they only shape the handshake so the
//! filter cannot read the server name in one clean segment. The server always
//! reassembles a valid stream.

use std::sync::OnceLock;

use crate::checksum::tcp_checksum;
use crate::packet::{find_sni, TcpView};
use crate::windivert::Packet;

/// One packet to put on the wire, and whether WinDivert should fix its checksums
/// on send. A decoy with a purposely broken checksum sets this to `false`.
pub struct Emit {
    pub packet: Packet,
    pub fix_checksums: bool,
}

/// Where to cut a ClientHello segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    /// Split so the SNI host name straddles the boundary (the filter can't read
    /// it whole). Falls back to a fixed offset if there is no SNI.
    Sni,
    /// Split at a fixed number of bytes into the TLS record (GoodByeDPI's default
    /// is a small offset like 2).
    Fixed(usize),
}

/// What a decoy packet does to fool the filter without reaching the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoy {
    /// TTL low enough to die between the filter and the server. Valid otherwise.
    LowTtl(u8),
    /// Correct everything but the TCP checksum: the server's stack drops it, a
    /// filter that ignores checksums still consumes it.
    BadChecksum,
    /// A sequence number far outside the window: the server discards it as
    /// out-of-order junk, but a filter that scans every packet's payload still
    /// reads the ClientHello. GoodByeDPI's `--wrong-seq`. The offset is how far
    /// below the real sequence number the decoy sits.
    WrongSeq(u32),
}

/// The strategies the probe tries and the engine applies. `Passthrough` is the
/// control: send the ClientHello untouched, to confirm the target really is
/// blocked before crediting any bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Strategy {
    Passthrough,
    /// Split into two segments at `cut`.
    Split { cut: Cut },
    /// Split at `cut` but send the second segment first (out-of-order).
    Disorder { cut: Cut },
    /// Send a decoy ClientHello, then the real one untouched.
    Fake { decoy: Decoy },
    /// Send a decoy, then split the real ClientHello.
    FakeSplit { decoy: Decoy, cut: Cut },
}

/// TTL values the sweep tries, low first. A home line's DPI usually sits a few
/// hops away, before the operator's core; 2–9 covers the common cases without a
/// full traceroute.
const TTL_SWEEP: &[u8] = &[2, 3, 4, 5, 6, 7, 8, 9];

impl Strategy {
    /// A short stable label used in reports and as a CLI/config token.
    pub fn label(&self) -> String {
        match self {
            Strategy::Passthrough => "passthrough".into(),
            Strategy::Split { cut } => format!("split:{}", cut_label(cut)),
            Strategy::Disorder { cut } => format!("disorder:{}", cut_label(cut)),
            Strategy::Fake { decoy } => format!("fake:{}", decoy_label(decoy)),
            Strategy::FakeSplit { decoy, cut } => {
                format!("fakesplit:{}:{}", decoy_label(decoy), cut_label(cut))
            }
        }
    }

    /// The default battery the probe walks, cheapest/most-likely first. Every
    /// entry is a technique proven in the field against Turkish ISP filters.
    pub fn probe_battery() -> Vec<Strategy> {
        let mut b = vec![
            // Cheapest first: pure splits, then sequence/checksum fakes that need
            // no TTL guessing, then the TTL sweep, then fake+split combinations.
            Strategy::Split { cut: Cut::Sni },
            Strategy::Split { cut: Cut::Fixed(2) },
            Strategy::Disorder { cut: Cut::Sni },
            Strategy::Fake { decoy: Decoy::WrongSeq(10_000) },
            Strategy::Fake { decoy: Decoy::BadChecksum },
        ];
        // TTL sweep: find the hop where the DPI sits without knowing it in advance.
        for ttl in TTL_SWEEP {
            b.push(Strategy::Fake { decoy: Decoy::LowTtl(*ttl) });
        }
        b.push(Strategy::FakeSplit { decoy: Decoy::WrongSeq(10_000), cut: Cut::Sni });
        b.push(Strategy::FakeSplit { decoy: Decoy::BadChecksum, cut: Cut::Sni });
        for ttl in TTL_SWEEP {
            b.push(Strategy::FakeSplit { decoy: Decoy::LowTtl(*ttl), cut: Cut::Sni });
        }
        b
    }

    /// Transform the captured ClientHello into the packets to send. Returns the
    /// original untouched if the strategy can't apply (e.g. no SNI for `Cut::Sni`
    /// and no fallback), so the caller always has something valid to send.
    pub fn apply(&self, orig: &Packet, view: &TcpView) -> Vec<Emit> {
        match self {
            Strategy::Passthrough => vec![pass(orig)],
            Strategy::Split { cut } => split(orig, view, *cut, false),
            Strategy::Disorder { cut } => split(orig, view, *cut, true),
            Strategy::Fake { decoy } => {
                let mut out = Vec::new();
                if let Some(d) = make_decoy(orig, view, *decoy) {
                    out.push(d);
                }
                out.push(pass(orig));
                out
            }
            Strategy::FakeSplit { decoy, cut } => {
                let mut out = Vec::new();
                if let Some(d) = make_decoy(orig, view, *decoy) {
                    out.push(d);
                }
                out.extend(split(orig, view, *cut, false));
                out
            }
        }
    }
}

fn cut_label(cut: &Cut) -> String {
    match cut {
        Cut::Sni => "sni".into(),
        Cut::Fixed(n) => format!("at{n}"),
    }
}

fn decoy_label(d: &Decoy) -> String {
    match d {
        Decoy::LowTtl(t) => format!("ttl{t}"),
        Decoy::BadChecksum => "badsum".into(),
        Decoy::WrongSeq(o) => format!("wseq{o}"),
    }
}

fn pass(orig: &Packet) -> Emit {
    Emit {
        packet: Packet {
            data: orig.data.clone(),
            addr: orig.addr,
        },
        fix_checksums: true,
    }
}

/// Resolve a `Cut` to a byte offset inside the TCP payload.
fn cut_offset(payload: &[u8], cut: Cut) -> Option<usize> {
    let n = match cut {
        Cut::Fixed(n) => n,
        Cut::Sni => match find_sni(payload) {
            // Cut in the middle of the host name so neither half is readable.
            Some((host, off)) => off + host.len() / 2,
            None => 2, // fallback: a small fixed split still breaks naive matching
        },
    };
    // Keep the cut strictly inside the payload.
    if n == 0 || n >= payload.len() {
        None
    } else {
        Some(n)
    }
}

/// Split the ClientHello into two TCP segments at `cut`. With `disorder`, the
/// second segment is emitted first.
fn split(orig: &Packet, view: &TcpView, cut: Cut, disorder: bool) -> Vec<Emit> {
    let payload = view.payload(&orig.data);
    let Some(off) = cut_offset(payload, cut) else {
        return vec![pass(orig)];
    };
    let hdr = view.payload_offset;
    let seq = read_seq(&orig.data, view.tcp_offset);

    let first = build_segment(&orig.data, hdr, &payload[..off], seq, orig.addr);
    let second = build_segment(&orig.data, hdr, &payload[off..], seq.wrapping_add(off as u32), orig.addr);

    let (a, b) = (
        Emit { packet: first, fix_checksums: true },
        Emit { packet: second, fix_checksums: true },
    );
    if disorder {
        vec![b, a]
    } else {
        vec![a, b]
    }
}

/// Build one TCP segment: the original IP+TCP headers (up to `hdr`) followed by
/// `new_payload`, with the IP total-length and TCP sequence fields fixed up.
/// Checksums are left for the send path unless the caller corrupts them.
fn build_segment(
    orig: &[u8],
    hdr: usize,
    new_payload: &[u8],
    seq: u32,
    addr: crate::ffi::WinDivertAddress,
) -> Packet {
    let mut data = Vec::with_capacity(hdr + new_payload.len());
    data.extend_from_slice(&orig[..hdr]);
    data.extend_from_slice(new_payload);

    // IP total length (offset 2, 2 bytes).
    let total = data.len() as u16;
    data[2..4].copy_from_slice(&total.to_be_bytes());

    // TCP sequence number lives at tcp_offset + 4. tcp_offset = ihl.
    let ihl = (orig[0] & 0x0F) as usize * 4;
    write_seq(&mut data, ihl, seq);

    Packet { data, addr }
}

fn read_seq(data: &[u8], tcp_offset: usize) -> u32 {
    u32::from_be_bytes([
        data[tcp_offset + 4],
        data[tcp_offset + 5],
        data[tcp_offset + 6],
        data[tcp_offset + 7],
    ])
}

fn write_seq(data: &mut [u8], tcp_offset: usize, seq: u32) {
    data[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
}

/// Build a decoy: the connection's own IP/TCP headers carrying a *benign*
/// ClientHello (a different, unblocked server name), sent at the real sequence
/// number so a filter that keeps the first bytes it sees for a sequence records
/// the harmless name for this flow. The server discards the decoy — its TTL
/// expires, or its checksum/sequence is wrong — so only the real ClientHello
/// reaches it. Carrying the *real* SNI here would poison nothing; the benign
/// name is the whole point.
fn make_decoy(orig: &Packet, view: &TcpView, decoy: Decoy) -> Option<Emit> {
    let ihl = (orig.data[0] & 0x0F) as usize * 4;
    let hdr = view.payload_offset;
    let fake = benign_fake_hello();

    // Real headers + benign payload, with the IP total length fixed up.
    let mut data = Vec::with_capacity(hdr + fake.len());
    data.extend_from_slice(&orig.data[..hdr]);
    data.extend_from_slice(fake);
    let total = data.len() as u16;
    data[2..4].copy_from_slice(&total.to_be_bytes());

    let real_seq = read_seq(&orig.data, ihl);

    match decoy {
        Decoy::LowTtl(ttl) => {
            // Overlap the real sequence so the benign name lands where the filter
            // looks; die early via a low TTL. Send path fixes the checksums.
            write_seq(&mut data, ihl, real_seq);
            data[8] = ttl;
            Some(Emit {
                packet: Packet { data, addr: orig.addr },
                fix_checksums: true,
            })
        }
        Decoy::BadChecksum => {
            write_seq(&mut data, ihl, real_seq);
            // Correct the TCP checksum, then break it by one so it is definitely
            // invalid: the server's stack drops it, a filter that skips checksum
            // validation still reads the benign name.
            let good = tcp_checksum(view.src, view.dst, &data[ihl..]);
            let bad = good.wrapping_add(1);
            let pos = ihl + 16;
            data[pos..pos + 2].copy_from_slice(&bad.to_be_bytes());
            let ip_sum = crate::checksum::ipv4_checksum(&data[..ihl]);
            data[10..12].copy_from_slice(&ip_sum.to_be_bytes());
            Some(Emit {
                packet: Packet { data, addr: orig.addr },
                fix_checksums: false, // keep our deliberately-wrong TCP checksum
            })
        }
        Decoy::WrongSeq(offset) => {
            // A sequence far below the window: the server rejects it outright, but
            // a filter that inspects every packet still sees the benign name.
            write_seq(&mut data, ihl, real_seq.wrapping_sub(offset));
            Some(Emit {
                packet: Packet { data, addr: orig.addr },
                fix_checksums: true,
            })
        }
    }
}

/// A cached benign ClientHello (an unblocked server name) used as the decoy body.
fn benign_fake_hello() -> &'static [u8] {
    static FAKE: OnceLock<Vec<u8>> = OnceLock::new();
    FAKE.get_or_init(|| build_client_hello("www.google.com"))
}

/// Build a minimal but well-formed TLS 1.2 ClientHello record for `sni`. It only
/// needs to look real enough that a filter reads the server name from it.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]); // server_name extension
    let sni_body_len = 2 + 1 + 2 + host.len();
    ext.extend_from_slice(&(sni_body_len as u16).to_be_bytes());
    ext.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
    ext.push(0x00); // host name
    ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
    ext.extend_from_slice(host);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0x00u8; 32]); // random
    body.push(0x00); // no session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16); // handshake record
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::WinDivertAddress;

    // IPv4+TCP packet carrying `payload`, dst port 443, seq = 1000.
    fn packet_with(payload: &[u8]) -> (Packet, TcpView) {
        let ihl = 20;
        let tcphl = 20;
        let mut data = vec![0u8; ihl + tcphl + payload.len()];
        data[0] = 0x45;
        data[9] = 6;
        data[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst
        let total = data.len() as u16;
        data[2..4].copy_from_slice(&total.to_be_bytes());
        data[ihl + 2..ihl + 4].copy_from_slice(&443u16.to_be_bytes());
        data[ihl + 4..ihl + 8].copy_from_slice(&1000u32.to_be_bytes());
        data[ihl + 12] = 0x50; // data offset 5
        data[ihl + tcphl..].copy_from_slice(payload);
        let view = TcpView::parse(&data).unwrap();
        (Packet { data, addr: WinDivertAddress::zeroed() }, view)
    }

    #[test]
    fn split_two_segments_have_right_seqs_and_lengths() {
        let payload = b"ABCDEFGHIJ";
        let (pkt, view) = packet_with(payload);
        let out = Strategy::Split { cut: Cut::Fixed(4) }.apply(&pkt, &view);
        assert_eq!(out.len(), 2);
        // First segment: 4 payload bytes, seq 1000.
        let a = &out[0].packet.data;
        assert_eq!(&a[40..], b"ABCD");
        assert_eq!(u32::from_be_bytes([a[24], a[25], a[26], a[27]]), 1000);
        // Second: 6 payload bytes, seq 1004.
        let b = &out[1].packet.data;
        assert_eq!(&b[40..], b"EFGHIJ");
        assert_eq!(u32::from_be_bytes([b[24], b[25], b[26], b[27]]), 1004);
        // IP total length updated on each.
        assert_eq!(u16::from_be_bytes([a[2], a[3]]), 44);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 46);
    }

    #[test]
    fn disorder_reverses_send_order() {
        let (pkt, view) = packet_with(b"ABCDEFGHIJ");
        let out = Strategy::Disorder { cut: Cut::Fixed(4) }.apply(&pkt, &view);
        // Second segment (EFGHIJ) comes first.
        assert_eq!(&out[0].packet.data[40..], b"EFGHIJ");
        assert_eq!(&out[1].packet.data[40..], b"ABCD");
    }

    #[test]
    fn bad_checksum_decoy_is_marked_no_fix_and_actually_wrong() {
        let (pkt, view) = packet_with(b"hello handshake bytes");
        let out = Strategy::Fake { decoy: Decoy::BadChecksum }.apply(&pkt, &view);
        assert_eq!(out.len(), 2);
        assert!(!out[0].fix_checksums, "decoy must not be re-fixed on send");
        // The decoy's stored TCP checksum should not equal the correct one.
        let d = &out[0].packet.data;
        let stored = u16::from_be_bytes([d[20 + 16], d[20 + 17]]);
        let correct = tcp_checksum([0, 0, 0, 0], [10, 0, 0, 1], &d[20..]);
        assert_ne!(stored, correct);
        // The real ClientHello follows, untouched and to be fixed.
        assert!(out[1].fix_checksums);
        assert_eq!(&out[1].packet.data, &pkt.data);
    }

    #[test]
    fn decoy_carries_a_benign_name_not_the_real_one() {
        // The real ClientHello is for a "blocked" host; the decoy must NOT repeat
        // it — poisoning only works if the decoy shows the filter a benign name.
        let real = build_client_hello("blocked.example");
        let ihl = 20;
        let mut data = vec![0u8; ihl + 20 + real.len()];
        data[0] = 0x45;
        data[9] = 6;
        data[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let total = data.len() as u16;
        data[2..4].copy_from_slice(&total.to_be_bytes());
        data[ihl + 2..ihl + 4].copy_from_slice(&443u16.to_be_bytes());
        data[ihl + 12] = 0x50;
        data[ihl + 20..].copy_from_slice(&real);
        let view = TcpView::parse(&data).unwrap();
        let pkt = Packet { data, addr: WinDivertAddress::zeroed() };

        let out = Strategy::Fake { decoy: Decoy::LowTtl(5) }.apply(&pkt, &view);
        let decoy_payload = &out[0].packet.data[40..];
        assert!(
            find_sni(decoy_payload).map(|(h, _)| h) == Some("www.google.com".to_string()),
            "decoy should carry the benign SNI"
        );
        assert!(
            find_sni(decoy_payload).map(|(h, _)| h) != Some("blocked.example".to_string()),
            "decoy must not carry the real, blocked SNI"
        );
    }

    #[test]
    fn low_ttl_decoy_sets_ttl() {
        let (pkt, view) = packet_with(b"hello");
        let out = Strategy::Fake { decoy: Decoy::LowTtl(4) }.apply(&pkt, &view);
        assert_eq!(out[0].packet.data[8], 4);
        assert!(out[0].fix_checksums);
    }

    #[test]
    fn wrong_seq_decoy_moves_sequence_below_real() {
        let (pkt, view) = packet_with(b"hello");
        let out = Strategy::Fake { decoy: Decoy::WrongSeq(10_000) }.apply(&pkt, &view);
        // Real seq is 1000; decoy sits 10_000 below it (wrapping).
        let d = &out[0].packet.data;
        let decoy_seq = u32::from_be_bytes([d[24], d[25], d[26], d[27]]);
        assert_eq!(decoy_seq, 1000u32.wrapping_sub(10_000));
        // The real ClientHello still follows with its true sequence.
        let r = &out[1].packet.data;
        assert_eq!(u32::from_be_bytes([r[24], r[25], r[26], r[27]]), 1000);
    }

    #[test]
    fn passthrough_is_identity() {
        let (pkt, view) = packet_with(b"anything");
        let out = Strategy::Passthrough.apply(&pkt, &view);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].packet.data, &pkt.data);
    }
}
