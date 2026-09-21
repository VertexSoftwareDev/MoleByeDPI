//! IPv4 and TCP checksums.
//!
//! WinDivert can recompute checksums for us on send, and for ordinary edited
//! packets we let it. But one strategy needs a packet the *server* rejects while
//! the *filter* still parses it — a decoy with a deliberately wrong TCP checksum.
//! For that we must compute the correct value ourselves and then break it, so the
//! break is exact rather than a guess. These are the standard 16-bit one's
//! complement sums over the IPv4 header and the TCP pseudo-header.

fn ones_complement_sum(bytes: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Checksum of an IPv4 header (`ihl` bytes), computed with the checksum field
/// treated as zero.
pub fn ipv4_checksum(ip_header: &[u8]) -> u16 {
    let mut buf = ip_header.to_vec();
    buf[10] = 0;
    buf[11] = 0;
    ones_complement_sum(&buf, 0)
}

/// TCP checksum over the pseudo-header + TCP segment. `src`/`dst` are the IPv4
/// addresses; `tcp` is the whole TCP header+payload with its own checksum field
/// treated as zero.
pub fn tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
    // Pseudo-header: src(4), dst(4), zero(1), protocol(1)=6, tcp_length(2).
    let mut pseudo = 0u32;
    pseudo += u16::from_be_bytes([src[0], src[1]]) as u32;
    pseudo += u16::from_be_bytes([src[2], src[3]]) as u32;
    pseudo += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    pseudo += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    pseudo += 6u32; // protocol
    pseudo += tcp.len() as u32;

    let mut buf = tcp.to_vec();
    buf[16] = 0;
    buf[17] = 0;
    ones_complement_sum(&buf, pseudo)
}
