//! Just enough IPv4/TCP parsing to find a TLS ClientHello and the server name
//! inside it. This is read-only inspection over a borrowed buffer; the filter
//! engine's edits live elsewhere. Kept deliberately small — Mole only ever needs
//! to reach the SNI and the TCP payload boundary, not a full packet decoder.

/// A parsed view of an IPv4 + TCP packet, with byte ranges into the original
/// buffer so the filter engine can splice without re-parsing.
pub struct TcpView {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    /// Where the IP header ends / TCP header begins.
    pub tcp_offset: usize,
    /// Where the TCP payload begins.
    pub payload_offset: usize,
    pub syn: bool,
    pub ack: bool,
}

impl TcpView {
    /// Parse an IPv4/TCP packet. Returns `None` for anything that is not IPv4+TCP
    /// or is too short to trust.
    pub fn parse(pkt: &[u8]) -> Option<TcpView> {
        if pkt.len() < 20 {
            return None;
        }
        let version = pkt[0] >> 4;
        if version != 4 {
            return None; // IPv6 is handled on its own path; not parsed here yet.
        }
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || pkt.len() < ihl + 20 {
            return None;
        }
        let protocol = pkt[9];
        if protocol != 6 {
            return None; // not TCP
        }
        let src = [pkt[12], pkt[13], pkt[14], pkt[15]];
        let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];

        let tcp = &pkt[ihl..];
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let data_offset = (tcp[12] >> 4) as usize * 4;
        if data_offset < 20 || pkt.len() < ihl + data_offset {
            return None;
        }
        let flags = tcp[13];
        Some(TcpView {
            src,
            dst,
            src_port,
            dst_port,
            tcp_offset: ihl,
            payload_offset: ihl + data_offset,
            syn: flags & 0x02 != 0,
            ack: flags & 0x10 != 0,
        })
    }

    pub fn payload<'a>(&self, pkt: &'a [u8]) -> &'a [u8] {
        &pkt[self.payload_offset..]
    }
}

/// If `payload` is a TLS ClientHello, return the SNI host name and the byte
/// offset of that name within `payload`. The offset is what the ClientHello
/// splitting strategy needs: it splits the TCP segment so the host name straddles
/// the boundary and the filter cannot read it whole.
pub fn find_sni(payload: &[u8]) -> Option<(String, usize)> {
    // TLS record header: type(1)=22 handshake, version(2), length(2).
    if payload.len() < 5 || payload[0] != 22 {
        return None;
    }
    let mut p = 5;
    // Handshake header: type(1)=1 ClientHello, length(3).
    if payload.len() < p + 4 || payload[p] != 1 {
        return None;
    }
    p += 4;
    // client_version(2) + random(32).
    p += 2 + 32;
    if payload.len() < p + 1 {
        return None;
    }
    // session_id.
    let sid_len = payload[p] as usize;
    p += 1 + sid_len;
    // cipher_suites.
    if payload.len() < p + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
    p += 2 + cs_len;
    // compression_methods.
    if payload.len() < p + 1 {
        return None;
    }
    let cm_len = payload[p] as usize;
    p += 1 + cm_len;
    // extensions.
    if payload.len() < p + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(payload.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[p], payload[p + 1]]);
        let ext_len = u16::from_be_bytes([payload[p + 2], payload[p + 3]]) as usize;
        p += 4;
        if p + ext_len > payload.len() {
            return None;
        }
        if ext_type == 0 {
            // server_name extension.
            // server_name_list length(2), then entry: type(1)=0 host, length(2), name.
            if ext_len < 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([payload[p + 3], payload[p + 4]]) as usize;
            let name_start = p + 5;
            if name_start + name_len > payload.len() {
                return None;
            }
            let host =
                String::from_utf8_lossy(&payload[name_start..name_start + name_len]).into_owned();
            return Some((host, name_start));
        }
        p += ext_len;
    }
    None
}

/// True if `payload` looks like a TLS ClientHello (handshake record, type 1).
pub fn is_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 22 && payload[5] == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built TLS 1.2 ClientHello for `example.com`, wrapped in a record.
    fn client_hello_example_com() -> Vec<u8> {
        // extensions: just server_name for example.com (11 bytes).
        let host = b"example.com";
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // type = server_name
        let sni_body_len = 2 + 1 + 2 + host.len(); // list_len + type + name_len + name
        ext.extend_from_slice(&(sni_body_len as u16).to_be_bytes()); // ext_len
        ext.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes()); // list_len
        ext.push(0x00); // name type host
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id len 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites len 2
        body.extend_from_slice(&[0x13, 0x01]); // one suite
        body.push(0x01); // compression len 1
        body.push(0x00); // null
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni_and_offset() {
        let ch = client_hello_example_com();
        assert!(is_client_hello(&ch));
        let (host, off) = find_sni(&ch).expect("SNI should parse");
        assert_eq!(host, "example.com");
        // The name must sit where we said it does.
        assert_eq!(&ch[off..off + host.len()], b"example.com");
    }

    #[test]
    fn ignores_non_handshake() {
        assert!(find_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]).is_none());
        assert!(!is_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 1]));
    }

    #[test]
    fn tcpview_parses_ipv4_tcp() {
        // Minimal IPv4(20) + TCP(20) with SYN set, dst port 443.
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // v4, ihl 5
        p[9] = 6; // TCP
        p[16..20].copy_from_slice(&[1, 2, 3, 4]); // dst
        p[20 + 2] = 0x01; // dst port high
        p[20 + 3] = 0xBB; // 443
        p[20 + 12] = 0x50; // data offset 5
        p[20 + 13] = 0x02; // SYN
        let v = TcpView::parse(&p).unwrap();
        assert_eq!(v.dst_port, 443);
        assert!(v.syn);
        assert_eq!(v.payload_offset, 40);
    }
}
