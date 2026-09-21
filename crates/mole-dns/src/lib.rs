//! DNS over HTTPS — a small, blocking, wire-format resolver.
//!
//! Part of the block is DNS hijacking: the operator answers a blocked name with a
//! wrong or empty address over plain UDP/53, which anyone on the path can rewrite.
//! DoH puts the query inside TLS to a resolver of the user's choice, so the answer
//! can't be tampered with. The probe needs this to learn the *correct* address of
//! a blocked target before it can tell a DPI block apart from a DNS lie.
//!
//! No async runtime, no HTTP crate: one TLS connection, one POST, one parse. That
//! keeps the dependency surface tiny and the behaviour easy to reason about.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;

/// A DoH endpoint: where to connect, the name to present in TLS, and the path.
#[derive(Clone)]
pub struct Resolver {
    pub addr: SocketAddr,
    pub sni: String,
    pub path: String,
    pub name: String,
}

impl Resolver {
    /// Cloudflare's `1.1.1.1`.
    pub fn cloudflare() -> Resolver {
        Resolver {
            addr: "1.1.1.1:443".parse().unwrap(),
            sni: "cloudflare-dns.com".into(),
            path: "/dns-query".into(),
            name: "Cloudflare".into(),
        }
    }

    /// Google's `8.8.8.8`.
    pub fn google() -> Resolver {
        Resolver {
            addr: "8.8.8.8:443".parse().unwrap(),
            sni: "dns.google".into(),
            path: "/dns-query".into(),
            name: "Google".into(),
        }
    }

    /// Look up the IPv4 addresses of `host`.
    pub fn resolve_a(&self, host: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let query = build_query(host, 1); // type A
        let body = self.post(&query)?;
        parse_answers_a(&body)
    }

    /// POST a raw DNS message and return the response DNS message bytes.
    fn post(&self, dns_message: &[u8]) -> Result<Vec<u8>, DnsError> {
        let config = tls_config()?;
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|_| DnsError::BadResolverName)?;
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| DnsError::Tls(e.to_string()))?;
        let mut sock = TcpStream::connect_timeout(&self.addr, Duration::from_secs(6))
            .map_err(DnsError::Connect)?;
        sock.set_read_timeout(Some(Duration::from_secs(6))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(6))).ok();

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            self.path,
            self.sni,
            dns_message.len()
        );

        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(request.as_bytes()).map_err(DnsError::Io)?;
        tls.write_all(dns_message).map_err(DnsError::Io)?;
        tls.flush().map_err(DnsError::Io)?;

        let mut raw = Vec::new();
        // Connection: close means the server ends the stream when done; a clean
        // EOF (or rustls' close-notify surfaced as UnexpectedEof) ends the read.
        match tls.read_to_end(&mut raw) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(DnsError::Io(e)),
        }
        http_body(&raw)
    }
}

/// Build the default rustls client config, verifying against the OS trust store.
fn tls_config() -> Result<rustls::ClientConfig, DnsError> {
    use rustls_platform_verifier::BuilderVerifierExt;
    // Install the ring crypto provider once; ignore if another already is.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .with_platform_verifier()
        .map_err(|e| DnsError::Tls(e.to_string()))?
        .with_no_client_auth();
    Ok(config)
}

/// Encode a DNS query for `host` of the given record `qtype`.
fn build_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&[0x00, 0x00]); // ID 0 (DoH ignores it / caches key on content)
    m.extend_from_slice(&[0x01, 0x00]); // flags: RD
    m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    m.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    m.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    m.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    for label in host.split('.').filter(|l| !l.is_empty()) {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0x00); // root
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0x00, 0x01]); // class IN
    m
}

/// Split an HTTP/1.1 response into its body, handling Content-Length, chunked
/// transfer encoding, and close-delimited bodies.
fn http_body(raw: &[u8]) -> Result<Vec<u8>, DnsError> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(DnsError::BadHttp)?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];

    let head_str = String::from_utf8_lossy(head);
    let status_ok = head_str
        .lines()
        .next()
        .map(|l| l.contains(" 200"))
        .unwrap_or(false);
    if !status_ok {
        return Err(DnsError::HttpStatus(
            head_str.lines().next().unwrap_or("").trim().to_string(),
        ));
    }

    let chunked = head_str
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    if chunked {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

/// Decode HTTP chunked transfer encoding.
fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::new();
    loop {
        let nl = b.windows(2).position(|w| w == b"\r\n").ok_or(DnsError::BadHttp)?;
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&b[..nl]).trim(),
            16,
        )
        .map_err(|_| DnsError::BadHttp)?;
        b = &b[nl + 2..];
        if size == 0 {
            break;
        }
        if size > b.len() {
            return Err(DnsError::BadHttp);
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..]; // skip chunk data + trailing CRLF
    }
    Ok(out)
}

/// Parse A records out of a DNS response message.
fn parse_answers_a(msg: &[u8]) -> Result<Vec<Ipv4Addr>, DnsError> {
    if msg.len() < 12 {
        return Err(DnsError::BadResponse);
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut p = 12;
    // Skip questions.
    for _ in 0..qd {
        p = skip_name(msg, p)?;
        p += 4; // qtype + qclass
    }
    let mut out = Vec::new();
    for _ in 0..an {
        p = skip_name(msg, p)?;
        if p + 10 > msg.len() {
            return Err(DnsError::BadResponse);
        }
        let rtype = u16::from_be_bytes([msg[p], msg[p + 1]]);
        let rdlen = u16::from_be_bytes([msg[p + 8], msg[p + 9]]) as usize;
        p += 10;
        if p + rdlen > msg.len() {
            return Err(DnsError::BadResponse);
        }
        if rtype == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(msg[p], msg[p + 1], msg[p + 2], msg[p + 3]));
        }
        p += rdlen;
    }
    Ok(out)
}

/// Advance past a (possibly compressed) DNS name, returning the offset after it.
fn skip_name(msg: &[u8], mut p: usize) -> Result<usize, DnsError> {
    loop {
        if p >= msg.len() {
            return Err(DnsError::BadResponse);
        }
        let len = msg[p];
        if len & 0xC0 == 0xC0 {
            return Ok(p + 2); // pointer: two bytes, name ends here
        }
        if len == 0 {
            return Ok(p + 1);
        }
        p += 1 + len as usize;
    }
}

#[derive(Debug)]
pub enum DnsError {
    BadResolverName,
    Connect(std::io::Error),
    Io(std::io::Error),
    Tls(String),
    BadHttp,
    HttpStatus(String),
    BadResponse,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::BadResolverName => write!(f, "the resolver's TLS name is invalid"),
            DnsError::Connect(e) => write!(f, "could not reach the DoH resolver: {e}"),
            DnsError::Io(e) => write!(f, "DoH I/O error: {e}"),
            DnsError::Tls(e) => write!(f, "DoH TLS error: {e} (the resolver's SNI may be blocked)"),
            DnsError::BadHttp => write!(f, "malformed HTTP response from the resolver"),
            DnsError::HttpStatus(s) => write!(f, "resolver returned a non-200 status: {s}"),
            DnsError::BadResponse => write!(f, "malformed DNS response"),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encodes_labels() {
        let q = build_query("example.com", 1);
        // header(12) + 7"example" + 3"com" + root + qtype + qclass
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(&q[25..29], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parses_a_record_with_compression() {
        // Header: 1 question, 1 answer.
        let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        // Question: example.com A IN
        m.extend_from_slice(&[7]);
        m.extend_from_slice(b"example");
        m.extend_from_slice(&[3]);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        // Answer: name pointer to 0x0C, type A, class IN, ttl, rdlen 4, 93.184.216.34
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let ips = parse_answers_a(&m).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn dechunk_reassembles() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(body).unwrap(), b"Wikipedia".to_vec());
    }
}
