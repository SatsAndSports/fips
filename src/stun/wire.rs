//! STUN wire format encoding and decoding (RFC 8489).
//!
//! Implements the minimal subset needed for Binding Request/Response with
//! XOR-MAPPED-ADDRESS and MAPPED-ADDRESS attributes. IPv4 only.

use super::StunError;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Magic cookie defined by RFC 5389 / 8489, always `0x2112A442`.
pub const STUN_MAGIC: u32 = 0x2112_A442;

/// STUN Binding Request message type.
pub const BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Response (success) message type.
pub const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute type: MAPPED-ADDRESS (RFC 3489 compat).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN attribute type: XOR-MAPPED-ADDRESS (RFC 8489).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN header length: 2 (type) + 2 (length) + 4 (cookie) + 12 (txn id).
pub const STUN_HEADER_LEN: usize = 20;

/// Address family: IPv4.
const FAMILY_IPV4: u8 = 0x01;

/// Build a STUN Binding Request (20 bytes, no attributes).
///
/// Returns the serialized packet and the random transaction ID for matching
/// against the response.
pub fn build_binding_request() -> ([u8; STUN_HEADER_LEN], [u8; 12]) {
    let mut buf = [0u8; STUN_HEADER_LEN];
    let txn_id: [u8; 12] = rand::random();

    // Message type: Binding Request
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    buf[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    // Transaction ID
    buf[8..20].copy_from_slice(&txn_id);

    (buf, txn_id)
}

/// Build a STUN Binding Response containing an XOR-MAPPED-ADDRESS attribute.
///
/// Used by the STUN server to reply with the observed source address.
pub fn build_binding_response(txn_id: &[u8; 12], addr: SocketAddrV4) -> Vec<u8> {
    // XOR-MAPPED-ADDRESS attribute value: 1 (reserved) + 1 (family) + 2 (xport) + 4 (xaddr) = 8 bytes
    // Attribute header: 2 (type) + 2 (length) = 4 bytes
    // Total attribute: 12 bytes
    let attr_value_len: u16 = 8;
    let attr_total_len = 4 + attr_value_len as usize; // 12

    let msg_len = attr_total_len as u16;
    let mut buf = Vec::with_capacity(STUN_HEADER_LEN + attr_total_len);

    // --- Header ---
    buf.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    buf.extend_from_slice(&msg_len.to_be_bytes());
    buf.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    buf.extend_from_slice(txn_id);

    // --- XOR-MAPPED-ADDRESS attribute ---
    // Attribute type
    buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    // Attribute value length
    buf.extend_from_slice(&attr_value_len.to_be_bytes());
    // Reserved byte
    buf.push(0x00);
    // Family: IPv4
    buf.push(FAMILY_IPV4);
    // X-Port: port XOR'd with upper 16 bits of magic cookie
    let xport = addr.port() ^ (STUN_MAGIC >> 16) as u16;
    buf.extend_from_slice(&xport.to_be_bytes());
    // X-Address: IPv4 addr XOR'd with magic cookie
    let xaddr = u32::from(*addr.ip()) ^ STUN_MAGIC;
    buf.extend_from_slice(&xaddr.to_be_bytes());

    buf
}

/// Parsed result of a STUN Binding Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResponse {
    /// The reflexive (mapped) address as reported by the STUN server.
    pub mapped_addr: SocketAddrV4,
}

/// Parse a STUN Binding Response, extracting the reflexive address.
///
/// Looks for XOR-MAPPED-ADDRESS first (mandatory in RFC 8489), falling back
/// to MAPPED-ADDRESS (RFC 3489 compat) if absent.
pub fn parse_binding_response(
    buf: &[u8],
    expected_txn: &[u8; 12],
) -> Result<StunResponse, StunError> {
    if buf.len() < STUN_HEADER_LEN {
        return Err(StunError::Protocol(
            "response too short for STUN header".into(),
        ));
    }

    // Message type
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(StunError::Protocol(format!(
            "unexpected message type: 0x{msg_type:04x}"
        )));
    }

    // Message length (bytes after the 20-byte header)
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < STUN_HEADER_LEN + msg_len {
        return Err(StunError::Protocol("response truncated".into()));
    }

    // Magic cookie
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC {
        return Err(StunError::Protocol(format!(
            "bad magic cookie: 0x{cookie:08x}"
        )));
    }

    // Transaction ID must match
    if buf[8..20] != expected_txn[..] {
        return Err(StunError::Protocol("transaction ID mismatch".into()));
    }

    // Walk attributes looking for XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
    let attrs = &buf[STUN_HEADER_LEN..STUN_HEADER_LEN + msg_len];
    let mut mapped: Option<SocketAddrV4> = None;
    let mut xor_mapped: Option<SocketAddrV4> = None;
    let mut pos = 0;

    while pos + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[pos], attrs[pos + 1]]);
        let attr_len = u16::from_be_bytes([attrs[pos + 2], attrs[pos + 3]]) as usize;
        let attr_start = pos + 4;

        if attr_start + attr_len > attrs.len() {
            break; // truncated attribute, stop
        }

        let attr_data = &attrs[attr_start..attr_start + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped = parse_xor_mapped_address(attr_data);
            }
            ATTR_MAPPED_ADDRESS => {
                mapped = parse_mapped_address(attr_data);
            }
            _ => {} // skip unknown attributes
        }

        // Attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        pos = attr_start + padded_len;
    }

    xor_mapped
        .or(mapped)
        .map(|addr| StunResponse { mapped_addr: addr })
        .ok_or_else(|| {
            StunError::Protocol("no MAPPED-ADDRESS or XOR-MAPPED-ADDRESS in response".into())
        })
}

/// Parse an XOR-MAPPED-ADDRESS attribute value (IPv4 only).
///
/// Layout:
///   0: reserved (0x00)
///   1: family (0x01 = IPv4)
///   2..4: port XOR'd with upper 16 bits of magic cookie
///   4..8: IPv4 addr XOR'd with magic cookie
fn parse_xor_mapped_address(data: &[u8]) -> Option<SocketAddrV4> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    if family != FAMILY_IPV4 {
        return None; // IPv6 not handled
    }
    let xport = u16::from_be_bytes([data[2], data[3]]);
    let port = xport ^ (STUN_MAGIC >> 16) as u16;

    let xaddr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let addr = xaddr ^ STUN_MAGIC;

    Some(SocketAddrV4::new(Ipv4Addr::from(addr), port))
}

/// Parse a plain MAPPED-ADDRESS attribute value (IPv4 only).
///
/// Layout:
///   0: reserved (0x00)
///   1: family (0x01 = IPv4)
///   2..4: port
///   4..8: IPv4 addr
fn parse_mapped_address(data: &[u8]) -> Option<SocketAddrV4> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    if family != FAMILY_IPV4 {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    let addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    Some(SocketAddrV4::new(Ipv4Addr::from(addr), port))
}

/// Validate a received buffer as a STUN Binding Request and extract the
/// transaction ID.
///
/// Returns `Some(txn_id)` if the buffer is a valid Binding Request,
/// `None` otherwise (caller should silently ignore non-STUN traffic).
pub fn parse_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
    if buf.len() < STUN_HEADER_LEN {
        return None;
    }

    // Message type must be Binding Request
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_REQUEST {
        return None;
    }

    // Magic cookie must match
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC {
        return None;
    }

    let mut txn_id = [0u8; 12];
    txn_id.copy_from_slice(&buf[8..20]);
    Some(txn_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_has_correct_header() {
        let (buf, txn_id) = build_binding_request();

        // Message type: Binding Request
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), BINDING_REQUEST);
        // Message length: 0 (no attributes)
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 0);
        // Magic cookie
        assert_eq!(
            u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            STUN_MAGIC
        );
        // Transaction ID
        assert_eq!(&buf[8..20], &txn_id);
    }

    #[test]
    fn binding_response_roundtrip_and_xor_encoding() {
        let txn_id = [0xAA; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 8080);

        let response = build_binding_response(&txn_id, addr);

        // Attribute type at byte 20 should be XOR-MAPPED-ADDRESS
        assert_eq!(
            u16::from_be_bytes([response[20], response[21]]),
            ATTR_XOR_MAPPED_ADDRESS
        );

        // Wire bytes must be XOR'd, not plaintext (this is the whole point
        // of XOR-MAPPED-ADDRESS — defeat broken NAT ALGs that rewrite IPs
        // they find in packet payloads).
        let wire_port = u16::from_be_bytes([response[26], response[27]]);
        assert_ne!(wire_port, 8080);

        let wire_addr =
            u32::from_be_bytes([response[28], response[29], response[30], response[31]]);
        assert_ne!(wire_addr, u32::from(Ipv4Addr::new(203, 0, 113, 1)));

        // Parse it back — should recover the original address
        let parsed = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(parsed.mapped_addr, addr);
    }

    #[test]
    fn reject_wrong_txn_id() {
        let txn_id = [1u8; 12];
        let wrong_txn = [2u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);

        let response = build_binding_response(&txn_id, addr);
        let err = parse_binding_response(&response, &wrong_txn).unwrap_err();
        assert!(matches!(err, StunError::Protocol(msg) if msg.contains("transaction ID")));
    }

    #[test]
    fn reject_truncated_response() {
        let err = parse_binding_response(&[0u8; 10], &[0u8; 12]).unwrap_err();
        assert!(matches!(err, StunError::Protocol(msg) if msg.contains("too short")));
    }

    #[test]
    fn reject_wrong_message_type() {
        let txn_id = [1u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);

        let mut response = build_binding_response(&txn_id, addr);
        response[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());

        let err = parse_binding_response(&response, &txn_id).unwrap_err();
        assert!(matches!(err, StunError::Protocol(msg) if msg.contains("message type")));
    }

    #[test]
    fn parse_binding_request_valid() {
        let (buf, txn_id) = build_binding_request();
        let parsed = parse_binding_request(&buf);
        assert_eq!(parsed, Some(txn_id));
    }

    #[test]
    fn parse_binding_request_rejects_garbage() {
        assert_eq!(parse_binding_request(b"hello"), None);
        assert_eq!(parse_binding_request(&[]), None);
        assert_eq!(parse_binding_request(&[0u8; 19]), None); // one byte too short
    }

    #[test]
    fn parse_binding_request_rejects_response() {
        let txn_id = [1u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);
        let response = build_binding_response(&txn_id, addr);

        // A Binding Response should not be parsed as a request
        assert_eq!(parse_binding_request(&response), None);
    }
}
