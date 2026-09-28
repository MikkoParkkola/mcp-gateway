// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Subject Alternative Names for a leaf certificate.

use std::net::{IpAddr, Ipv6Addr};

use rcgen::SanType;
use rcgen::string::Ia5String;

use crate::{Error, Result};

/// The SANs for `san_dns` then `san_uris`, in order.
///
/// A `san_dns` entry that is an IP literal becomes an IP SAN: a client dialling
/// an address matches IP SANs only, so the address as a DNS name never verifies.
pub(super) fn leaf_sans(san_dns: &[String], san_uris: &[String]) -> Result<Vec<SanType>> {
    let mut sans = Vec::with_capacity(san_dns.len() + san_uris.len());
    for entry in san_dns {
        let entry = entry.as_str();
        if let Some(ip) = ip_literal(entry) {
            sans.push(SanType::IpAddress(ip));
            continue;
        }
        let ia5 = Ia5String::try_from(entry)
            .map_err(|e| Error::Config(format!("Invalid DNS SAN '{entry}': {e}")))?;
        sans.push(SanType::DnsName(ia5));
    }
    for uri in san_uris {
        let ia5 = Ia5String::try_from(uri.as_str())
            .map_err(|e| Error::Config(format!("Invalid URI SAN '{uri}': {e}")))?;
        sans.push(SanType::URI(ia5));
    }
    Ok(sans)
}

/// `entry` as an IP address: IPv4 dotted quad, IPv6, or IPv6 in brackets.
fn ip_literal(entry: &str) -> Option<IpAddr> {
    match entry.strip_prefix('[').and_then(|e| e.strip_suffix(']')) {
        Some(inner) => inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        None => entry.parse().ok(),
    }
}
