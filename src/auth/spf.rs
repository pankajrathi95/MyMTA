// src/auth/spf.rs
//
// SPF (Sender Policy Framework) verification implementation.
//
// SPF allows domain owners to specify which servers are authorized to send
// email on their behalf by publishing DNS TXT records.
//
// RFC 7208 - Sender Policy Framework (SPF) for Authorizing Use of Domain Names

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of an SPF verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpfResult {
    /// SPF record not found for the domain
    None,
    /// Neutral result (no policy assertion)
    #[default]
    Neutral,
    /// Pass - the IP address is authorized
    Pass,
    /// Fail - the IP address is NOT authorized
    Fail,
    /// Soft fail - the IP address is NOT authorized (but in transition)
    SoftFail,
    /// Temporary error (DNS failure, etc.)
    TempError,
    /// Permanent error (invalid SPF record format)
    PermError,
}

impl SpfResult {
    /// Returns true if the result is a definitive pass.
    pub fn is_pass(&self) -> bool {
        matches!(self, SpfResult::Pass)
    }

    /// Returns true if the result indicates the sender is NOT authorized (fail or softfail).
    pub fn is_fail(&self) -> bool {
        matches!(self, SpfResult::Fail | SpfResult::SoftFail)
    }

    /// Returns true if this is an error result.
    pub fn is_error(&self) -> bool {
        matches!(self, SpfResult::TempError | SpfResult::PermError)
    }

    /// Get the recommended SMTP response code for this result.
    pub fn smtp_response(&self) -> Option<(u16, &'static str)> {
        match self {
            SpfResult::Fail => Some((550, "Message rejected due to SPF fail")),
            SpfResult::SoftFail => None, // Accept but may flag
            SpfResult::PermError => Some((550, "Message rejected due to SPF policy error")),
            _ => None,
        }
    }
}

impl fmt::Display for SpfResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpfResult::None => write!(f, "none"),
            SpfResult::Neutral => write!(f, "neutral"),
            SpfResult::Pass => write!(f, "pass"),
            SpfResult::Fail => write!(f, "fail"),
            SpfResult::SoftFail => write!(f, "softfail"),
            SpfResult::TempError => write!(f, "temperror"),
            SpfResult::PermError => write!(f, "permerror"),
        }
    }
}

/// SPF policy extracted from a DNS record.
#[derive(Debug, Clone, Default)]
pub struct SpfPolicy {
    /// The mechanisms in the SPF record (in order)
    pub mechanisms: Vec<Mechanism>,
    /// The default result if no mechanism matches
    pub default_result: SpfResult,
    /// Modifiers (e.g., redirect, exp)
    pub modifiers: Vec<(String, String)>,
}

/// An SPF mechanism.
#[derive(Debug, Clone)]
pub enum Mechanism {
    /// All - matches any IP
    All,
    /// A - matches if IP is in A/AAAA records for domain
    A { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    /// MX - matches if IP is in MX records for domain
    Mx { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    /// PTR - matches if IP's reverse DNS is in domain (deprecated)
    Ptr { domain: Option<String> },
    /// IP4 - matches IPv4 address or CIDR range
    Ip4 { network: Ipv4Addr, cidr: u8 },
    /// IP6 - matches IPv6 address or CIDR range
    Ip6 { network: Ipv6Addr, cidr: u8 },
    /// Exists - matches if A record exists for constructed domain
    Exists { domain: String },
    /// Include - include another domain's SPF record
    Include { domain: String },
}

/// SPF verifier for checking sender authorization.
pub struct SpfVerifier;

impl SpfVerifier {
    /// Create a new SPF verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify SPF for a given IP address and sender domain.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the connecting client
    /// * `sender_domain` - The domain part of the MAIL FROM address
    /// * `helo_domain` - The domain from the HELO/EHLO command
    ///
    /// Returns the SPF result.
    pub async fn verify(
        &self,
        ip: IpAddr,
        sender_domain: &str,
        helo_domain: &str,
    ) -> SpfResult {
        // For now, return a placeholder implementation
        // In a full implementation, this would:
        // 1. Query DNS for SPF TXT record on sender_domain
        // 2. Parse the SPF record
        // 3. Evaluate mechanisms against the IP address
        // 4. Return the appropriate result
        
        tracing::debug!(
            "SPF check: ip={}, sender={}, helo={}",
            ip,
            sender_domain,
            helo_domain
        );
        
        // Placeholder: return neutral (no policy)
        SpfResult::Neutral
    }

    /// Parse an SPF record string.
    pub fn parse_record(&self, record: &str) -> Result<SpfPolicy, SpfError> {
        let mut policy = SpfPolicy::default();
        let mut terms = record.split_whitespace();
        
        // First term must be "v=spf1"
        match terms.next() {
            Some("v=spf1") => {}
            _ => return Err(SpfError::InvalidVersion),
        }

        for term in terms {
            // Skip empty terms
            if term.is_empty() {
                continue;
            }

            // Check for modifier (contains '=')
            if let Some(pos) = term.find('=') {
                let name = &term[..pos];
                let value = &term[pos + 1..];
                policy.modifiers.push((name.to_string(), value.to_string()));
                continue;
            }

            // Parse mechanism
            let (qualifier, mechanism_str) = parse_qualifier(term);
            
            match parse_mechanism(mechanism_str) {
                Some(mechanism) => {
                    policy.mechanisms.push(mechanism);
                }
                None => {
                    return Err(SpfError::InvalidMechanism(term.to_string()));
                }
            }
        }

        // Default result is neutral if no explicit all
        if !policy.mechanisms.iter().any(|m| matches!(m, Mechanism::All)) {
            policy.default_result = SpfResult::Neutral;
        }

        Ok(policy)
    }

    /// Evaluate an SPF policy against an IP address.
    pub fn evaluate(&self, policy: &SpfPolicy, ip: IpAddr, _domain: &str) -> SpfResult {
        for mechanism in &policy.mechanisms {
            let matches = match mechanism {
                Mechanism::All => true,
                Mechanism::Ip4 { network, cidr } => {
                    if let IpAddr::V4(client_ip) = ip {
                        ip_in_cidr4(client_ip, *network, *cidr)
                    } else {
                        false
                    }
                }
                Mechanism::Ip6 { network, cidr } => {
                    if let IpAddr::V6(client_ip) = ip {
                        ip_in_cidr6(client_ip, *network, *cidr)
                    } else {
                        false
                    }
                }
                // Other mechanisms require DNS lookups
                _ => false,
            };

            if matches {
                // Determine result based on qualifier (default is Pass)
                return SpfResult::Pass;
            }
        }

        policy.default_result
    }
}

impl Default for SpfVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the qualifier prefix from a mechanism string.
fn parse_qualifier(term: &str) -> (char, &str) {
    match term.chars().next() {
        Some('+') => ('+', &term[1..]),
        Some('-') => ('-', &term[1..]),
        Some('~') => ('~', &term[1..]),
        Some('?') => ('?', &term[1..]),
        _ => ('+', term),
    }
}

/// Parse a mechanism from a string (without qualifier).
fn parse_mechanism(s: &str) -> Option<Mechanism> {
    if s == "all" {
        return Some(Mechanism::All);
    }

    if s.starts_with("ip4:") {
        let ip_str = &s[4..];
        if let Some(pos) = ip_str.find('/') {
            let ip_part = &ip_str[..pos];
            let cidr_part = &ip_str[pos + 1..];
            let ip = ip_part.parse::<Ipv4Addr>().ok()?;
            let cidr = cidr_part.parse::<u8>().ok()?;
            return Some(Mechanism::Ip4 { network: ip, cidr });
        } else {
            let ip = ip_str.parse::<Ipv4Addr>().ok()?;
            return Some(Mechanism::Ip4 { network: ip, cidr: 32 });
        }
    }

    if s.starts_with("ip6:") {
        let ip_str = &s[4..];
        if let Some(pos) = ip_str.find('/') {
            let ip_part = &ip_str[..pos];
            let cidr_part = &ip_str[pos + 1..];
            let ip = ip_part.parse::<Ipv6Addr>().ok()?;
            let cidr = cidr_part.parse::<u8>().ok()?;
            return Some(Mechanism::Ip6 { network: ip, cidr });
        } else {
            let ip = ip_str.parse::<Ipv6Addr>().ok()?;
            return Some(Mechanism::Ip6 { network: ip, cidr: 128 });
        }
    }

    if s.starts_with("a") {
        // a, a:domain, a/24, a:domain/24
        let rest = s.strip_prefix("a:").or_else(|| s.strip_prefix("a"));
        if let Some(rest) = rest {
            if rest.is_empty() {
                return Some(Mechanism::A { domain: None, cidr4: None, cidr6: None });
            }
            // Parse domain with optional CIDR
            // Simplified - full parsing would handle CIDR notation
            return Some(Mechanism::A { 
                domain: Some(rest.to_string()), 
                cidr4: None, 
                cidr6: None 
            });
        }
    }

    if s.starts_with("mx:") || s == "mx" {
        let domain = s.strip_prefix("mx:").map(|d| d.to_string());
        return Some(Mechanism::Mx { domain, cidr4: None, cidr6: None });
    }

    if s.starts_with("ptr:") || s == "ptr" {
        let domain = s.strip_prefix("ptr:").map(|d| d.to_string());
        return Some(Mechanism::Ptr { domain });
    }

    if s.starts_with("exists:") {
        let domain = s[7..].to_string();
        return Some(Mechanism::Exists { domain });
    }

    if s.starts_with("include:") {
        let domain = s[8..].to_string();
        return Some(Mechanism::Include { domain });
    }

    None
}

/// Check if an IPv4 address is within a CIDR range.
fn ip_in_cidr4(ip: Ipv4Addr, network: Ipv4Addr, cidr: u8) -> bool {
    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(network);
    let mask = if cidr == 0 {
        0
    } else {
        (!0u32) << (32 - cidr)
    };
    (ip_u32 & mask) == (net_u32 & mask)
}

/// Check if an IPv6 address is within a CIDR range.
fn ip_in_cidr6(ip: Ipv6Addr, network: Ipv6Addr, cidr: u8) -> bool {
    let ip_segments = ip.segments();
    let net_segments = network.segments();
    
    let full_segments = (cidr / 16) as usize;
    let remaining_bits = cidr % 16;
    
    // Check full segments
    for i in 0..full_segments {
        if ip_segments[i] != net_segments[i] {
            return false;
        }
    }
    
    // Check partial segment if needed
    if remaining_bits > 0 && full_segments < 8 {
        let mask = !0u16 << (16 - remaining_bits);
        if (ip_segments[full_segments] & mask) != (net_segments[full_segments] & mask) {
            return false;
        }
    }
    
    true
}

/// Errors that can occur during SPF operations.
#[derive(Debug, Clone)]
pub enum SpfError {
    /// Invalid SPF version
    InvalidVersion,
    /// Invalid mechanism syntax
    InvalidMechanism(String),
}

impl fmt::Display for SpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpfError::InvalidVersion => write!(f, "Invalid SPF version"),
            SpfError::InvalidMechanism(m) => write!(f, "Invalid SPF mechanism: {}", m),
        }
    }
}

impl std::error::Error for SpfError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spf_result_display() {
        assert_eq!(SpfResult::Pass.to_string(), "pass");
        assert_eq!(SpfResult::Fail.to_string(), "fail");
        assert_eq!(SpfResult::SoftFail.to_string(), "softfail");
    }

    #[test]
    fn test_parse_qualifier() {
        assert_eq!(parse_qualifier("all"), ('+', "all"));
        assert_eq!(parse_qualifier("-all"), ('-', "all"));
        assert_eq!(parse_qualifier("~all"), ('~', "all"));
        assert_eq!(parse_qualifier("?all"), ('?', "all"));
    }

    #[test]
    fn test_parse_mechanism_all() {
        assert!(matches!(parse_mechanism("all"), Some(Mechanism::All)));
    }

    #[test]
    fn test_parse_mechanism_ip4() {
        let result = parse_mechanism("ip4:192.168.1.1");
        assert!(matches!(result, Some(Mechanism::Ip4 { network, cidr: 32 }) if network == Ipv4Addr::new(192, 168, 1, 1)));
        
        let result = parse_mechanism("ip4:192.168.0.0/16");
        assert!(matches!(result, Some(Mechanism::Ip4 { network, cidr: 16 }) if network == Ipv4Addr::new(192, 168, 0, 0)));
    }

    #[test]
    fn test_parse_record() {
        let verifier = SpfVerifier::new();
        
        // Valid record
        let record = "v=spf1 ip4:192.168.1.0/24 include:_spf.google.com ~all";
        let policy = verifier.parse_record(record).unwrap();
        assert_eq!(policy.mechanisms.len(), 3);
        
        // Invalid version
        let record = "v=spf2 ip4:192.168.1.1 -all";
        assert!(verifier.parse_record(record).is_err());
    }

    #[test]
    fn test_ip_in_cidr4() {
        assert!(ip_in_cidr4(
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));
        
        assert!(!ip_in_cidr4(
            Ipv4Addr::new(192, 168, 2, 50),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));
    }

    #[test]
    fn test_spf_result_helpers() {
        assert!(SpfResult::Pass.is_pass());
        assert!(!SpfResult::Fail.is_pass());
        
        assert!(SpfResult::Fail.is_fail());
        assert!(SpfResult::SoftFail.is_fail());
        assert!(!SpfResult::Pass.is_fail());
        
        assert!(SpfResult::TempError.is_error());
        assert!(SpfResult::PermError.is_error());
        assert!(!SpfResult::Pass.is_error());
    }
}
