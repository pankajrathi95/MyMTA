// src/dns/error.rs
//
// DNS error types and classification for email delivery decisions.
//
// Each error maps to a delivery action:
//   - Permanent: bounce immediately (bad domain, no mail target)
//   - Temporary: retry later (server errors, timeouts)

use std::fmt;

/// Classification of a DNS failure for email delivery purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFailureMode {
    /// Domain doesn't exist (NXDOMAIN). Permanent → bounce.
    Permanent,
    /// DNS server error, timeout, or network issue. Temporary → retry.
    Temporary,
}

/// All possible DNS resolution errors.
#[derive(Debug, Clone)]
pub enum DnsError {
    /// NXDOMAIN — the domain does not exist.
    NxDomain { domain: String },
    /// NODATA — domain exists but has no MX or A/AAAA records.
    NoData { domain: String, query_type: String },
    /// SERVFAIL — upstream DNS server reported failure.
    ServFail { domain: String, message: String },
    /// Query was refused by the server.
    Refused { domain: String },
    /// Query timed out.
    Timeout { domain: String },
    /// Response was malformed or truncated.
    Malformed { domain: String, message: String },
    /// CNAME chain exceeded max depth (loop or very long chain).
    CnameLoop { domain: String, max_depth: usize },
    /// Other I/O or resolver error.
    Other { domain: String, message: String },
}

impl DnsError {
    /// Classify this error for delivery decisions.
    pub fn failure_mode(&self) -> DnsFailureMode {
        match self {
            DnsError::NxDomain { .. } => DnsFailureMode::Permanent,
            DnsError::NoData { .. } => DnsFailureMode::Permanent,
            DnsError::CnameLoop { .. } => DnsFailureMode::Permanent,
            DnsError::ServFail { .. } => DnsFailureMode::Temporary,
            DnsError::Refused { .. } => DnsFailureMode::Temporary,
            DnsError::Timeout { .. } => DnsFailureMode::Temporary,
            DnsError::Malformed { .. } => DnsFailureMode::Temporary,
            DnsError::Other { .. } => DnsFailureMode::Temporary,
        }
    }

    /// Returns true if this error means permanent delivery failure (bounce).
    pub fn is_permanent(&self) -> bool {
        self.failure_mode() == DnsFailureMode::Permanent
    }

    /// Returns true if this error means temporary failure (retry later).
    pub fn is_temporary(&self) -> bool {
        self.failure_mode() == DnsFailureMode::Temporary
    }

    /// The domain that caused this error.
    pub fn domain(&self) -> &str {
        match self {
            DnsError::NxDomain { domain } => domain,
            DnsError::NoData { domain, .. } => domain,
            DnsError::ServFail { domain, .. } => domain,
            DnsError::Refused { domain } => domain,
            DnsError::Timeout { domain } => domain,
            DnsError::Malformed { domain, .. } => domain,
            DnsError::CnameLoop { domain, .. } => domain,
            DnsError::Other { domain, .. } => domain,
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NxDomain { domain } => write!(f, "NXDOMAIN: {}", domain),
            DnsError::NoData { domain, query_type } => {
                write!(f, "NODATA: {} has no {} records", domain, query_type)
            }
            DnsError::ServFail { domain, message } => {
                write!(f, "SERVFAIL for {}: {}", domain, message)
            }
            DnsError::Refused { domain } => write!(f, "REFUSED: {}", domain),
            DnsError::Timeout { domain } => write!(f, "DNS timeout for {}", domain),
            DnsError::Malformed { domain, message } => {
                write!(f, "Malformed DNS response for {}: {}", domain, message)
            }
            DnsError::CnameLoop { domain, max_depth } => {
                write!(f, "CNAME loop for {} (max depth {})", domain, max_depth)
            }
            DnsError::Other { domain, message } => {
                write!(f, "DNS error for {}: {}", domain, message)
            }
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nxdomain_is_permanent() {
        let e = DnsError::NxDomain { domain: "bad.domain".into() };
        assert!(e.is_permanent());
        assert!(!e.is_temporary());
        assert_eq!(e.failure_mode(), DnsFailureMode::Permanent);
    }

    #[test]
    fn nodata_is_permanent() {
        let e = DnsError::NoData { domain: "no.mx".into(), query_type: "MX".into() };
        assert!(e.is_permanent());
    }

    #[test]
    fn servfail_is_temporary() {
        let e = DnsError::ServFail { domain: "x".into(), message: "upstream".into() };
        assert!(e.is_temporary());
        assert!(!e.is_permanent());
    }

    #[test]
    fn timeout_is_temporary() {
        let e = DnsError::Timeout { domain: "slow".into() };
        assert!(e.is_temporary());
    }

    #[test]
    fn refused_is_temporary() {
        let e = DnsError::Refused { domain: "denied".into() };
        assert!(e.is_temporary());
    }

    #[test]
    fn cname_loop_is_permanent() {
        let e = DnsError::CnameLoop { domain: "loop".into(), max_depth: 8 };
        assert!(e.is_permanent());
    }

    #[test]
    fn error_display() {
        let e = DnsError::NxDomain { domain: "gone.com".into() };
        assert!(e.to_string().contains("NXDOMAIN"));
        assert!(e.to_string().contains("gone.com"));
    }
}
