// src/delivery/mx_resolve.rs
//
// MX to IP resolution strategy with fallback to A/AAAA records.
// Implements RFC 5321 Section 5.1 (Locating the Target Host).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::dns::resolver::{DnsResolver, MxRecord, MxResult};
use crate::delivery::error::DeliveryError;

/// Port for SMTP submission (standard).
pub const SMTP_PORT: u16 = 25;

/// Port for SMTP with implicit TLS (SMTPS).
pub const SMTPS_PORT: u16 = 465;

/// Port for message submission with STARTTLS.
pub const SUBMISSION_PORT: u16 = 587;

/// A resolved destination with all candidate IPs.
#[derive(Debug, Clone)]
pub struct ResolvedDestination {
    /// The domain being delivered to
    pub domain: String,
    /// The MX exchange hostname (or domain if using A/AAAA fallback)
    pub exchange: String,
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// MX preference (lower = higher priority)
    pub preference: u16,
    /// Port to connect to
    pub port: u16,
}

impl ResolvedDestination {
    /// Create socket addresses for all resolved IPs.
    pub fn to_socket_addrs(&self) -> Vec<SocketAddr> {
        self.addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect()
    }

    /// Returns true if this destination has any resolved IPs.
    pub fn is_resolved(&self) -> bool {
        !self.addresses.is_empty()
    }
}

/// MX resolver that handles MX lookup with A/AAAA fallback.
pub struct MxResolver<R: DnsResolver> {
    resolver: Arc<R>,
    port: u16,
}

impl<R: DnsResolver> MxResolver<R> {
    /// Create a new MX resolver with default SMTP port.
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            port: SMTP_PORT,
        }
    }

    /// Create with a custom port (e.g., 587 for submission).
    pub fn with_port(resolver: Arc<R>, port: u16) -> Self {
        Self { resolver, port }
    }

    /// Resolve a domain to a list of candidate destinations.
    ///
    /// Strategy per RFC 5321:
    /// 1. Query MX records
    /// 2. If MX exists: sort by preference, resolve each exchange to IPs
    /// 3. If no MX: try A/AAAA lookup on the domain itself (fallback)
    /// 4. If all fail: return error
    pub async fn resolve(&self, domain: &str) -> Result<Vec<ResolvedDestination>, DeliveryError> {
        let domain = domain.to_lowercase();

        // Step 1: Try MX lookup
        match self.resolver.resolve_mx(&domain).await {
            MxResult::Ok(records) if !records.is_empty() => {
                // Sort by preference (ascending - lower is better)
                let mut records = records;
                records.sort_by_key(|r| r.preference);

                // Resolve each MX exchange to IPs
                let mut destinations = Vec::new();
                for mx in records {
                    match self.resolve_mx_exchange(&domain, &mx).await {
                        Some(dest) if dest.is_resolved() => destinations.push(dest),
                        _ => continue, // Skip unresolvable exchanges
                    }
                }

                if destinations.is_empty() {
                    return Err(DeliveryError::DnsResolutionFailed {
                        domain,
                        reason: "MX records found but none resolve to IP addresses".to_string(),
                    });
                }

                Ok(destinations)
            }
            _ => {
                // Step 2: MX lookup failed or returned empty - try A/AAAA fallback
                self.resolve_fallback_a_aaaa(&domain).await
            }
        }
    }

    /// Resolve a single MX exchange hostname to IPs.
    async fn resolve_mx_exchange(
        &self,
        domain: &str,
        mx: &MxRecord,
    ) -> Option<ResolvedDestination> {
        let exchange = mx.exchange.trim_end_matches('.').to_lowercase();

        // Try AAAA first (IPv6 preference), then A
        let mut addresses = Vec::new();

        match self.resolver.resolve_aaaa(&exchange).await {
            crate::dns::resolver::AddrResult::Ok(ips) => addresses.extend(ips),
            _ => {}
        }

        match self.resolver.resolve_a(&exchange).await {
            crate::dns::resolver::AddrResult::Ok(ips) => addresses.extend(ips),
            _ => {}
        }

        Some(ResolvedDestination {
            domain: domain.to_string(),
            exchange,
            addresses,
            preference: mx.preference,
            port: self.port,
        })
    }

    /// A/AAAA fallback when no MX records exist.
    async fn resolve_fallback_a_aaaa(
        &self,
        domain: &str,
    ) -> Result<Vec<ResolvedDestination>, DeliveryError> {
        let mut addresses = Vec::new();

        // Try AAAA first
        match self.resolver.resolve_aaaa(domain).await {
            crate::dns::resolver::AddrResult::Ok(ips) => addresses.extend(ips),
            _ => {}
        }

        // Then A
        match self.resolver.resolve_a(domain).await {
            crate::dns::resolver::AddrResult::Ok(ips) => addresses.extend(ips),
            _ => {}
        }

        if addresses.is_empty() {
            return Err(DeliveryError::DnsResolutionFailed {
                domain: domain.to_string(),
                reason: "No MX records and no A/AAAA records found".to_string(),
            });
        }

        Ok(vec![ResolvedDestination {
            domain: domain.to_string(),
            exchange: domain.to_string(),
            addresses,
            preference: 0, // No MX preference in fallback
            port: self.port,
        }])
    }
}

/// Select the best destination to try based on preference and previous failures.
pub fn select_destination<'a>(
    destinations: &'a [ResolvedDestination],
    attempted: &[SocketAddr],
) -> Option<&'a ResolvedDestination> {
    for dest in destinations {
        // Find an address we haven't tried yet
        for addr in dest.to_socket_addrs() {
            if !attempted.contains(&addr) {
                return Some(dest);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::MockDnsResolver;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn mx(exchange: &str, preference: u16) -> MxRecord {
        MxRecord {
            preference,
            exchange: exchange.to_string(),
        }
    }

    #[tokio::test]
    async fn test_mx_resolution_success() {
        let mock = Arc::new(MockDnsResolver::new());

        // Setup: MX records for example.com
        mock.set_mx(
            "example.com",
            vec![mx("mail1.example.com", 10), mx("mail2.example.com", 20)],
            Duration::from_secs(300),
        )
        .await;

        // Setup: IP addresses for MX exchanges
        mock.set_a(
            "mail1.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            Duration::from_secs(300),
        )
        .await;
        mock.set_a(
            "mail2.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))],
            Duration::from_secs(300),
        )
        .await;

        let resolver = MxResolver::new(mock);
        let dests = resolver.resolve("example.com").await.unwrap();

        assert_eq!(dests.len(), 2);
        // Should be sorted by preference
        assert_eq!(dests[0].preference, 10);
        assert_eq!(dests[0].exchange, "mail1.example.com");
        assert_eq!(dests[1].preference, 20);
        assert_eq!(dests[1].exchange, "mail2.example.com");
    }

    #[tokio::test]
    async fn test_mx_with_ipv6_preference() {
        let mock = Arc::new(MockDnsResolver::new());

        mock.set_mx(
            "example.com",
            vec![mx("mail.example.com", 10)],
            Duration::from_secs(300),
        )
        .await;

        mock.set_aaaa(
            "mail.example.com",
            vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))],
            Duration::from_secs(300),
        )
        .await;

        let resolver = MxResolver::new(mock);
        let dests = resolver.resolve("example.com").await.unwrap();

        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].addresses.len(), 1);
        assert!(matches!(dests[0].addresses[0], IpAddr::V6(_)));
    }

    #[tokio::test]
    async fn test_a_aaaa_fallback() {
        let mock = Arc::new(MockDnsResolver::new());

        // No MX records - should fallback to A record
        mock.set_a(
            "example.com",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            Duration::from_secs(300),
        )
        .await;

        let resolver = MxResolver::new(mock);
        let dests = resolver.resolve("example.com").await.unwrap();

        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].exchange, "example.com"); // Domain itself
        assert_eq!(dests[0].preference, 0); // No MX preference
    }

    #[tokio::test]
    async fn test_mx_unresolvable_exchange_skipped() {
        let mock = Arc::new(MockDnsResolver::new());

        mock.set_mx(
            "example.com",
            vec![mx("bad.example.com", 10), mx("good.example.com", 20)],
            Duration::from_secs(300),
        )
        .await;

        // Only good.example.com resolves
        mock.set_a(
            "good.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            Duration::from_secs(300),
        )
        .await;

        let resolver = MxResolver::new(mock);
        let dests = resolver.resolve("example.com").await.unwrap();

        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].exchange, "good.example.com");
    }

    #[test]
    fn test_select_destination() {
        let dest1 = ResolvedDestination {
            domain: "example.com".to_string(),
            exchange: "mx1.example.com".to_string(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            preference: 10,
            port: 25,
        };

        let dest2 = ResolvedDestination {
            domain: "example.com".to_string(),
            exchange: "mx2.example.com".to_string(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))],
            preference: 20,
            port: 25,
        };

        let destinations = vec![dest1, dest2];

        // No attempts yet - should return first
        let selected = select_destination(&destinations, &[]);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().preference, 10);

        // After trying first, should return second
        let attempted = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            25,
        )];
        let selected = select_destination(&destinations, &attempted);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().preference, 20);

        // After trying both, should return None
        let attempted = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 25),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 25),
        ];
        let selected = select_destination(&destinations, &attempted);
        assert!(selected.is_none());
    }
}
