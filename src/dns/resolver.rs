// src/dns/resolver.rs
//
// DNS resolver trait and implementations.
//
// - DnsResolver trait: abstract resolver interface
// - MockDnsResolver: in-memory mock for tests (no network)
// - RealResolver: hickory-resolver backed (real DNS, used at runtime)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::cache::DnsCache;
use super::error::{DnsError, DnsFailureMode};

/// An MX record: preference + exchange host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Result of an MX resolution: either records or a classified error.
#[derive(Debug, Clone)]
pub enum MxResult {
    /// Successfully resolved MX records (may be empty if A/AAAA fallback applies).
    Ok(Vec<MxRecord>),
    /// Resolution failed with a classified error.
    Err(DnsError),
}

impl MxResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, MxResult::Ok(_))
    }

    pub fn is_err(&self) -> bool {
        matches!(self, MxResult::Err(_))
    }

    pub fn as_ref(&self) -> Result<&[MxRecord], &DnsError> {
        match self {
            MxResult::Ok(v) => Ok(v),
            MxResult::Err(e) => Err(e),
        }
    }
}

/// Result of A/AAAA resolution.
#[derive(Debug, Clone)]
pub enum AddrResult {
    Ok(Vec<IpAddr>),
    Err(DnsError),
}

impl AddrResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, AddrResult::Ok(_))
    }

    pub fn is_err(&self) -> bool {
        matches!(self, AddrResult::Err(_))
    }
}

/// Abstract DNS resolver. All tests use MockDnsResolver.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve MX records for a domain.
    /// Returns Ok(vec) on success (possibly empty → caller should try A/AAAA fallback),
    /// or Err(DnsError) on failure.
    async fn resolve_mx(&self, domain: &str) -> MxResult;

    /// Resolve A records (IPv4) for a host.
    async fn resolve_a(&self, host: &str) -> AddrResult;

    /// Resolve AAAA records (IPv6) for a host.
    async fn resolve_aaaa(&self, host: &str) -> AddrResult;
}

// ── Mock resolver (for tests — NO network) ──────────────────────────

/// A programmable mock resolver. Pre-load answers; no network calls ever.
pub struct MockDnsResolver {
    /// Pre-programmed MX answers: domain → (records, ttl, maybe error).
    mx: RwLock<HashMap<String, MockMx>>,
    /// Pre-programmed A answers.
    a: RwLock<HashMap<String, MockAddr>>,
    /// Pre-programmed AAAA answers.
    aaaa: RwLock<HashMap<String, MockAddr>>,
    /// CNAME records: alias → canonical name.
    cname: RwLock<HashMap<String, String>>,
    /// Max CNAME chain depth before error.
    max_cname_depth: usize,
}

#[derive(Debug, Clone)]
enum MockMx {
    Ok { records: Vec<MxRecord>, ttl: Duration },
    Err(DnsError),
}

#[derive(Debug, Clone)]
enum MockAddr {
    Ok { ips: Vec<IpAddr>, ttl: Duration },
    Err(DnsError),
}

impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            mx: RwLock::new(HashMap::new()),
            a: RwLock::new(HashMap::new()),
            aaaa: RwLock::new(HashMap::new()),
            cname: RwLock::new(HashMap::new()),
            max_cname_depth: 8,
        }
    }

    pub fn with_max_cname_depth(mut self, depth: usize) -> Self {
        self.max_cname_depth = depth;
        self
    }

    /// Program a CNAME record: alias resolves to target (canonical name).
    pub async fn set_cname(&self, alias: &str, target: &str) {
        self.cname.write().await.insert(alias.to_lowercase(), target.to_lowercase());
    }

    /// Program an MX success response.
    pub async fn set_mx(&self, domain: &str, records: Vec<MxRecord>, ttl: Duration) {
        self.mx.write().await.insert(domain.to_lowercase(), MockMx::Ok { records, ttl });
    }

    /// Program an MX error response.
    pub async fn set_mx_err(&self, domain: &str, err: DnsError) {
        self.mx.write().await.insert(domain.to_lowercase(), MockMx::Err(err));
    }

    /// Program an A success response.
    pub async fn set_a(&self, host: &str, ips: Vec<IpAddr>, ttl: Duration) {
        self.a.write().await.insert(host.to_lowercase(), MockAddr::Ok { ips, ttl });
    }

    /// Program an A error response.
    pub async fn set_a_err(&self, host: &str, err: DnsError) {
        self.a.write().await.insert(host.to_lowercase(), MockAddr::Err(err));
    }

    /// Program an AAAA success response.
    pub async fn set_aaaa(&self, host: &str, ips: Vec<IpAddr>, ttl: Duration) {
        self.aaaa.write().await.insert(host.to_lowercase(), MockAddr::Ok { ips, ttl });
    }

    /// Program an AAAA error response.
    pub async fn set_aaaa_err(&self, host: &str, err: DnsError) {
        self.aaaa.write().await.insert(host.to_lowercase(), MockAddr::Err(err));
    }

    /// Clear all programmed responses.
    pub async fn clear(&self) {
        self.mx.write().await.clear();
        self.a.write().await.clear();
        self.aaaa.write().await.clear();
        self.cname.write().await.clear();
    }

    /// Follow CNAME chain starting from `name`, returning the final canonical name.
    /// Returns Err(CnameLoop) if a loop is detected or max depth exceeded.
    async fn resolve_cname_chain(&self, start: &str) -> Result<String, DnsError> {
        let mut current = start.to_lowercase();
        let mut visited = std::collections::HashSet::new();
        let mut depth = 0;

        loop {
            if depth >= self.max_cname_depth {
                return Err(DnsError::CnameLoop {
                    domain: start.to_string(),
                    max_depth: self.max_cname_depth,
                });
            }
            if visited.contains(&current) {
                return Err(DnsError::CnameLoop {
                    domain: start.to_string(),
                    max_depth: self.max_cname_depth,
                });
            }
            visited.insert(current.clone());

            let guard = self.cname.read().await;
            if let Some(target) = guard.get(&current) {
                current = target.clone();
                depth += 1;
            } else {
                // No more CNAMEs; current is the final name
                return Ok(current);
            }
        }
    }
}

impl Default for MockDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn resolve_mx(&self, domain: &str) -> MxResult {
        // Follow CNAME chain first (detects loops)
        match self.resolve_cname_chain(domain).await {
            Ok(final_name) => {
                let guard = self.mx.read().await;
                match guard.get(&final_name) {
                    Some(MockMx::Ok { records, .. }) => MxResult::Ok(records.clone()),
                    Some(MockMx::Err(e)) => MxResult::Err(e.clone()),
                    None => MxResult::Err(DnsError::NxDomain { domain: domain.to_string() }),
                }
            }
            Err(e) => MxResult::Err(e),
        }
    }

    async fn resolve_a(&self, host: &str) -> AddrResult {
        // Follow CNAME chain first (detects loops)
        match self.resolve_cname_chain(host).await {
            Ok(final_name) => {
                let guard = self.a.read().await;
                match guard.get(&final_name) {
                    Some(MockAddr::Ok { ips, .. }) => AddrResult::Ok(ips.clone()),
                    Some(MockAddr::Err(e)) => AddrResult::Err(e.clone()),
                    None => AddrResult::Err(DnsError::NxDomain { domain: host.to_string() }),
                }
            }
            Err(e) => AddrResult::Err(e),
        }
    }

    async fn resolve_aaaa(&self, host: &str) -> AddrResult {
        // Follow CNAME chain first (detects loops)
        match self.resolve_cname_chain(host).await {
            Ok(final_name) => {
                let guard = self.aaaa.read().await;
                match guard.get(&final_name) {
                    Some(MockAddr::Ok { ips, .. }) => AddrResult::Ok(ips.clone()),
                    Some(MockAddr::Err(e)) => AddrResult::Err(e.clone()),
                    None => AddrResult::Err(DnsError::NxDomain { domain: host.to_string() }),
                }
            }
            Err(e) => AddrResult::Err(e),
        }
    }
}

// ── Real resolver (hickory-resolver) ──────────────────────────────────

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// Real DNS resolver using hickory-resolver (trust-dns).
/// Wraps a cache; on cache miss, queries the network.
pub struct RealResolver {
    inner: TokioAsyncResolver,
    cache: DnsCache,
    max_cname_depth: usize,
}

impl RealResolver {
    /// Create with system default resolver and default cache config.
    pub fn new() -> Result<Self, DnsError> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self {
            inner: resolver,
            cache: DnsCache::with_defaults(),
            max_cname_depth: 8,
        })
    }

    /// Create with custom cache config.
    pub fn with_cache_config(cache_cfg: super::cache::CacheConfig) -> Result<Self, DnsError> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self {
            inner: resolver,
            cache: DnsCache::new(cache_cfg),
            max_cname_depth: 8,
        })
    }

    /// Create sharing an existing cache (for coordinated cache use).
    pub fn with_cache(cache: DnsCache) -> Result<Self, DnsError> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self {
            inner: resolver,
            cache,
            max_cname_depth: 8,
        })
    }

    /// Set max CNAME chain depth.
    pub fn set_max_cname_depth(&mut self, depth: usize) {
        self.max_cname_depth = depth;
    }

    /// Helper: convert hickory MX to our MxRecord.
    fn mx_from_hickory(mx: &hickory_resolver::proto::rr::rdata::MX) -> MxRecord {
        MxRecord {
            preference: mx.preference(),
            exchange: mx.exchange().to_string(),
        }
    }

    // NOTE: CNAME chain following is complex with hickory-resolver's type system.
    // For Phase 3 we rely on hickory's internal CNAME handling during MX/A lookups.
    // The MockDnsResolver supports explicit CNAME programming for tests.
    // A future enhancement can add explicit CNAME chasing here.
}

#[async_trait]
impl DnsResolver for RealResolver {
    async fn resolve_mx(&self, domain: &str) -> MxResult {
        // Check cache first
        if let Some(cached) = self.cache.get_mx(domain).await {
            return MxResult::Ok(cached);
        }
        if let Some(_remaining) = self.cache.get_negative(domain, "MX").await {
            return MxResult::Err(DnsError::NoData { domain: domain.into(), query_type: "MX".into() });
        }

        // Query MX
        match self.inner.mx_lookup(domain).await {
            Ok(resp) => {
                let records: Vec<MxRecord> = resp.iter().map(Self::mx_from_hickory).collect();
                // Follow CNAME for each exchange? The MX exchange can itself be a CNAME.
                // For simplicity, we don't fully chase CNAMEs in MX exchange here;
                // real MTAs often do. We'll leave that to the A/AAAA lookup stage.
                let ttl = resp.as_lookup().valid_until().saturating_duration_since(std::time::Instant::now());
                self.cache.insert_mx(domain, records.clone(), ttl).await;
                MxResult::Ok(records)
            }
            Err(e) => {
                let de = map_hickory_err(e, domain);
                if de.is_permanent() {
                    // Cache negative
                    self.cache.insert_negative(domain, "MX").await;
                }
                MxResult::Err(de)
            }
        }
    }

    async fn resolve_a(&self, host: &str) -> AddrResult {
        if let Some(cached) = self.cache.get_a(host).await {
            return AddrResult::Ok(cached);
        }
        if let Some(_rem) = self.cache.get_negative(host, "A").await {
            return AddrResult::Err(DnsError::NoData { domain: host.into(), query_type: "A".into() });
        }

        match self.inner.ipv4_lookup(host).await {
            Ok(resp) => {
                // A RData wraps Ipv4Addr; extract via .0
                let ips: Vec<IpAddr> = resp.iter().map(|a| IpAddr::V4(a.0)).collect();
                let ttl = resp.as_lookup().valid_until().saturating_duration_since(std::time::Instant::now());
                self.cache.insert_a(host, ips.clone(), ttl).await;
                AddrResult::Ok(ips)
            }
            Err(e) => {
                let de = map_hickory_err(e, host);
                if de.is_permanent() {
                    self.cache.insert_negative(host, "A").await;
                }
                AddrResult::Err(de)
            }
        }
    }

    async fn resolve_aaaa(&self, host: &str) -> AddrResult {
        if let Some(cached) = self.cache.get_aaaa(host).await {
            return AddrResult::Ok(cached);
        }
        if let Some(_rem) = self.cache.get_negative(host, "AAAA").await {
            return AddrResult::Err(DnsError::NoData { domain: host.into(), query_type: "AAAA".into() });
        }

        match self.inner.ipv6_lookup(host).await {
            Ok(resp) => {
                // AAAA RData wraps Ipv6Addr; extract via .0
                let ips: Vec<IpAddr> = resp.iter().map(|a| IpAddr::V6(a.0)).collect();
                let ttl = resp.as_lookup().valid_until().saturating_duration_since(std::time::Instant::now());
                self.cache.insert_aaaa(host, ips.clone(), ttl).await;
                AddrResult::Ok(ips)
            }
            Err(e) => {
                let de = map_hickory_err(e, host);
                if de.is_permanent() {
                    self.cache.insert_negative(host, "AAAA").await;
                }
                AddrResult::Err(de)
            }
        }
    }
}

/// Map hickory resolver errors to our DnsError.
fn map_hickory_err(e: hickory_resolver::error::ResolveError, domain: &str) -> DnsError {
    use hickory_resolver::error::ResolveErrorKind;
    match e.kind() {
        ResolveErrorKind::NoRecordsFound { .. } => {
            DnsError::NoData { domain: domain.into(), query_type: "MX/A/AAAA".into() }
        }
        ResolveErrorKind::NoConnections => DnsError::Timeout { domain: domain.into() },
        ResolveErrorKind::Io(_) => DnsError::Other { domain: domain.into(), message: e.to_string() },
        ResolveErrorKind::Proto(_) => DnsError::Malformed { domain: domain.into(), message: e.to_string() },
        ResolveErrorKind::Message(_) => DnsError::ServFail { domain: domain.into(), message: e.to_string() },
        ResolveErrorKind::Timeout => DnsError::Timeout { domain: domain.into() },
        _ => DnsError::Other { domain: domain.into(), message: e.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mx(ex: &str, pref: u16) -> MxRecord {
        MxRecord { preference: pref, exchange: ex.into() }
    }

    // ── Mock tests (no network ever) ──────────────────────────────────

    #[tokio::test]
    async fn mock_mx_ok() {
        let mock = MockDnsResolver::new();
        mock.set_mx("example.com", vec![mx("mail.example.com", 10)], Duration::from_secs(60)).await;

        let res = mock.resolve_mx("example.com").await;
        assert!(res.is_ok());
        let recs = match res { MxResult::Ok(v) => v, _ => panic!() };
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].exchange, "mail.example.com");
        assert_eq!(recs[0].preference, 10);
    }

    #[tokio::test]
    async fn mock_mx_nxdomain() {
        let mock = MockDnsResolver::new();
        // Not programmed → default NXDOMAIN
        let res = mock.resolve_mx("nope.example.com").await;
        assert!(res.is_err());
        let err = match res { MxResult::Err(e) => e, _ => panic!() };
        assert!(err.is_permanent());
        assert!(matches!(err, DnsError::NxDomain { .. }));
    }

    #[tokio::test]
    async fn mock_mx_servfail() {
        let mock = MockDnsResolver::new();
        mock.set_mx_err("bad.srv", DnsError::ServFail { domain: "bad.srv".into(), message: "upstream dead".into() }).await;

        let res = mock.resolve_mx("bad.srv").await;
        assert!(res.is_err());
        let err = match res { MxResult::Err(e) => e, _ => panic!() };
        assert!(err.is_temporary());
    }

    #[tokio::test]
    async fn mock_a_ok() {
        let mock = MockDnsResolver::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1,2,3,4));
        mock.set_a("mail.example.com", vec![ip], Duration::from_secs(60)).await;

        let res = mock.resolve_a("mail.example.com").await;
        assert!(res.is_ok());
        let ips = match res { AddrResult::Ok(v) => v, _ => panic!() };
        assert_eq!(ips, vec![ip]);
    }

    #[tokio::test]
    async fn mock_aaaa_ok() {
        let mock = MockDnsResolver::new();
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        mock.set_aaaa("mail.example.com", vec![ip], Duration::from_secs(60)).await;

        let res = mock.resolve_aaaa("mail.example.com").await;
        assert!(res.is_ok());
        let ips = match res { AddrResult::Ok(v) => v, _ => panic!() };
        assert_eq!(ips, vec![ip]);
    }

    #[tokio::test]
    async fn mock_case_insensitive() {
        let mock = MockDnsResolver::new();
        mock.set_mx("Example.COM", vec![mx("Mail.Example.COM", 5)], Duration::from_secs(60)).await;

        // Query with different case
        let res = mock.resolve_mx("EXAMPLE.com").await;
        assert!(res.is_ok());
        let recs = match res { MxResult::Ok(v) => v, _ => panic!() };
        assert_eq!(recs[0].exchange, "Mail.Example.COM");
    }

    #[tokio::test]
    async fn mock_timeout_is_temporary() {
        let mock = MockDnsResolver::new();
        mock.set_mx_err("slow", DnsError::Timeout { domain: "slow".into() }).await;

        let res = mock.resolve_mx("slow").await;
        let err = match res { MxResult::Err(e) => e, _ => panic!() };
        assert!(err.is_temporary());
    }

    #[tokio::test]
    async fn mock_clear() {
        let mock = MockDnsResolver::new();
        mock.set_mx("x.com", vec![mx("m.x.com", 1)], Duration::from_secs(60)).await;
        assert!(mock.resolve_mx("x.com").await.is_ok());
        mock.clear().await;
        // After clear, unprogrammed → NXDOMAIN
        let res = mock.resolve_mx("x.com").await;
        assert!(res.is_err());
    }

    // ── CNAME chain and loop tests ────────────────────────────────────

    #[tokio::test]
    async fn mock_cname_chain_follows_to_final() {
        let mock = MockDnsResolver::new();
        // A → CNAME → B → (A record)
        mock.set_cname("a.example.com", "b.example.com").await;
        let ip = IpAddr::V4(Ipv4Addr::new(1,2,3,4));
        mock.set_a("b.example.com", vec![ip], Duration::from_secs(60)).await;

        // Resolving A should follow CNAME and return B's A record
        let res = mock.resolve_a("a.example.com").await;
        assert!(res.is_ok());
        let ips = match res { AddrResult::Ok(v) => v, _ => panic!() };
        assert_eq!(ips, vec![ip]);
    }

    #[tokio::test]
    async fn mock_cname_chain_multiple_hops() {
        let mock = MockDnsResolver::new();
        // A → CNAME → B → CNAME → C → (A record)
        mock.set_cname("a.example.com", "b.example.com").await;
        mock.set_cname("b.example.com", "c.example.com").await;
        let ip = IpAddr::V4(Ipv4Addr::new(5,6,7,8));
        mock.set_a("c.example.com", vec![ip], Duration::from_secs(60)).await;

        let res = mock.resolve_a("a.example.com").await;
        assert!(res.is_ok());
        let ips = match res { AddrResult::Ok(v) => v, _ => panic!() };
        assert_eq!(ips, vec![ip]);
    }

    #[tokio::test]
    async fn mock_cname_loop_detected() {
        let mock = MockDnsResolver::new();
        // A → CNAME → B → CNAME → C → CNAME → A (loop)
        mock.set_cname("a.example.com", "b.example.com").await;
        mock.set_cname("b.example.com", "c.example.com").await;
        mock.set_cname("c.example.com", "a.example.com").await;

        let res = mock.resolve_a("a.example.com").await;
        assert!(res.is_err());
        let err = match res { AddrResult::Err(e) => e, _ => panic!() };
        assert!(err.is_permanent());
        assert!(matches!(err, DnsError::CnameLoop { .. }));
    }

    #[tokio::test]
    async fn mock_cname_max_depth_exceeded() {
        let mock = MockDnsResolver::new().with_max_cname_depth(3);
        // Chain of 4: A → B → C → D (no A record for D)
        mock.set_cname("a.example.com", "b.example.com").await;
        mock.set_cname("b.example.com", "c.example.com").await;
        mock.set_cname("c.example.com", "d.example.com").await;

        let res = mock.resolve_a("a.example.com").await;
        assert!(res.is_err());
        let err = match res { AddrResult::Err(e) => e, _ => panic!() };
        assert!(err.is_permanent());
        assert!(matches!(err, DnsError::CnameLoop { max_depth: 3, .. }));
    }

    #[tokio::test]
    async fn mock_cname_loop_is_permanent() {
        let mock = MockDnsResolver::new();
        mock.set_cname("loop.example.com", "loop.example.com").await; // self-loop

        let res = mock.resolve_mx("loop.example.com").await;
        assert!(res.is_err());
        let err = match res { MxResult::Err(e) => e, _ => panic!() };
        assert!(err.is_permanent());
    }
}
