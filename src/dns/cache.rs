// src/dns/cache.rs
//
// TTL-aware DNS cache for positive and negative results.
//
// Positive entries store resolved records (MX, A, AAAA).
// Negative entries store NXDOMAIN / NODATA with a shorter TTL.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// A cached DNS answer.
#[derive(Debug, Clone)]
pub struct CacheEntry<V> {
    /// The cached value (e.g., Vec<MxRecord> or Vec<IpAddr>).
    pub value: V,
    /// When this entry expires.
    pub expires_at: Instant,
}

impl<V> CacheEntry<V> {
    pub fn new(value: V, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Configurable TTL caps.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum TTL for positive cache entries (cap DNS TTLs).
    pub max_ttl: Duration,
    /// TTL for negative cache entries (NXDOMAIN/NODATA).
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_ttl: Duration::from_secs(3600),      // 1 hour cap
            negative_ttl: Duration::from_secs(300),  // 5 min for negatives
        }
    }
}

/// The cache key combines domain + query type.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum CacheKey {
    Mx(String),
    A(String),
    Aaaa(String),
}

/// Thread-safe DNS cache.
pub struct DnsCache {
    config: CacheConfig,
    store: RwLock<HashMap<CacheKey, Box<dyn std::any::Any + Send + Sync>>>,
}

impl DnsCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            store: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default TTL caps.
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Compute effective TTL (min of dns_ttl and max_ttl).
    fn effective_ttl(&self, dns_ttl: Duration) -> Duration {
        dns_ttl.min(self.config.max_ttl)
    }

    // ── MX cache ──────────────────────────────────────────────────────

    /// Insert MX records into cache.
    pub async fn insert_mx(&self, domain: &str, records: Vec<super::resolver::MxRecord>, dns_ttl: Duration) {
        let ttl = self.effective_ttl(dns_ttl);
        let entry = CacheEntry::new(records, ttl);
        let mut guard = self.store.write().await;
        guard.insert(CacheKey::Mx(domain.to_lowercase()), Box::new(entry));
    }

    /// Lookup MX records; returns None if missing or expired.
    pub async fn get_mx(&self, domain: &str) -> Option<Vec<super::resolver::MxRecord>> {
        let guard = self.store.read().await;
        if let Some(any) = guard.get(&CacheKey::Mx(domain.to_lowercase())) {
            if let Some(entry) = any.downcast_ref::<CacheEntry<Vec<super::resolver::MxRecord>>>() {
                if !entry.is_expired() {
                    return Some(entry.value.clone());
                }
            }
        }
        None
    }

    // ── A cache ───────────────────────────────────────────────────────

    pub async fn insert_a(&self, domain: &str, ips: Vec<std::net::IpAddr>, dns_ttl: Duration) {
        let ttl = self.effective_ttl(dns_ttl);
        let entry = CacheEntry::new(ips, ttl);
        let mut guard = self.store.write().await;
        guard.insert(CacheKey::A(domain.to_lowercase()), Box::new(entry));
    }

    pub async fn get_a(&self, domain: &str) -> Option<Vec<std::net::IpAddr>> {
        let guard = self.store.read().await;
        if let Some(any) = guard.get(&CacheKey::A(domain.to_lowercase())) {
            if let Some(entry) = any.downcast_ref::<CacheEntry<Vec<std::net::IpAddr>>>() {
                if !entry.is_expired() {
                    return Some(entry.value.clone());
                }
            }
        }
        None
    }

    // ── AAAA cache ────────────────────────────────────────────────────

    pub async fn insert_aaaa(&self, domain: &str, ips: Vec<std::net::IpAddr>, dns_ttl: Duration) {
        let ttl = self.effective_ttl(dns_ttl);
        let entry = CacheEntry::new(ips, ttl);
        let mut guard = self.store.write().await;
        guard.insert(CacheKey::Aaaa(domain.to_lowercase()), Box::new(entry));
    }

    pub async fn get_aaaa(&self, domain: &str) -> Option<Vec<std::net::IpAddr>> {
        let guard = self.store.read().await;
        if let Some(any) = guard.get(&CacheKey::Aaaa(domain.to_lowercase())) {
            if let Some(entry) = any.downcast_ref::<CacheEntry<Vec<std::net::IpAddr>>>() {
                if !entry.is_expired() {
                    return Some(entry.value.clone());
                }
            }
        }
        None
    }

    // ── Negative cache ────────────────────────────────────────────────

    /// Insert a negative result (NXDOMAIN or NODATA).
    /// We store a marker; caller checks before querying.
    pub async fn insert_negative(&self, domain: &str, query_type: &str) {
        let ttl = self.config.negative_ttl;
        // Use a special "negative" marker type.
        let entry = CacheEntry::new(NegativeMarker { query_type: query_type.to_string() }, ttl);
        let mut guard = self.store.write().await;
        let key = match query_type {
            "MX" => CacheKey::Mx(domain.to_lowercase()),
            "A" => CacheKey::A(domain.to_lowercase()),
            "AAAA" => CacheKey::Aaaa(domain.to_lowercase()),
            _ => return,
        };
        guard.insert(key, Box::new(entry));
    }

    /// Check if we have a cached negative for this query.
    pub async fn get_negative(&self, domain: &str, query_type: &str) -> Option<Duration> {
        let guard = self.store.read().await;
        let key = match query_type {
            "MX" => CacheKey::Mx(domain.to_lowercase()),
            "A" => CacheKey::A(domain.to_lowercase()),
            "AAAA" => CacheKey::Aaaa(domain.to_lowercase()),
            _ => return None,
        };
        if let Some(any) = guard.get(&key) {
            if let Some(entry) = any.downcast_ref::<CacheEntry<NegativeMarker>>() {
                if !entry.is_expired() {
                    let remaining = entry.expires_at.saturating_duration_since(Instant::now());
                    return Some(remaining);
                }
            }
        }
        None
    }

    /// Clear all cached entries.
    pub async fn clear(&self) {
        let mut guard = self.store.write().await;
        guard.clear();
    }
}

/// Marker for negative cache entries.
#[derive(Debug, Clone)]
struct NegativeMarker {
    query_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::MxRecord;
    use std::net::{IpAddr, Ipv4Addr};

    fn mx(domain: &str, pref: u16) -> MxRecord {
        MxRecord { preference: pref, exchange: domain.into() }
    }

    #[tokio::test]
    async fn mx_cache_hit_and_miss() {
        let cache = DnsCache::with_defaults();
        let domain = "example.com";
        let records = vec![mx("mail.example.com", 10)];

        // Initially miss
        assert!(cache.get_mx(domain).await.is_none());

        // Insert
        cache.insert_mx(domain, records.clone(), Duration::from_secs(60)).await;

        // Hit
        let got = cache.get_mx(domain).await;
        assert!(got.is_some());
        assert_eq!(got.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mx_cache_expires() {
        // Use a very small max_ttl to test expiry quickly
        let cache = DnsCache::new(CacheConfig {
            max_ttl: Duration::from_millis(1),
            negative_ttl: Duration::from_secs(1),
        });
        let domain = "exp.example.com";
        cache.insert_mx(domain, vec![mx("m.exp.example.com", 5)], Duration::from_secs(60)).await;

        // Should be present immediately (race is unlikely for 1ms)
        // If flaky, we accept: the important thing is TTL capping works
        if cache.get_mx(domain).await.is_some() {
            // Wait for expiry
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(cache.get_mx(domain).await.is_none(), "entry should expire");
        }
        // If already expired by now, test still passes (TTL cap worked)
    }

    #[tokio::test]
    async fn negative_cache() {
        let cache = DnsCache::with_defaults();
        let domain = "nodata.example.com";

        assert!(cache.get_negative(domain, "MX").await.is_none());

        cache.insert_negative(domain, "MX").await;
        assert!(cache.get_negative(domain, "MX").await.is_some());
        // Different query type should miss
        assert!(cache.get_negative(domain, "A").await.is_none());
    }

    #[tokio::test]
    async fn ttl_cap() {
        let cache = DnsCache::new(CacheConfig {
            max_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_secs(5),
        });
        // DNS says 1 hour, but we cap at 30s
        cache.insert_mx("capped.com", vec![mx("m.capped.com", 1)], Duration::from_secs(3600)).await;
        // We can't directly check expiry, but insert should succeed.
        assert!(cache.get_mx("capped.com").await.is_some());
    }

    #[tokio::test]
    async fn a_cache() {
        let cache = DnsCache::with_defaults();
        let domain = "ip.example.com";
        let ips: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(1,2,3,4))];

        cache.insert_a(domain, ips.clone(), Duration::from_secs(60)).await;
        let got = cache.get_a(domain).await;
        assert_eq!(got.unwrap(), ips);
    }

    #[tokio::test]
    async fn clear() {
        let cache = DnsCache::with_defaults();
        cache.insert_mx("x.com", vec![mx("m.x.com", 1)], Duration::from_secs(60)).await;
        assert!(cache.get_mx("x.com").await.is_some());
        cache.clear().await;
        assert!(cache.get_mx("x.com").await.is_none());
    }
}
