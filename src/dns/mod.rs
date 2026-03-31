// src/dns/mod.rs
//
// Phase 3: DNS Resolution
//
// Features:
//   - MX record lookup with CNAME chaining
//   - A/AAAA fallback
//   - TTL-aware caching (positive + negative)
//   - Error classification (permanent vs temporary) for delivery decisions
//
// All tests use MockDnsResolver — zero network calls.

pub mod cache;
pub mod error;
pub mod resolver;

pub use cache::{CacheConfig, DnsCache};
pub use error::{DnsError, DnsFailureMode};
pub use resolver::{AddrResult, DnsResolver, MockDnsResolver, MxRecord, MxResult, RealResolver};
