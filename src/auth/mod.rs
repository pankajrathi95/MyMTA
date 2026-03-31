// src/auth/mod.rs
//
// Authentication module for Phase 5: DKIM, SPF, and DMARC.
//
// This module provides:
// - DKIM signing for outbound messages
// - SPF verification for inbound connections
// - DMARC verification combining DKIM and SPF results

pub mod dkim;
pub mod dmarc;
pub mod spf;

pub use dkim::{DkimConfig, DkimSigner, DkimSigningKey};
pub use dmarc::{DmarcPolicy, DmarcResult, DmarcVerifier};
pub use spf::{SpfPolicy, SpfResult, SpfVerifier};
