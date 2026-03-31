// src/auth/dmarc.rs
//
// DMARC (Domain-based Message Authentication, Reporting, and Conformance)
// verification implementation.
//
// DMARC builds on SPF and DKIM to provide domain-level authentication and
// policy enforcement for email.
//
// RFC 7489 - Domain-based Message Authentication, Reporting, and Conformance

use std::fmt;

use crate::auth::spf::SpfResult;

/// DMARC policy extracted from a DNS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// No policy (monitor only)
    None,
    /// Quarantine suspicious messages
    Quarantine,
    /// Reject suspicious messages
    Reject,
}

impl DmarcPolicy {
    /// Returns true if this policy requires action (quarantine or reject).
    pub fn requires_action(&self) -> bool {
        matches!(self, DmarcPolicy::Quarantine | DmarcPolicy::Reject)
    }

    /// Get the recommended SMTP response code for this policy.
    pub fn smtp_response(&self) -> Option<(u16, &'static str)> {
        match self {
            DmarcPolicy::Reject => Some((550, "Message rejected per DMARC policy")),
            DmarcPolicy::Quarantine => None, // Accept but may flag/spam-folder
            DmarcPolicy::None => None,
        }
    }
}

impl fmt::Display for DmarcPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarcPolicy::None => write!(f, "none"),
            DmarcPolicy::Quarantine => write!(f, "quarantine"),
            DmarcPolicy::Reject => write!(f, "reject"),
        }
    }
}

impl Default for DmarcPolicy {
    fn default() -> Self {
        DmarcPolicy::None
    }
}

/// Alignment mode for DKIM and SPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    /// Relaxed alignment (subdomains allowed)
    Relaxed,
    /// Strict alignment (exact match required)
    Strict,
}

impl fmt::Display for AlignmentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlignmentMode::Relaxed => write!(f, "r"),
            AlignmentMode::Strict => write!(f, "s"),
        }
    }
}

impl Default for AlignmentMode {
    fn default() -> Self {
        AlignmentMode::Relaxed
    }
}

/// Result of a DMARC verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcResult {
    /// DMARC record not found
    None,
    /// Pass - at least one of DKIM or SPF passed with alignment
    Pass,
    /// Fail - neither DKIM nor SPF passed with alignment
    Fail,
    /// Temporary error (DNS failure, etc.)
    TempError,
    /// Permanent error (invalid DMARC record)
    PermError,
}

impl DmarcResult {
    /// Returns true if the result is a pass.
    pub fn is_pass(&self) -> bool {
        matches!(self, DmarcResult::Pass)
    }

    /// Returns true if the result is a fail.
    pub fn is_fail(&self) -> bool {
        matches!(self, DmarcResult::Fail)
    }

    /// Returns true if this is an error result.
    pub fn is_error(&self) -> bool {
        matches!(self, DmarcResult::TempError | DmarcResult::PermError)
    }
}

impl fmt::Display for DmarcResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarcResult::None => write!(f, "none"),
            DmarcResult::Pass => write!(f, "pass"),
            DmarcResult::Fail => write!(f, "fail"),
            DmarcResult::TempError => write!(f, "temperror"),
            DmarcResult::PermError => write!(f, "permerror"),
        }
    }
}

/// DMARC record data.
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    /// Requested policy (p=)
    pub policy: DmarcPolicy,
    /// Subdomain policy (sp=)
    pub subdomain_policy: Option<DmarcPolicy>,
    /// DKIM alignment mode (adkim=)
    pub dkim_alignment: AlignmentMode,
    /// SPF alignment mode (aspf=)
    pub spf_alignment: AlignmentMode,
    /// Percentage of messages to apply policy to (pct=)
    pub percentage: u8,
    /// Reporting URI for aggregate reports (rua=)
    pub report_uri_aggregate: Vec<String>,
    /// Reporting URI for forensic reports (ruf=)
    pub report_uri_forensic: Vec<String>,
    /// Failure reporting options (fo=)
    pub failure_options: Vec<char>,
}

impl Default for DmarcRecord {
    fn default() -> Self {
        Self {
            policy: DmarcPolicy::None,
            subdomain_policy: None,
            dkim_alignment: AlignmentMode::Relaxed,
            spf_alignment: AlignmentMode::Relaxed,
            percentage: 100,
            report_uri_aggregate: Vec::new(),
            report_uri_forensic: Vec::new(),
            failure_options: vec!['0'],
        }
    }
}

/// DMARC verifier for checking message authentication.
pub struct DmarcVerifier;

impl DmarcVerifier {
    /// Create a new DMARC verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify DMARC for a message.
    ///
    /// # Arguments
    /// * `from_domain` - The domain from the From: header
    /// * `dkim_result` - Result of DKIM verification (if any)
    /// * `dkim_domain` - The signing domain from DKIM (if verified)
    /// * `spf_result` - Result of SPF verification
    /// * `spf_domain` - The domain that passed SPF (if any)
    ///
    /// Returns the DMARC result.
    pub async fn verify(
        &self,
        from_domain: &str,
        dkim_result: Option<crate::auth::dkim::DkimResult>,
        dkim_domain: Option<&str>,
        spf_result: SpfResult,
        spf_domain: Option<&str>,
    ) -> DmarcResult {
        // For now, return a placeholder implementation
        // In a full implementation, this would:
        // 1. Query DNS for DMARC record on _dmarc.<from_domain>
        // 2. Parse the DMARC record
        // 3. Check DKIM alignment (if DKIM passed)
        // 4. Check SPF alignment (if SPF passed)
        // 5. Return pass if either aligned authentication passed
        
        tracing::debug!(
            "DMARC check: from_domain={}, dkim_domain={:?}, spf_domain={:?}",
            from_domain,
            dkim_domain,
            spf_domain
        );
        
        // Placeholder: return pass (assume authenticated)
        DmarcResult::Pass
    }

    /// Parse a DMARC record string.
    pub fn parse_record(&self, record: &str) -> Result<DmarcRecord, DmarcError> {
        let mut dmarc = DmarcRecord::default();
        
        // Check for DMARC version
        if !record.starts_with("v=DMARC1") {
            return Err(DmarcError::InvalidVersion);
        }

        // Parse key-value pairs
        for tag in record.split(';') {
            let tag = tag.trim();
            if tag.is_empty() || tag.starts_with("v=DMARC1") {
                continue;
            }

            if let Some(pos) = tag.find('=') {
                let key = &tag[..pos].trim();
                let value = &tag[pos + 1..].trim();

                match *key {
                    "p" => dmarc.policy = parse_policy(value)?,
                    "sp" => dmarc.subdomain_policy = Some(parse_policy(value)?),
                    "adkim" => dmarc.dkim_alignment = parse_alignment(value)?,
                    "aspf" => dmarc.spf_alignment = parse_alignment(value)?,
                    "pct" => dmarc.percentage = value.parse().unwrap_or(100),
                    "rua" => dmarc.report_uri_aggregate = parse_uri_list(value),
                    "ruf" => dmarc.report_uri_forensic = parse_uri_list(value),
                    "fo" => dmarc.failure_options = value.chars().collect(),
                    _ => {} // Unknown tag, ignore per RFC
                }
            }
        }

        Ok(dmarc)
    }

    /// Check if DKIM result aligns with the From domain.
    pub fn check_dkim_alignment(
        &self,
        from_domain: &str,
        dkim_domain: &str,
        mode: AlignmentMode,
    ) -> bool {
        match mode {
            AlignmentMode::Strict => from_domain.eq_ignore_ascii_case(dkim_domain),
            AlignmentMode::Relaxed => {
                // Relaxed: dkim_domain must match from_domain or be a subdomain
                let from_lower = from_domain.to_lowercase();
                let dkim_lower = dkim_domain.to_lowercase();
                
                from_lower == dkim_lower || 
                    dkim_lower.ends_with(&format!(".{}", from_lower))
            }
        }
    }

    /// Check if SPF result aligns with the From domain.
    pub fn check_spf_alignment(
        &self,
        from_domain: &str,
        spf_domain: &str,
        mode: AlignmentMode,
    ) -> bool {
        // Same logic as DKIM alignment
        self.check_dkim_alignment(from_domain, spf_domain, mode)
    }

    /// Evaluate DMARC result from individual authentication results.
    pub fn evaluate(
        &self,
        record: &DmarcRecord,
        dkim_aligned: bool,
        spf_aligned: bool,
    ) -> DmarcResult {
        // DMARC passes if at least one of DKIM or SPF passes with alignment
        if dkim_aligned || spf_aligned {
            DmarcResult::Pass
        } else {
            DmarcResult::Fail
        }
    }

    /// Get the effective policy for a domain.
    pub fn effective_policy(&self, record: &DmarcRecord, is_subdomain: bool) -> DmarcPolicy {
        if is_subdomain && record.subdomain_policy.is_some() {
            record.subdomain_policy.unwrap()
        } else {
            record.policy
        }
    }

    /// Get the DNS record name for DMARC lookup.
    pub fn dns_record_name(&self, domain: &str) -> String {
        format!("_dmarc.{}", domain)
    }
}

impl Default for DmarcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a policy value.
fn parse_policy(s: &str) -> Result<DmarcPolicy, DmarcError> {
    match s.to_lowercase().as_str() {
        "none" => Ok(DmarcPolicy::None),
        "quarantine" => Ok(DmarcPolicy::Quarantine),
        "reject" => Ok(DmarcPolicy::Reject),
        _ => Err(DmarcError::InvalidPolicy(s.to_string())),
    }
}

/// Parse an alignment mode value.
fn parse_alignment(s: &str) -> Result<AlignmentMode, DmarcError> {
    match s.to_lowercase().as_str() {
        "r" | "relaxed" => Ok(AlignmentMode::Relaxed),
        "s" | "strict" => Ok(AlignmentMode::Strict),
        _ => Err(DmarcError::InvalidAlignment(s.to_string())),
    }
}

/// Parse a comma-separated URI list.
fn parse_uri_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|uri| uri.trim().to_string())
        .filter(|uri| !uri.is_empty())
        .collect()
}

/// Errors that can occur during DMARC operations.
#[derive(Debug, Clone)]
pub enum DmarcError {
    /// Invalid DMARC version
    InvalidVersion,
    /// Invalid policy value
    InvalidPolicy(String),
    /// Invalid alignment mode
    InvalidAlignment(String),
}

impl fmt::Display for DmarcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarcError::InvalidVersion => write!(f, "Invalid DMARC version"),
            DmarcError::InvalidPolicy(p) => write!(f, "Invalid DMARC policy: {}", p),
            DmarcError::InvalidAlignment(a) => write!(f, "Invalid alignment mode: {}", a),
        }
    }
}

impl std::error::Error for DmarcError {}

/// Placeholder DKIM result type for DMARC integration.
/// In a full implementation, this would come from the dkim module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimResult {
    /// DKIM signature not present
    None,
    /// Valid DKIM signature
    Pass,
    /// Invalid DKIM signature
    Fail,
    /// Temporary error
    TempError,
    /// Permanent error
    PermError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmarc_policy_display() {
        assert_eq!(DmarcPolicy::None.to_string(), "none");
        assert_eq!(DmarcPolicy::Quarantine.to_string(), "quarantine");
        assert_eq!(DmarcPolicy::Reject.to_string(), "reject");
    }

    #[test]
    fn test_parse_record() {
        let verifier = DmarcVerifier::new();
        
        // Valid record
        let record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100";
        let dmarc = verifier.parse_record(record).unwrap();
        assert!(matches!(dmarc.policy, DmarcPolicy::Reject));
        assert_eq!(dmarc.percentage, 100);
        assert_eq!(dmarc.report_uri_aggregate, vec!["mailto:dmarc@example.com"]);
        
        // Invalid version
        let record = "v=DMARC2; p=reject";
        assert!(verifier.parse_record(record).is_err());
    }

    #[test]
    fn test_dkim_alignment() {
        let verifier = DmarcVerifier::new();
        
        // Strict alignment
        assert!(verifier.check_dkim_alignment(
            "example.com",
            "example.com",
            AlignmentMode::Strict
        ));
        assert!(!verifier.check_dkim_alignment(
            "example.com",
            "sub.example.com",
            AlignmentMode::Strict
        ));
        
        // Relaxed alignment
        assert!(verifier.check_dkim_alignment(
            "example.com",
            "example.com",
            AlignmentMode::Relaxed
        ));
        assert!(verifier.check_dkim_alignment(
            "example.com",
            "sub.example.com",
            AlignmentMode::Relaxed
        ));
        assert!(!verifier.check_dkim_alignment(
            "example.com",
            "other.com",
            AlignmentMode::Relaxed
        ));
    }

    #[test]
    fn test_evaluate() {
        let verifier = DmarcVerifier::new();
        let record = DmarcRecord::default();
        
        // Pass if either aligns
        assert!(matches!(
            verifier.evaluate(&record, true, false),
            DmarcResult::Pass
        ));
        assert!(matches!(
            verifier.evaluate(&record, false, true),
            DmarcResult::Pass
        ));
        assert!(matches!(
            verifier.evaluate(&record, true, true),
            DmarcResult::Pass
        ));
        
        // Fail if neither aligns
        assert!(matches!(
            verifier.evaluate(&record, false, false),
            DmarcResult::Fail
        ));
    }

    #[test]
    fn test_effective_policy() {
        let verifier = DmarcVerifier::new();
        let mut record = DmarcRecord::default();
        record.policy = DmarcPolicy::Reject;
        record.subdomain_policy = Some(DmarcPolicy::Quarantine);
        
        assert!(matches!(
            verifier.effective_policy(&record, false),
            DmarcPolicy::Reject
        ));
        assert!(matches!(
            verifier.effective_policy(&record, true),
            DmarcPolicy::Quarantine
        ));
    }

    #[test]
    fn test_dmarc_result_helpers() {
        assert!(DmarcResult::Pass.is_pass());
        assert!(!DmarcResult::Fail.is_pass());
        
        assert!(DmarcResult::Fail.is_fail());
        assert!(!DmarcResult::Pass.is_fail());
        
        assert!(DmarcResult::TempError.is_error());
        assert!(DmarcResult::PermError.is_error());
        assert!(!DmarcResult::Pass.is_error());
    }
}
