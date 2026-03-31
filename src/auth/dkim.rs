// src/auth/dkim.rs
//
// DKIM (DomainKeys Identified Mail) signing implementation.
//
// DKIM provides cryptographic authentication of email messages, allowing
// the sender to sign messages and receivers to verify the signature.
//
// RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// DKIM signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimAlgorithm {
    /// RSA-SHA256 (most common)
    RsaSha256,
    /// Ed25519-SHA256 (newer, faster)
    Ed25519Sha256,
}

impl fmt::Display for DkimAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DkimAlgorithm::RsaSha256 => write!(f, "rsa-sha256"),
            DkimAlgorithm::Ed25519Sha256 => write!(f, "ed25519-sha256"),
        }
    }
}

impl Default for DkimAlgorithm {
    fn default() -> Self {
        DkimAlgorithm::RsaSha256
    }
}

/// Canonicalization algorithm for headers and body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    /// Simple - minimal processing (strict)
    Simple,
    /// Relaxed - whitespace normalization (recommended)
    Relaxed,
}

impl fmt::Display for Canonicalization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Canonicalization::Simple => write!(f, "simple"),
            Canonicalization::Relaxed => write!(f, "relaxed"),
        }
    }
}

impl Default for Canonicalization {
    fn default() -> Self {
        Canonicalization::Relaxed
    }
}

/// Format of the private key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// PEM encoded private key
    Pem,
    /// DER encoded private key
    Der,
}

impl Default for KeyFormat {
    fn default() -> Self {
        KeyFormat::Pem
    }
}

/// A DKIM signing key.
pub enum DkimSigningKey {
    /// RSA private key
    Rsa(RsaPrivateKey),
    // Ed25519 keys can be added when needed
}

/// Configuration for DKIM signing.
#[derive(Debug, Clone)]
pub struct DkimConfig {
    /// Selector for the DKIM key (e.g., "default", "2024")
    pub selector: String,
    /// Domain being signed (e.g., "example.com")
    pub domain: String,
    /// Path to the private key file
    pub private_key_path: PathBuf,
    /// Format of the private key
    pub key_format: KeyFormat,
    /// Signing algorithm
    pub algorithm: DkimAlgorithm,
    /// Header canonicalization
    pub header_canon: Canonicalization,
    /// Body canonicalization
    pub body_canon: Canonicalization,
    /// Headers to include in signature (in order)
    pub signed_headers: Vec<String>,
}

impl DkimConfig {
    /// Create a new DKIM config with required fields.
    pub fn new(
        selector: impl Into<String>,
        domain: impl Into<String>,
        private_key_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            selector: selector.into(),
            domain: domain.into(),
            private_key_path: private_key_path.as_ref().to_path_buf(),
            key_format: KeyFormat::default(),
            algorithm: DkimAlgorithm::default(),
            header_canon: Canonicalization::default(),
            body_canon: Canonicalization::default(),
            signed_headers: default_signed_headers(),
        }
    }

    /// Set the key format.
    pub fn with_key_format(mut self, format: KeyFormat) -> Self {
        self.key_format = format;
        self
    }

    /// Set the algorithm.
    pub fn with_algorithm(mut self, algorithm: DkimAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set canonicalization.
    pub fn with_canonicalization(
        mut self,
        header: Canonicalization,
        body: Canonicalization,
    ) -> Self {
        self.header_canon = header;
        self.body_canon = body;
        self
    }

    /// Set signed headers.
    pub fn with_signed_headers(mut self, headers: Vec<String>) -> Self {
        self.signed_headers = headers;
        self
    }
}

/// Default headers to sign (recommended set per RFC 6376).
fn default_signed_headers() -> Vec<String> {
    vec![
        "from",
        "to",
        "subject",
        "date",
        "message-id",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

/// DKIM signer for signing outbound messages.
pub struct DkimSigner {
    config: DkimConfig,
    signing_key: DkimSigningKey,
}

/// A DKIM signature header value.
#[derive(Debug, Clone)]
pub struct DkimSignature {
    /// DKIM version
    pub v: String,
    /// Signature algorithm
    pub a: String,
    /// Canonicalization for header and body
    pub c: String,
    /// SDID (signing domain)
    pub d: String,
    /// Selector
    pub s: String,
    /// Timestamp
    pub t: Option<u64>,
    /// Expiration
    pub x: Option<u64>,
    /// Headers included in signature
    pub h: String,
    /// Body hash
    pub bh: String,
    /// Signature data
    pub b: String,
    /// Length of body signed (optional)
    pub l: Option<usize>,
    /// Query methods
    pub q: String,
}

impl DkimSigner {
    /// Create a new DKIM signer from configuration.
    pub fn from_config(config: DkimConfig) -> Result<Self, DkimError> {
        let signing_key = Self::load_key(&config)?;
        Ok(Self {
            config,
            signing_key,
        })
    }

    /// Load the private key from file.
    fn load_key(config: &DkimConfig) -> Result<DkimSigningKey, DkimError> {
        let key_data = fs::read(&config.private_key_path).map_err(|e| {
            DkimError::KeyLoadError(format!(
                "Failed to read key file {}: {}",
                config.private_key_path.display(),
                e
            ))
        })?;

        match config.algorithm {
            DkimAlgorithm::RsaSha256 => {
                let private_key = match config.key_format {
                    KeyFormat::Pem => {
                        let pem_str = String::from_utf8(key_data).map_err(|e| {
                            DkimError::KeyLoadError(format!("Invalid PEM encoding: {}", e))
                        })?;
                        RsaPrivateKey::from_pkcs8_pem(&pem_str).map_err(|e| {
                            DkimError::KeyLoadError(format!("Invalid RSA key: {}", e))
                        })?
                    }
                    KeyFormat::Der => RsaPrivateKey::from_pkcs8_der(&key_data).map_err(|e| {
                        DkimError::KeyLoadError(format!("Invalid RSA key: {}", e))
                    })?,
                };
                Ok(DkimSigningKey::Rsa(private_key))
            }
            DkimAlgorithm::Ed25519Sha256 => {
                // Ed25519 support can be added with ed25519-dalek crate
                Err(DkimError::UnsupportedAlgorithm(
                    "Ed25519 not yet implemented".to_string(),
                ))
            }
        }
    }

    /// Sign a message and return the DKIM-Signature header value.
    pub fn sign(&self, headers: &[(String, String)], body: &[u8]) -> Result<String, DkimError> {
        // 1. Canonicalize body and compute hash
        let canonical_body = canonicalize_body(body, self.config.body_canon);
        let body_hash = compute_body_hash(&canonical_body);

        // 2. Build DKIM header without signature
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();

        let mut dkim_header = format!(
            "v=1; a={}; c={}/{}; d={}; s={}; t={}; h={}; bh={}; q=dns/txt; b=",
            self.config.algorithm,
            self.config.header_canon,
            self.config.body_canon,
            self.config.domain,
            self.config.selector,
            timestamp.unwrap_or(0),
            self.config.signed_headers.join(":"),
            BASE64.encode(&body_hash),
        );

        // 3. Build header hash input
        let header_hash_input =
            build_header_hash_input(headers, &self.config.signed_headers, self.config.header_canon, &dkim_header);

        // 4. Sign the header hash
        let signature = self.sign_data(&header_hash_input)?;

        // 5. Add signature to header
        // Fold the signature into multiple lines (max 76 chars per line per RFC)
        let folded_sig = fold_signature(&BASE64.encode(&signature));
        dkim_header.push_str(&folded_sig);

        Ok(dkim_header)
    }

    /// Sign data using the configured key.
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, DkimError> {
        match &self.signing_key {
            DkimSigningKey::Rsa(private_key) => {
                use rsa::signature::{SignatureEncoding, Signer};
                let signing_key = RsaSigningKey::<Sha256>::new(private_key.clone());
                let signature = signing_key.try_sign(data).map_err(|e| {
                    DkimError::SigningError(format!("RSA signing failed: {}", e))
                })?;
                Ok(signature.to_vec())
            }
        }
    }

    /// Get the DNS record name for this DKIM key.
    pub fn dns_record_name(&self) -> String {
        format!("{}._domainkey.{}.", self.config.selector, self.config.domain)
    }

    /// Generate the public key DNS TXT record content.
    pub fn generate_dns_record(&self) -> Result<String, DkimError> {
        let public_key = match &self.signing_key {
            DkimSigningKey::Rsa(private_key) => {
                use rsa::pkcs8::EncodePublicKey;
                let public_key = private_key.to_public_key();
                let der = public_key.to_public_key_der().map_err(|e| {
                    DkimError::KeyError(format!("Failed to encode public key: {}", e))
                })?;
                BASE64.encode(der.as_bytes())
            }
        };

        Ok(format!(
            "v=DKIM1; k={}; p={}",
            match self.config.algorithm {
                DkimAlgorithm::RsaSha256 => "rsa",
                DkimAlgorithm::Ed25519Sha256 => "ed25519",
            },
            public_key
        ))
    }
}

/// Canonicalize body according to the specified algorithm.
fn canonicalize_body(body: &[u8], canon: Canonicalization) -> Vec<u8> {
    match canon {
        Canonicalization::Simple => {
            // Simple: keep body as-is, but ensure it ends with CRLF
            // Empty body becomes CRLF
            if body.is_empty() {
                return b"\r\n".to_vec();
            }
            let mut result = body.to_vec();
            if !result.ends_with(b"\r\n") {
                result.extend_from_slice(b"\r\n");
            }
            result
        }
        Canonicalization::Relaxed => {
            // Relaxed: 
            // - Remove trailing empty lines
            // - Ensure CRLF line endings
            // - Remove trailing whitespace from lines
            if body.is_empty() {
                return b"\r\n".to_vec();
            }

            let text = String::from_utf8_lossy(body);
            let mut lines: Vec<&str> = text.lines().collect();
            
            // Remove trailing empty lines
            while let Some(last) = lines.last() {
                if last.trim().is_empty() {
                    lines.pop();
                } else {
                    break;
                }
            }

            if lines.is_empty() {
                return b"\r\n".to_vec();
            }

            let mut result = Vec::new();
            for line in lines {
                // Remove trailing whitespace, add CRLF
                let trimmed = line.trim_end();
                result.extend_from_slice(trimmed.as_bytes());
                result.extend_from_slice(b"\r\n");
            }
            result
        }
    }
}

/// Compute SHA-256 hash of the canonicalized body.
fn compute_body_hash(body: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().to_vec()
}

/// Build the header hash input.
fn build_header_hash_input(
    headers: &[(String, String)],
    signed_headers: &[String],
    canon: Canonicalization,
    dkim_header: &str,
) -> Vec<u8> {
    let mut result = Vec::new();

    // Create a map of lowercase header name to list of values (preserving order)
    let mut header_map: HashMap<String, Vec<&str>> = HashMap::new();
    for (name, value) in headers {
        header_map
            .entry(name.to_lowercase())
            .or_default()
            .push(value);
    }

    // Process headers in the order specified
    for header_name in signed_headers {
        let header_lower = header_name.to_lowercase();
        
        if header_lower == "dkim-signature" {
            // Add the DKIM-Signature header we're building (without b= value)
            let canon_header = canonicalize_header("dkim-signature", dkim_header, canon);
            result.extend_from_slice(canon_header.as_bytes());
            result.extend_from_slice(b"\r\n");
        } else if let Some(values) = header_map.get(&header_lower) {
            // Take the last occurrence of the header (most recent)
            if let Some(value) = values.last() {
                let canon_header = canonicalize_header(&header_lower, value, canon);
                result.extend_from_slice(canon_header.as_bytes());
                result.extend_from_slice(b"\r\n");
            }
        }
    }

    result
}

/// Canonicalize a single header.
fn canonicalize_header(name: &str, value: &str, canon: Canonicalization) -> String {
    match canon {
        Canonicalization::Simple => {
            format!("{}:{}", name, value)
        }
        Canonicalization::Relaxed => {
            // Header name: lowercase, no change
            // Header value: unfold (replace CRLF/CF/LF with single space),
            //              trim leading/trailing spaces, 
            //              compress internal whitespace to single space
            let name = name.to_lowercase();
            let value = value.replace("\r\n", "");
            let value = value.replace('\n', "");
            let value = value.replace('\r', "");
            let value: Vec<&str> = value.split_whitespace().collect();
            let value = value.join(" ");
            format!("{}:{}", name, value)
        }
    }
}

/// Fold a base64 signature into multiple lines (max 76 chars).
fn fold_signature(sig: &str) -> String {
    const MAX_LINE_LEN: usize = 76;
    
    if sig.len() <= MAX_LINE_LEN {
        return sig.to_string();
    }

    let mut result = String::new();
    let mut pos = 0;
    
    while pos < sig.len() {
        let end = (pos + MAX_LINE_LEN).min(sig.len());
        result.push_str(&sig[pos..end]);
        if end < sig.len() {
            result.push_str("\r\n ");  // Continue on next line with leading space
        }
        pos = end;
    }
    
    result
}

/// Result of a DKIM verification check.
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

impl DkimResult {
    /// Returns true if the result is a pass.
    pub fn is_pass(&self) -> bool {
        matches!(self, DkimResult::Pass)
    }
}

/// Errors that can occur during DKIM operations.
#[derive(Debug, Clone)]
pub enum DkimError {
    /// Failed to load the private key
    KeyLoadError(String),
    /// Invalid key format
    KeyError(String),
    /// Signing operation failed
    SigningError(String),
    /// Unsupported algorithm
    UnsupportedAlgorithm(String),
}

impl fmt::Display for DkimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DkimError::KeyLoadError(msg) => write!(f, "Key load error: {}", msg),
            DkimError::KeyError(msg) => write!(f, "Key error: {}", msg),
            DkimError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            DkimError::UnsupportedAlgorithm(msg) => write!(f, "Unsupported algorithm: {}", msg),
        }
    }
}

impl std::error::Error for DkimError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_body_simple() {
        // Empty body becomes CRLF
        assert_eq!(canonicalize_body(b"", Canonicalization::Simple), b"\r\n");
        
        // Body without trailing CRLF gets it added
        assert_eq!(
            canonicalize_body(b"Hello", Canonicalization::Simple),
            b"Hello\r\n"
        );
        
        // Body with CRLF stays the same
        assert_eq!(
            canonicalize_body(b"Hello\r\n", Canonicalization::Simple),
            b"Hello\r\n"
        );
    }

    #[test]
    fn test_canonicalize_body_relaxed() {
        // Empty body becomes CRLF
        assert_eq!(canonicalize_body(b"", Canonicalization::Relaxed), b"\r\n");
        
        // Trailing empty lines removed
        assert_eq!(
            canonicalize_body(b"Hello\r\n\r\n", Canonicalization::Relaxed),
            b"Hello\r\n"
        );
        
        // Trailing whitespace removed
        assert_eq!(
            canonicalize_body(b"Hello   \r\n", Canonicalization::Relaxed),
            b"Hello\r\n"
        );
    }

    #[test]
    fn test_canonicalize_header_relaxed() {
        assert_eq!(
            canonicalize_header("From", "  user@example.com  ", Canonicalization::Relaxed),
            "from:user@example.com"
        );
        
        assert_eq!(
            canonicalize_header("Subject", "Hello   World", Canonicalization::Relaxed),
            "subject:Hello World"
        );
    }

    #[test]
    fn test_body_hash() {
        let body = b"Hello World\r\n";
        let hash = compute_body_hash(body);
        assert_eq!(hash.len(), 32); // SHA-256 is 32 bytes
    }

    #[test]
    fn test_default_signed_headers() {
        let headers = default_signed_headers();
        assert!(headers.contains(&"from".to_string()));
        assert!(headers.contains(&"to".to_string()));
        assert!(headers.contains(&"subject".to_string()));
    }
}
