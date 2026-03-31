// src/config.rs
//
// Runtime configuration for the MTA.
//
// Resolution order (each layer overrides the previous):
//   1. Compiled-in defaults
//   2. TOML config file  (--config path)
//   3. Environment variables  (MTA_*)
//
// This gives operators a config file for the baseline, with env-var overrides
// for container / CI / one-off tweaks.

use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

// ── public Config (runtime) ─────────────────────────────────────────

/// Fully resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on (e.g. 0.0.0.0:2525).
    pub listen_addr: SocketAddr,
    /// Hostname announced in the 220 greeting and EHLO response.
    pub hostname: String,
    /// Maximum message size in bytes (announced via SIZE extension).
    pub max_message_size: usize,
    /// Maximum number of RCPT TO recipients per message.
    pub max_recipients: usize,
    /// Directory where spooled messages are stored.
    pub spool_dir: PathBuf,
    /// Log level filter string (e.g. "info", "debug", "mymta=trace").
    pub log_level: String,
    /// Address for the HTTP injection API (e.g. 0.0.0.0:8025).
    pub http_listen_addr: SocketAddr,
    // ── Phase 2: Queue settings ────────────────────────────────────
    /// Default max concurrent deliveries per destination domain.
    pub queue_concurrency: u32,
    /// Initial retry delay in seconds.
    pub queue_retry_initial_delay_secs: u64,
    /// Backoff multiplier after each failed attempt.
    pub queue_retry_backoff_multiplier: f64,
    /// Maximum retry delay cap in seconds.
    pub queue_retry_max_delay_secs: u64,
    /// Maximum delivery attempts before giving up.
    pub queue_retry_max_attempts: u32,
    // ── Phase 3: DNS settings ──────────────────────────────────────
    /// Per-query DNS timeout in seconds.
    pub dns_timeout_secs: u64,
    /// Max TTL for cached positive DNS entries (caps DNS TTLs).
    pub dns_cache_max_ttl_secs: u64,
    /// TTL for negative cache entries (NXDOMAIN/NODATA).
    pub dns_cache_neg_ttl_secs: u64,
    /// Max CNAME chain depth before error.
    pub dns_max_cname_depth: usize,
    // ── Phase 5: Authentication settings ───────────────────────────
    /// Directory where DKIM private keys are stored (legacy/simple config).
    pub dkim_key_dir: Option<PathBuf>,
    /// Default DKIM selector to use for signing (legacy/simple config).
    pub dkim_default_selector: Option<String>,
    /// Per-selector DKIM configurations. Key is "selector" or "domain/selector".
    pub dkim_selectors: HashMap<String, DkimSelectorConfig>,
    /// Enable SPF verification for inbound mail.
    pub spf_verify_enabled: bool,
    /// Enable DMARC verification for inbound mail.
    pub dmarc_verify_enabled: bool,
    /// Reject messages that fail SPF hard fail.
    pub spf_reject_fail: bool,
    /// Reject messages that fail DMARC policy.
    pub dmarc_reject_fail: bool,
}

/// Configuration for a specific DKIM selector.
#[derive(Debug, Clone)]
pub struct DkimSelectorConfig {
    /// The domain this selector signs for.
    pub domain: String,
    /// Path to the private key file (PEM or DER format).
    pub key_path: PathBuf,
    /// Signing algorithm (default: rsa-sha256).
    pub algorithm: String,
    /// Header canonicalization (default: relaxed).
    pub header_canon: String,
    /// Body canonicalization (default: relaxed).
    pub body_canon: String,
    /// Headers to sign (comma-separated, default: from,to,subject,date,message-id).
    pub signed_headers: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:2525".parse().unwrap(),
            hostname: "localhost".into(),
            max_message_size: 10 * 1024 * 1024, // 10 MB
            max_recipients: 100,
            spool_dir: PathBuf::from("spool"),
            log_level: "info".into(),
            http_listen_addr: "0.0.0.0:8025".parse().unwrap(),
            // Queue defaults
            queue_concurrency: 5,
            queue_retry_initial_delay_secs: 60,
            queue_retry_backoff_multiplier: 2.0,
            queue_retry_max_delay_secs: 3600,
            queue_retry_max_attempts: 10,
            // DNS defaults
            dns_timeout_secs: 5,
            dns_cache_max_ttl_secs: 3600,
            dns_cache_neg_ttl_secs: 300,
            dns_max_cname_depth: 8,
            // Auth defaults
            dkim_key_dir: None,
            dkim_default_selector: None,
            dkim_selectors: HashMap::new(),
            spf_verify_enabled: true,
            dmarc_verify_enabled: true,
            spf_reject_fail: false,
            dmarc_reject_fail: false,
        }
    }
}

impl Default for DkimSelectorConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            key_path: PathBuf::new(),
            algorithm: "rsa-sha256".to_string(),
            header_canon: "relaxed".to_string(),
            body_canon: "relaxed".to_string(),
            signed_headers: "from,to,subject,date,message-id,mime-version,content-type,content-transfer-encoding".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from an optional TOML file, then overlay env vars.
    ///
    /// `config_path` — when `Some`, the file is read and parsed; a missing or
    /// malformed file is a hard error.  When `None`, only defaults + env vars
    /// are used.
    pub fn load(config_path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        // ── layer 2: config file ────────────────────────────────────
        if let Some(path) = config_path {
            let contents = std::fs::read_to_string(path).map_err(|e| {
                ConfigError(format!("cannot read config file {}: {}", path.display(), e))
            })?;
            let file: FileConfig = toml::from_str(&contents).map_err(|e| {
                ConfigError(format!("bad TOML in {}: {}", path.display(), e))
            })?;
            file.apply(&mut cfg)?;
        }

        // ── layer 3: env-var overrides ──────────────────────────────
        Self::apply_env(&mut cfg);

        Ok(cfg)
    }

    /// Convenience: load with env vars only (no config file). Useful for tests
    /// and backward compat.
    pub fn from_env() -> Self {
        Self::load(None).expect("default config is always valid")
    }

    // ── env-var overlay ─────────────────────────────────────────────

    fn apply_env(cfg: &mut Config) {
        if let Ok(v) = std::env::var("MTA_LISTEN") {
            if let Ok(a) = v.parse() {
                cfg.listen_addr = a;
            }
        }
        if let Ok(v) = std::env::var("MTA_HOSTNAME") {
            cfg.hostname = v;
        }
        if let Ok(v) = std::env::var("MTA_MAX_MESSAGE_SIZE") {
            if let Ok(n) = v.parse() {
                cfg.max_message_size = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_MAX_RECIPIENTS") {
            if let Ok(n) = v.parse() {
                cfg.max_recipients = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_SPOOL_DIR") {
            cfg.spool_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("MTA_LOG_LEVEL") {
            cfg.log_level = v;
        }
        if let Ok(v) = std::env::var("MTA_HTTP_LISTEN") {
            if let Ok(a) = v.parse() {
                cfg.http_listen_addr = a;
            }
        }
        // Queue settings
        if let Ok(v) = std::env::var("MTA_QUEUE_CONCURRENCY") {
            if let Ok(n) = v.parse() {
                cfg.queue_concurrency = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_QUEUE_RETRY_INITIAL_DELAY") {
            if let Ok(n) = v.parse() {
                cfg.queue_retry_initial_delay_secs = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_QUEUE_RETRY_BACKOFF") {
            if let Ok(f) = v.parse() {
                cfg.queue_retry_backoff_multiplier = f;
            }
        }
        if let Ok(v) = std::env::var("MTA_QUEUE_RETRY_MAX_DELAY") {
            if let Ok(n) = v.parse() {
                cfg.queue_retry_max_delay_secs = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_QUEUE_RETRY_MAX_ATTEMPTS") {
            if let Ok(n) = v.parse() {
                cfg.queue_retry_max_attempts = n;
            }
        }
        // DNS settings
        if let Ok(v) = std::env::var("MTA_DNS_TIMEOUT") {
            if let Ok(n) = v.parse() {
                cfg.dns_timeout_secs = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_DNS_CACHE_MAX_TTL") {
            if let Ok(n) = v.parse() {
                cfg.dns_cache_max_ttl_secs = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_DNS_CACHE_NEG_TTL") {
            if let Ok(n) = v.parse() {
                cfg.dns_cache_neg_ttl_secs = n;
            }
        }
        if let Ok(v) = std::env::var("MTA_DNS_MAX_CNAME_DEPTH") {
            if let Ok(n) = v.parse() {
                cfg.dns_max_cname_depth = n;
            }
        }
        // Auth settings
        if let Ok(v) = std::env::var("MTA_DKIM_KEY_DIR") {
            cfg.dkim_key_dir = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("MTA_DKIM_SELECTOR") {
            cfg.dkim_default_selector = Some(v);
        }
        if let Ok(v) = std::env::var("MTA_SPF_VERIFY") {
            cfg.spf_verify_enabled = v.parse().unwrap_or(true);
        }
        if let Ok(v) = std::env::var("MTA_DMARC_VERIFY") {
            cfg.dmarc_verify_enabled = v.parse().unwrap_or(true);
        }
        if let Ok(v) = std::env::var("MTA_SPF_REJECT_FAIL") {
            cfg.spf_reject_fail = v.parse().unwrap_or(false);
        }
        if let Ok(v) = std::env::var("MTA_DMARC_REJECT_FAIL") {
            cfg.dmarc_reject_fail = v.parse().unwrap_or(false);
        }
    }
}

// ── config error ────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

// ── TOML file schema ────────────────────────────────────────────────
//
// Every field is optional — only the values present in the file override the
// compiled-in defaults.
//
// Example mymta.toml:
//
//   [server]
//   listen   = "0.0.0.0:2525"
//   hostname = "mx.example.com"
//
//   [limits]
//   max_message_size = 26214400   # 25 MB
//   max_recipients   = 200
//
//   [spool]
//   dir = "/var/spool/mymta"
//
//   [logging]
//   level = "info"
//
//   [queue]
//   concurrency = 10
//   retry_initial_delay = 60
//   retry_backoff = 2.0
//   retry_max_delay = 3600
//   retry_max_attempts = 10
//
//   [auth]
//   # Simple config (single selector)
//   dkim_key_dir = "/etc/mymta/dkim"
//   dkim_selector = "default"
//
//   # Advanced config (multiple selectors per domain)
//   [auth.dkim.selectors.default]
//   domain = "example.com"
//   key_path = "/etc/mymta/dkim/example.com.default.pem"
//   algorithm = "rsa-sha256"
//   header_canon = "relaxed"
//   body_canon = "relaxed"
//
//   [auth.dkim.selectors."2024"]
//   domain = "example.com"
//   key_path = "/etc/mymta/dkim/example.com.2024.pem"
//
//   [auth.dkim.selectors."mail"]
//   domain = "example.org"
//   key_path = "/etc/mymta/dkim/example.org.mail.pem"
//   signed_headers = "from,to,subject,date"

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    server: Option<ServerSection>,
    limits: Option<LimitsSection>,
    spool: Option<SpoolSection>,
    logging: Option<LoggingSection>,
    http: Option<HttpSection>,
    queue: Option<QueueSection>,
    dns: Option<DnsSection>,
    auth: Option<AuthSection>,
}

#[derive(Debug, Deserialize, Default)]
struct ServerSection {
    listen: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct LimitsSection {
    max_message_size: Option<usize>,
    max_recipients: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct SpoolSection {
    dir: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct LoggingSection {
    level: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct HttpSection {
    listen: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct QueueSection {
    concurrency: Option<u32>,
    retry_initial_delay: Option<u64>,
    retry_backoff: Option<f64>,
    retry_max_delay: Option<u64>,
    retry_max_attempts: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
struct DnsSection {
    timeout_secs: Option<u64>,
    cache_max_ttl_secs: Option<u64>,
    cache_neg_ttl_secs: Option<u64>,
    max_cname_depth: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct AuthSection {
    dkim_key_dir: Option<String>,
    dkim_selector: Option<String>,
    /// Nested DKIM configuration section
    dkim: Option<DkimSection>,
    spf_verify: Option<bool>,
    dmarc_verify: Option<bool>,
    spf_reject_fail: Option<bool>,
    dmarc_reject_fail: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct DkimSection {
    /// Per-selector DKIM configurations. Map key is selector name.
    #[serde(default)]
    selectors: HashMap<String, DkimSelectorFileConfig>,
}

/// TOML file format for DKIM selector config.
#[derive(Debug, Deserialize, Default)]
struct DkimSelectorFileConfig {
    domain: String,
    key_path: String,
    #[serde(default = "default_rsa_sha256")]
    algorithm: String,
    #[serde(default = "default_relaxed")]
    header_canon: String,
    #[serde(default = "default_relaxed")]
    body_canon: String,
    #[serde(default = "default_signed_headers")]
    signed_headers: String,
}

fn default_rsa_sha256() -> String { "rsa-sha256".to_string() }
fn default_relaxed() -> String { "relaxed".to_string() }
fn default_signed_headers() -> String {
    "from,to,subject,date,message-id,mime-version,content-type,content-transfer-encoding".to_string()
}

impl FileConfig {
    fn apply(self, cfg: &mut Config) -> Result<(), ConfigError> {
        if let Some(s) = self.server {
            if let Some(listen) = s.listen {
                cfg.listen_addr = listen.parse().map_err(|e| {
                    ConfigError(format!("invalid server.listen '{}': {}", listen, e))
                })?;
            }
            if let Some(h) = s.hostname {
                cfg.hostname = h;
            }
        }
        if let Some(l) = self.limits {
            if let Some(n) = l.max_message_size {
                cfg.max_message_size = n;
            }
            if let Some(n) = l.max_recipients {
                cfg.max_recipients = n;
            }
        }
        if let Some(sp) = self.spool {
            if let Some(d) = sp.dir {
                cfg.spool_dir = PathBuf::from(d);
            }
        }
        if let Some(lg) = self.logging {
            if let Some(l) = lg.level {
                cfg.log_level = l;
            }
        }
        if let Some(h) = self.http {
            if let Some(listen) = h.listen {
                cfg.http_listen_addr = listen.parse().map_err(|e| {
                    ConfigError(format!("invalid http.listen '{}': {}", listen, e))
                })?;
            }
        }
        if let Some(q) = self.queue {
            if let Some(n) = q.concurrency {
                cfg.queue_concurrency = n;
            }
            if let Some(n) = q.retry_initial_delay {
                cfg.queue_retry_initial_delay_secs = n;
            }
            if let Some(f) = q.retry_backoff {
                cfg.queue_retry_backoff_multiplier = f;
            }
            if let Some(n) = q.retry_max_delay {
                cfg.queue_retry_max_delay_secs = n;
            }
            if let Some(n) = q.retry_max_attempts {
                cfg.queue_retry_max_attempts = n;
            }
        }
        if let Some(d) = self.dns {
            if let Some(n) = d.timeout_secs {
                cfg.dns_timeout_secs = n;
            }
            if let Some(n) = d.cache_max_ttl_secs {
                cfg.dns_cache_max_ttl_secs = n;
            }
            if let Some(n) = d.cache_neg_ttl_secs {
                cfg.dns_cache_neg_ttl_secs = n;
            }
            if let Some(n) = d.max_cname_depth {
                cfg.dns_max_cname_depth = n;
            }
        }
        if let Some(a) = self.auth {
            if let Some(d) = a.dkim_key_dir {
                cfg.dkim_key_dir = Some(PathBuf::from(d));
            }
            if let Some(s) = a.dkim_selector {
                cfg.dkim_default_selector = Some(s);
            }
            // Parse nested [auth.dkim.selectors] configs
            if let Some(dkim) = a.dkim {
                for (selector_name, selector_cfg) in dkim.selectors {
                    cfg.dkim_selectors.insert(
                        selector_name,
                        DkimSelectorConfig {
                            domain: selector_cfg.domain,
                            key_path: PathBuf::from(selector_cfg.key_path),
                            algorithm: selector_cfg.algorithm,
                            header_canon: selector_cfg.header_canon,
                            body_canon: selector_cfg.body_canon,
                            signed_headers: selector_cfg.signed_headers,
                        },
                    );
                }
            }
            if let Some(v) = a.spf_verify {
                cfg.spf_verify_enabled = v;
            }
            if let Some(v) = a.dmarc_verify {
                cfg.dmarc_verify_enabled = v;
            }
            if let Some(r) = a.spf_reject_fail {
                cfg.spf_reject_fail = r;
            }
            if let Some(r) = a.dmarc_reject_fail {
                cfg.dmarc_reject_fail = r;
            }
        }
        Ok(())
    }
}

impl Config {
    /// Get a DKIM selector configuration by name.
    /// Returns None if the selector is not configured.
    pub fn get_dkim_selector(&self, selector_name: &str) -> Option<&DkimSelectorConfig> {
        self.dkim_selectors.get(selector_name)
    }

    /// Find a DKIM selector configuration for a specific domain.
    /// If `selector` is provided, looks for that specific selector.
    /// Otherwise, returns the first selector configured for the domain.
    pub fn find_dkim_selector_for_domain(
        &self,
        domain: &str,
        selector: Option<&str>,
    ) -> Option<(&String, &DkimSelectorConfig)> {
        if let Some(sel) = selector {
            // Look for specific selector
            self.dkim_selectors
                .iter()
                .find(|(name, cfg)| name.as_str() == sel && cfg.domain == domain)
        } else {
            // Find any selector for this domain
            self.dkim_selectors
                .iter()
                .find(|(_, cfg)| cfg.domain == domain)
        }
    }

    /// Get all selectors configured for a specific domain.
    pub fn get_dkim_selectors_for_domain(
        &self,
        domain: &str,
    ) -> Vec<(&String, &DkimSelectorConfig)> {
        self.dkim_selectors
            .iter()
            .filter(|(_, cfg)| cfg.domain == domain)
            .collect()
    }
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn defaults_are_sane() {
        let cfg = Config::default();
        assert_eq!(cfg.listen_addr, "0.0.0.0:2525".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.hostname, "localhost");
        assert_eq!(cfg.max_message_size, 10 * 1024 * 1024);
        assert_eq!(cfg.max_recipients, 100);
        assert_eq!(cfg.spool_dir, PathBuf::from("spool"));
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.http_listen_addr, "0.0.0.0:8025".parse::<SocketAddr>().unwrap());
        // Queue defaults
        assert_eq!(cfg.queue_concurrency, 5);
        assert_eq!(cfg.queue_retry_initial_delay_secs, 60);
        assert_eq!(cfg.queue_retry_backoff_multiplier, 2.0);
        assert_eq!(cfg.queue_retry_max_delay_secs, 3600);
        assert_eq!(cfg.queue_retry_max_attempts, 10);
        // DNS defaults
        assert_eq!(cfg.dns_timeout_secs, 5);
        assert_eq!(cfg.dns_cache_max_ttl_secs, 3600);
        assert_eq!(cfg.dns_cache_neg_ttl_secs, 300);
        assert_eq!(cfg.dns_max_cname_depth, 8);
    }

    #[test]
    fn load_from_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
[server]
listen   = "127.0.0.1:9025"
hostname = "mx.test.com"

[limits]
max_message_size = 5242880
max_recipients   = 50

[spool]
dir = "/tmp/mymta-spool"

[logging]
level = "debug"

[http]
listen = "127.0.0.1:9080"
"#
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:9025".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.hostname, "mx.test.com");
        assert_eq!(cfg.max_message_size, 5_242_880);
        assert_eq!(cfg.max_recipients, 50);
        assert_eq!(cfg.spool_dir, PathBuf::from("/tmp/mymta-spool"));
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.http_listen_addr, "127.0.0.1:9080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn partial_toml_keeps_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
[server]
hostname = "custom.host"

[spool]
dir = "/data/mail"
"#
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.hostname, "custom.host");
        assert_eq!(cfg.spool_dir, PathBuf::from("/data/mail"));
        // Untouched fields keep defaults
        assert_eq!(cfg.listen_addr, "0.0.0.0:2525".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.max_message_size, 10 * 1024 * 1024);
    }

    #[test]
    fn missing_file_is_error() {
        let result = Config::load(Some(Path::new("/nonexistent/mymta.toml")));
        assert!(result.is_err());
    }

    #[test]
    fn bad_toml_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not [valid toml @@@@").unwrap();
        let result = Config::load(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn bad_listen_address_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("badaddr.toml");
        std::fs::write(&path, "[server]\nlisten = \"not-an-address\"").unwrap();
        let result = Config::load(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn no_file_gives_defaults() {
        let cfg = Config::load(None).unwrap();
        assert_eq!(cfg.hostname, "localhost");
        assert_eq!(cfg.spool_dir, PathBuf::from("spool"));
    }

    #[test]
    fn load_dkim_selectors_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dkim.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
[auth.dkim.selectors.default]
domain = "example.com"
key_path = "/etc/mymta/dkim/example.com.default.pem"

[auth.dkim.selectors."2024"]
domain = "example.com"
key_path = "/etc/mymta/dkim/example.com.2024.pem"
algorithm = "rsa-sha256"
header_canon = "simple"

[auth.dkim.selectors.mail]
domain = "example.org"
key_path = "/etc/mymta/dkim/example.org.mail.pem"
signed_headers = "from,to,subject,date"
"#
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        
        // Should have 3 selectors
        assert_eq!(cfg.dkim_selectors.len(), 3);
        
        // Check default selector for example.com
        let default_sel = cfg.get_dkim_selector("default").unwrap();
        assert_eq!(default_sel.domain, "example.com");
        assert_eq!(default_sel.key_path, PathBuf::from("/etc/mymta/dkim/example.com.default.pem"));
        assert_eq!(default_sel.algorithm, "rsa-sha256");
        assert_eq!(default_sel.header_canon, "relaxed"); // default
        
        // Check 2024 selector with custom header_canon
        let sel2024 = cfg.get_dkim_selector("2024").unwrap();
        assert_eq!(sel2024.domain, "example.com");
        assert_eq!(sel2024.header_canon, "simple");
        
        // Check mail selector for example.org
        let mail_sel = cfg.get_dkim_selector("mail").unwrap();
        assert_eq!(mail_sel.domain, "example.org");
        assert_eq!(mail_sel.signed_headers, "from,to,subject,date");
        
        // Test find_dkim_selector_for_domain
        let (name, _) = cfg.find_dkim_selector_for_domain("example.com", Some("default")).unwrap();
        assert_eq!(name, "default");
        
        // Test get_all_selectors_for_domain
        let example_com_selectors = cfg.get_dkim_selectors_for_domain("example.com");
        assert_eq!(example_com_selectors.len(), 2); // default and 2024
        
        let example_org_selectors = cfg.get_dkim_selectors_for_domain("example.org");
        assert_eq!(example_org_selectors.len(), 1); // mail
    }
}