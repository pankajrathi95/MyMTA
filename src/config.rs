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

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    server: Option<ServerSection>,
    limits: Option<LimitsSection>,
    spool: Option<SpoolSection>,
    logging: Option<LoggingSection>,
    http: Option<HttpSection>,
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
        Ok(())
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
}