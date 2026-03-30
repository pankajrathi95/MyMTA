// src/spool/disk.rs
//
// Disk-based message spool.  Each accepted message is stored as two files:
//   {queue_id}.env.json  — Envelope metadata (sender, recipients, timestamps)
//   {queue_id}.eml       — Raw email message (headers + body)
//
// Writes are atomic: data goes to a temp file first, then renamed into place.

use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing;

use crate::message::envelope::Envelope;

/// Disk-based message spool.
pub struct DiskSpool {
    spool_dir: PathBuf,
}

impl DiskSpool {
    /// Create a new spool rooted at `spool_dir`.  The directory is created if
    /// it does not exist.
    pub async fn new(spool_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let spool_dir = spool_dir.as_ref().to_path_buf();
        fs::create_dir_all(&spool_dir).await?;
        // Create a tmp sub-directory for atomic writes
        fs::create_dir_all(spool_dir.join("tmp")).await?;
        Ok(Self { spool_dir })
    }

    /// Spool a message to disk.  Returns the path to the .eml file on success.
    pub async fn store(
        &self,
        envelope: &Envelope,
        message_data: &[u8],
    ) -> std::io::Result<PathBuf> {
        let queue_id = &envelope.id;

        // ── write envelope JSON (atomic) ────────────────────────────
        let env_json = serde_json::to_string_pretty(envelope)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let env_tmp = self.spool_dir.join("tmp").join(format!("{}.env.json", queue_id));
        let env_final = self.spool_dir.join(format!("{}.env.json", queue_id));
        Self::atomic_write(&env_tmp, &env_final, env_json.as_bytes()).await?;

        // ── write raw message (atomic) ──────────────────────────────
        let eml_tmp = self.spool_dir.join("tmp").join(format!("{}.eml", queue_id));
        let eml_final = self.spool_dir.join(format!("{}.eml", queue_id));
        Self::atomic_write(&eml_tmp, &eml_final, message_data).await?;

        tracing::info!(
            queue_id = %queue_id,
            sender = %envelope.sender,
            recipients = ?envelope.recipients,
            size = message_data.len(),
            "message spooled to disk"
        );

        Ok(eml_final)
    }

    /// Write `data` to `tmp_path`, then atomically rename to `final_path`.
    async fn atomic_write(
        tmp_path: &Path,
        final_path: &Path,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut f = fs::File::create(tmp_path).await?;
        f.write_all(data).await?;
        f.flush().await?;
        // sync to ensure data is on disk before rename
        f.sync_all().await?;
        fs::rename(tmp_path, final_path).await?;
        Ok(())
    }

    /// List all queued message IDs (based on .eml files present).
    pub async fn list_queue(&self) -> std::io::Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut entries = fs::read_dir(&self.spool_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".eml") {
                ids.push(name.trim_end_matches(".eml").to_string());
            }
        }
        Ok(ids)
    }

    /// Read a spooled envelope by queue id.
    pub async fn read_envelope(&self, queue_id: &str) -> std::io::Result<Envelope> {
        let path = self.spool_dir.join(format!("{}.env.json", queue_id));
        let data = fs::read_to_string(&path).await?;
        serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Read the raw message by queue id.
    pub async fn read_message(&self, queue_id: &str) -> std::io::Result<Vec<u8>> {
        let path = self.spool_dir.join(format!("{}.eml", queue_id));
        fs::read(&path).await
    }

    /// Remove a message from the spool (after delivery).
    pub async fn remove(&self, queue_id: &str) -> std::io::Result<()> {
        let env_path = self.spool_dir.join(format!("{}.env.json", queue_id));
        let eml_path = self.spool_dir.join(format!("{}.eml", queue_id));
        // Best-effort removal of both files
        let _ = fs::remove_file(&env_path).await;
        let _ = fs::remove_file(&eml_path).await;
        Ok(())
    }

    /// Get the spool directory path.
    pub fn spool_dir(&self) -> &Path {
        &self.spool_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn make_test_envelope() -> Envelope {
        let mut env = Envelope::new();
        env.stamp("TEST123456".into());
        env.set_sender("sender@example.com".into(), vec![]);
        env.add_recipient("rcpt@example.com".into());
        env.client_hostname = Some("client.test".into());
        env.peer_addr = Some("127.0.0.1:12345".into());
        env
    }

    #[tokio::test]
    async fn spool_and_read_back() {
        let tmp = TempDir::new().unwrap();
        let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();
        let env = make_test_envelope().await;
        let msg = b"From: sender@example.com\r\nTo: rcpt@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nHello!\r\n";

        let eml_path = spool.store(&env, msg).await.unwrap();
        assert!(eml_path.exists());

        // Read back envelope
        let read_env = spool.read_envelope("TEST123456").await.unwrap();
        assert_eq!(read_env.sender, "sender@example.com");
        assert_eq!(read_env.recipients, vec!["rcpt@example.com"]);

        // Read back message
        let read_msg = spool.read_message("TEST123456").await.unwrap();
        assert_eq!(read_msg, msg);
    }

    #[tokio::test]
    async fn list_queue() {
        let tmp = TempDir::new().unwrap();
        let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();

        // Spool two messages
        let mut env1 = make_test_envelope().await;
        env1.stamp("MSG001".into());
        spool.store(&env1, b"msg1").await.unwrap();

        let mut env2 = make_test_envelope().await;
        env2.stamp("MSG002".into());
        spool.store(&env2, b"msg2").await.unwrap();

        let mut ids = spool.list_queue().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["MSG001", "MSG002"]);
    }

    #[tokio::test]
    async fn remove_from_spool() {
        let tmp = TempDir::new().unwrap();
        let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();

        let env = make_test_envelope().await;
        spool.store(&env, b"data").await.unwrap();

        spool.remove("TEST123456").await.unwrap();

        assert!(spool.read_message("TEST123456").await.is_err());
        assert!(spool.read_envelope("TEST123456").await.is_err());
    }

    #[tokio::test]
    async fn creates_spool_dir() {
        let tmp = TempDir::new().unwrap();
        let deep = tmp.path().join("a").join("b").join("spool");
        let spool = DiskSpool::new(&deep).await.unwrap();
        assert!(spool.spool_dir().exists());
    }
}