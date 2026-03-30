// src/queue/manager.rs
//
// QueueManager — orchestrates per-destination queues, retry scheduling,
// and concurrency limits.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, RwLock};
use tracing;

use crate::message::envelope::Envelope;
use crate::spool::disk::DiskSpool;

use super::retry::RetrySchedule;

/// Metadata about a queued message's delivery state.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub queue_id: String,
    pub attempt: u32,
    pub next_retry_at: Option<Instant>,
    /// Delivery priority: 0=High, 1=Normal, 2=Low. Lower = higher priority.
    pub priority: u8,
}

/// State for a single destination domain's queue.
#[derive(Debug)]
pub struct DestinationQueue {
    /// Destination domain (e.g., "example.com").
    pub domain: String,
    /// Pending messages waiting to be sent or retried.
    pub pending: Vec<QueuedMessage>,
    /// Number of messages currently being delivered.
    pub in_flight: u32,
    /// Maximum concurrent deliveries allowed for this destination.
    pub concurrency_limit: u32,
}

impl DestinationQueue {
    pub fn new(domain: String, concurrency_limit: u32) -> Self {
        Self {
            domain,
            pending: Vec::new(),
            in_flight: 0,
            concurrency_limit,
        }
    }

    /// Can we start another delivery right now?
    pub fn can_send_now(&self) -> bool {
        self.in_flight < self.concurrency_limit
    }

    /// How many slots are available for new deliveries?
    pub fn available_slots(&self) -> u32 {
        self.concurrency_limit.saturating_sub(self.in_flight)
    }

    /// Enqueue a new message for this destination.
    pub fn enqueue(&mut self, queue_id: String, priority: u8) {
        self.pending.push(QueuedMessage {
            queue_id,
            attempt: 0,
            next_retry_at: None,
            priority,
        });
    }

    /// Mark delivery started (increments in_flight).
    /// Picks the highest-priority (lowest number) message that is ready to send.
    pub fn start_delivery(&mut self) -> Option<QueuedMessage> {
        let now = Instant::now();
        // Find the ready message with highest priority (lowest priority value)
        let best = self.pending
            .iter()
            .enumerate()
            .filter(|(_, m)| match m.next_retry_at {
                None => true,
                Some(t) => t <= now,
            })
            .min_by_key(|(_, m)| m.priority)?;

        let idx = best.0;
        let msg = self.pending.remove(idx);
        self.in_flight += 1;
        Some(msg)
    }

    /// Called when a delivery succeeds: decrement in_flight.
    pub fn on_success(&mut self) {
        if self.in_flight > 0 {
            self.in_flight -= 1;
        }
    }

    /// Called when a delivery fails: schedule retry or give up.
    pub fn on_failure(&mut self, mut msg: QueuedMessage, schedule: &RetrySchedule) {
        if self.in_flight > 0 {
            self.in_flight -= 1;
        }
        msg.attempt += 1;
        if schedule.should_give_up(msg.attempt) {
            tracing::warn!(
                queue_id = %msg.queue_id,
                domain = %self.domain,
                attempts = msg.attempt,
                "giving up on message after max attempts"
            );
            // Message is dropped (caller should remove from spool)
        } else {
            let delay = schedule.delay_for_attempt(msg.attempt);
            msg.next_retry_at = Some(Instant::now() + delay);
            tracing::info!(
                queue_id = %msg.queue_id,
                domain = %self.domain,
                attempt = msg.attempt,
                delay_secs = delay.as_secs(),
                "scheduling retry"
            );
            self.pending.push(msg);
        }
    }
}

/// Global queue manager handling all destinations.
pub struct QueueManager {
    /// Per-destination queues keyed by domain (lowercased).
    destinations: RwLock<HashMap<String, Mutex<DestinationQueue>>>,
    /// Default concurrency limit per destination.
    default_concurrency: u32,
    /// Retry schedule policy.
    retry_schedule: RetrySchedule,
    /// Shared spool for reading/removing messages.
    spool: Arc<DiskSpool>,
}

impl QueueManager {
    /// Create a new QueueManager with the given spool and defaults.
    pub fn new(
        spool: Arc<DiskSpool>,
        default_concurrency: u32,
        retry_schedule: RetrySchedule,
    ) -> Self {
        Self {
            destinations: RwLock::new(HashMap::new()),
            default_concurrency,
            retry_schedule,
            spool,
        }
    }

    /// Create with default retry schedule.
    pub fn with_defaults(spool: Arc<DiskSpool>) -> Self {
        Self::new(spool, 5, RetrySchedule::default())
    }

    /// Extract destination domain from a recipient email address.
    fn extract_domain(addr: &str) -> Option<String> {
        addr.rsplit('@').next().map(|d| d.to_lowercase())
    }

    /// Determine the primary destination domain for an envelope.
    /// Uses the first recipient's domain (common MTA behavior).
    fn envelope_domain(envelope: &Envelope) -> Option<String> {
        envelope
            .recipients
            .first()
            .and_then(|rcpt| Self::extract_domain(rcpt))
    }

    /// Enqueue a newly accepted message (called after spooling).
    pub async fn enqueue(&self, queue_id: &str) -> std::io::Result<()> {
        // Read envelope to find destination and priority
        let env = self.spool.read_envelope(queue_id).await?;
        let domain = match Self::envelope_domain(&env) {
            Some(d) => d,
            None => {
                tracing::warn!(queue_id = %queue_id, "no recipients, cannot enqueue");
                return Ok(());
            }
        };
        let priority = env.priority;

        self.enqueue_to_domain(queue_id, &domain, priority).await;
        tracing::info!(queue_id = %queue_id, domain = %domain, priority = %priority, "message enqueued for delivery");
        Ok(())
    }

    /// Internal: add queue_id to a specific domain's queue.
    async fn enqueue_to_domain(&self, queue_id: &str, domain: &str, priority: u8) {
        let mut dests = self.destinations.write().await;
        let entry = dests.entry(domain.to_string()).or_insert_with(|| {
            Mutex::new(DestinationQueue::new(domain.to_string(), self.default_concurrency))
        });
        let mut dq = entry.lock().await;
        dq.enqueue(queue_id.to_string(), priority);
    }

    /// Try to get a message ready for delivery from any destination.
    /// Returns (queue_id, domain) if a slot is available and a message is ready.
    pub async fn next_for_delivery(&self) -> Option<(String, String)> {
        let dests = self.destinations.read().await;
        for (domain, dq_mutex) in dests.iter() {
            let mut dq = dq_mutex.lock().await;
            if dq.can_send_now() {
                if let Some(msg) = dq.start_delivery() {
                    return Some((msg.queue_id, domain.clone()));
                }
            }
        }
        None
    }

    /// Signal successful delivery: remove from spool and release slot.
    pub async fn on_delivery_success(&self, queue_id: &str, domain: &str) {
        // Remove from spool
        if let Err(e) = self.spool.remove(queue_id).await {
            tracing::error!(queue_id = %queue_id, error = %e, "failed to remove spooled message");
        }
        // Release concurrency slot
        if let Some(dq_mutex) = self.destinations.read().await.get(domain) {
            let mut dq = dq_mutex.lock().await;
            dq.on_success();
        }
        tracing::info!(queue_id = %queue_id, domain = %domain, "delivery succeeded");
    }

    /// Signal failed delivery: schedule retry or give up.
    pub async fn on_delivery_failure(&self, queue_id: &str, domain: &str) {
        let dests = self.destinations.read().await;
        if let Some(dq_mutex) = dests.get(domain) {
            let mut dq = dq_mutex.lock().await;
            // Find the message in in_flight state — we need to reconstruct it
            // For simplicity, we recreate from the queue_id with incremented attempt.
            // In a real system you'd track in-flight messages separately.
            // Priority defaults to 1 (normal) if unknown; real impl would preserve it.
            let msg = QueuedMessage {
                queue_id: queue_id.to_string(),
                attempt: 0, // Will be incremented in on_failure
                next_retry_at: None,
                priority: 1,
            };
            dq.on_failure(msg, &self.retry_schedule);
        }
        tracing::warn!(queue_id = %queue_id, domain = %domain, "delivery failed, retry scheduled");
    }

    /// Get number of pending messages across all destinations.
    pub async fn total_pending(&self) -> usize {
        let dests = self.destinations.read().await;
        let mut total = 0;
        for dq_mutex in dests.values() {
            let dq = dq_mutex.lock().await;
            total += dq.pending.len();
        }
        total
    }

    /// Get in-flight count across all destinations.
    pub async fn total_in_flight(&self) -> u32 {
        let dests = self.destinations.read().await;
        let mut total = 0u32;
        for dq_mutex in dests.values() {
            let dq = dq_mutex.lock().await;
            total += dq.in_flight;
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn make_test_spool() -> (Arc<DiskSpool>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let spool = Arc::new(DiskSpool::new(tmp.path().join("spool")).await.unwrap());
        (spool, tmp)
    }

    #[tokio::test]
    async fn enqueue_and_pickup() {
        let (spool, _tmp) = make_test_spool().await;
        let qm = QueueManager::with_defaults(spool.clone());

        // Create a fake envelope and spool it
        let mut env = Envelope::new();
        env.stamp("Q001".into());
        env.set_sender("a@b.com".into(), vec![]);
        env.add_recipient("user@example.com".into());
        spool.store(&env, b"test message").await.unwrap();

        // Enqueue
        qm.enqueue("Q001").await.unwrap();

        // Should be able to pick up for delivery
        let next = qm.next_for_delivery().await;
        assert!(next.is_some());
        let (qid, domain) = next.unwrap();
        assert_eq!(qid, "Q001");
        assert_eq!(domain, "example.com");

        // Success path
        qm.on_delivery_success("Q001", "example.com").await;
        assert!(spool.read_message("Q001").await.is_err()); // removed
    }

    #[tokio::test]
    async fn concurrency_limit() {
        let (spool, _tmp) = make_test_spool().await;
        let qm = QueueManager::new(spool.clone(), 2, RetrySchedule::default());

        // Spool 3 messages to same domain
        for i in 1..=3 {
            let mut env = Envelope::new();
            env.stamp(format!("Q{:03}", i));
            env.set_sender("a@b.com".into(), vec![]);
            env.add_recipient("user@example.com".into());
            spool.store(&env, b"msg").await.unwrap();
            qm.enqueue(&format!("Q{:03}", i)).await.unwrap();
        }

        // First two should be picked up
        assert!(qm.next_for_delivery().await.is_some());
        assert!(qm.next_for_delivery().await.is_some());
        // Third should be blocked (concurrency exhausted)
        assert!(qm.next_for_delivery().await.is_none());

        // Release one
        qm.on_delivery_success("Q001", "example.com").await;
        // Now third should be available
        assert!(qm.next_for_delivery().await.is_some());
    }

    #[tokio::test]
    async fn priority_ordering() {
        let (spool, _tmp) = make_test_spool().await;
        let qm = QueueManager::with_defaults(spool.clone());

        // Spool 3 messages: normal, low, high (in that order)
        for (i, prio) in [(1, 1), (2, 2), (3, 0)] {
            let mut env = Envelope::new();
            env.stamp(format!("P{:03}", i));
            env.set_sender("a@b.com".into(), vec![]);
            env.add_recipient("user@example.com".into());
            env.priority = prio;
            spool.store(&env, b"msg").await.unwrap();
            qm.enqueue(&format!("P{:03}", i)).await.unwrap();
        }

        // Should pick up in priority order: P003 (high=0), then P001 (normal=1), then P002 (low=2)
        let first = qm.next_for_delivery().await;
        assert_eq!(first.unwrap().0, "P003");

        let second = qm.next_for_delivery().await;
        assert_eq!(second.unwrap().0, "P001");

        let third = qm.next_for_delivery().await;
        assert_eq!(third.unwrap().0, "P002");

        // No more
        assert!(qm.next_for_delivery().await.is_none());
    }
}
