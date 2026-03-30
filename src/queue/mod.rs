// src/queue/mod.rs
//
// Phase 2: Outbound message queuing and delivery management.
//
// Features implemented:
//   - One queue per destination domain
//   - Retry schedule with exponential backoff
//   - Concurrency limits per destination
//   - Single-file spool format integration

pub mod manager;
pub mod retry;

pub use manager::QueueManager;
pub use retry::RetrySchedule;
