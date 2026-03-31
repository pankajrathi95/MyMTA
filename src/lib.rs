// src/lib.rs - Library crate exposing all modules for integration tests and
// re-use in future binaries.

pub mod auth;
pub mod config;
pub mod delivery;
pub mod dns;
pub mod http;
pub mod message;
pub mod queue;
pub mod smtp;
pub mod spool;