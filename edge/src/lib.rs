#![forbid(unsafe_code)]

pub mod admission;
pub mod cage;
pub mod central;
pub mod config;
pub mod mgmt_entry;
pub mod prober;
pub mod proto;
pub mod reverse_tunnel;
pub mod server;
pub mod ssrf;
pub mod usage_extract;
pub mod wal;

pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-edge-rs");
