//! moss: OS-agnostic user-profile backup and restore on top of Kopia.
//!
//! Kopia is the engine. The profile model is the product.

pub mod backup;
pub mod cli;
pub mod config;
pub mod credentials;
pub mod doctor;
pub mod endpoints;
pub mod error;
pub mod lock;
pub mod model;
pub mod output;
pub mod platform;
pub mod profile;
pub mod restore;
pub mod scan;
pub mod security;
pub mod yubikey;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
