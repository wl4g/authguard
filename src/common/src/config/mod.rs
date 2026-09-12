//! Single strongly typed product configuration shared by both services.

#[allow(clippy::module_inception)]
mod config;
pub mod constants;

pub use config::*;
pub use constants::*;
