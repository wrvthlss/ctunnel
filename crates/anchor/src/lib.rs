// ANCHOR facade API (demo repo).
//     This crate is the intended embedding surface for consumers.
//     It hides protocol internals and exposes a simple zero-trust secure transport API.

mod error;
mod identity;
mod trust;
mod conn;
mod listener;

pub use error::AnchorError;
pub use identity::{Identity, PublicKey};
pub use trust::TrustPolicy;
pub use conn::AnchorConn;
pub use listener::AnchorListener;

// High-level entry points:
pub use listener::listen;
pub use conn::connect;
