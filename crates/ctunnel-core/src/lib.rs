/*
    ctunnel-core
        low-level pritimitives for authenticated, encrypted
        control-place tunnels.
 */

pub mod error;

pub mod framing;
pub mod protocol;
pub mod crypto;
pub mod handshake;
pub mod channel;

pub use error::CtunnelError;

#[cfg(test)]
mod lib_tests;