//! Error types for atv-core.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("OPACK error: {0}")]
    Opack(#[from] crate::opack::OpackError),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("SRP error: {0}")]
    Srp(String),

    #[error("mDNS error: {0}")]
    Mdns(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;
