use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to setup tun device: {}", .msg)]
    Setup { msg: String },

    #[error("Only PKCS8 Ed25519 private key is supported.")]
    InvalidPrivateKeyFormat,

    #[error("Signature is invalid (incorrect public key?)")]
    InvalidSignature,

    #[error("MAC tag is invalid")]
    Unseal,

    #[error("Received message was broken")]
    BrokenMessage,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
