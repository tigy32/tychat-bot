use crate::state::PauseReason;

/// Every failure a runner can see. Messages never carry keys, credentials,
/// plaintext or ciphertext.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BotError {
    #[error("network error: {0}")]
    Network(String),
    #[error("server refused the request ({status} {code})")]
    Http { status: u16, code: String },
    #[error("the pairing code is malformed, unknown, used or expired")]
    InvalidPairingCode,
    #[error("the owner deleted this bot; its credential no longer works")]
    Revoked,
    #[error("the bot is paused: {0}")]
    Paused(PauseReason),
    #[error("the owner has not confirmed this bot yet")]
    NotConfirmed,
    #[error("this message id was already used for a different message")]
    MessageIdConflict,
    #[error("a message is at most 8000 UTF-16 code units")]
    MessageTooLong,
    #[error("the server answered with data that breaks the protocol: {0}")]
    Protocol(&'static str),
    #[error("verification or decryption failed")]
    Crypto,
    #[error("the bot state is invalid: {0}")]
    InvalidState(&'static str),
    #[error("the bot client has stopped")]
    Closed,
}

impl BotError {
    pub(crate) fn network(error: reqwest::Error) -> Self {
        Self::Network(error.without_url().to_string())
    }

    pub(crate) fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            _ => None,
        }
    }
}
