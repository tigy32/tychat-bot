//! Runner library for Tychat personal bots (ADR-0034, `design/systems/bots.md`).
//!
//! A bot is a program its owner runs. [`pair`] redeems the one-time code from
//! Tychat Settings → Bots and returns a secret [`BotState`];
//! [`BotClient::connect`] then reads the owner's messages, verified and
//! decrypted, as [`BotEvent`]s and sends replies, typing and read receipts.
//! All cryptography is `tychat-crypto`; nothing here logs keys, the
//! credential, plaintext or ciphertext.

mod api;
mod client;
mod error;
mod pair;
mod state;
mod trust;
mod wire;

#[cfg(feature = "owner-kit")]
pub mod owner_kit;

pub use client::{BotClient, BotEvent, MessageRef};
pub use error::BotError;
pub use pair::pair;
pub use state::{BotState, PairingResult, PauseReason};
pub use url::Url;

/// The production Tychat origin.
pub const PRODUCTION_API_BASE: &str = "https://chat.tyggs.com";
