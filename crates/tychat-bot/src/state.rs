use std::fmt;

use serde::{Deserialize, Serialize};
use tychat_crypto::{DeviceKeys, IdentityKeys};
use tychat_protocol::IdentityStatement;

use crate::wire::{b64, bytes, id};
use crate::BotError;

const STATE_VERSION: u32 = 1;

/// Why a runner stopped reading and sending until it is paired again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    /// The owner account now has a different identity (a replacement, not a
    /// succession). The old chat cannot be trusted; pair a new bot.
    OwnerIdentityReplaced,
    /// The owner identity changed in a way the runner cannot verify from its
    /// pin (a rollback, a forked statement or a broken succession chain).
    OwnerIdentityUnverifiable,
}

impl fmt::Display for PauseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OwnerIdentityReplaced => "the owner's identity was replaced",
            Self::OwnerIdentityUnverifiable => "the owner's identity could not be verified",
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateWire {
    v: u32,
    api_version: u32,
    bot_id: String,
    bot_account_id: String,
    display_name: String,
    credential: String,
    identity_root_seed: String,
    identity: IdentityStatement,
    device_id: String,
    device_sig_seed: String,
    device_kem_secret: String,
    certificate_sig: String,
    owner_account_id: String,
    owner_display_name: String,
    owner_identity: IdentityStatement,
    conversation_id: Option<String>,
    cursor_seq: u64,
    receipt_read_through_seq: u64,
    paused: Option<PauseReason>,
}

/// Everything a runner must keep between runs. **Secret**: it holds the
/// bot's private keys and its credential. Persist it with owner-only
/// permissions, write it atomically, and save it again on every
/// [`crate::BotEvent::StateChanged`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "StateWire", into = "StateWire")]
pub struct BotState {
    wire: Box<StateWire>,
    device: Box<DeviceKeys>,
    bot_fingerprint: String,
}

impl fmt::Debug for BotState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BotState")
            .field("bot_id", &self.wire.bot_id)
            .field("owner_account_id", &self.wire.owner_account_id)
            .field("conversation_id", &self.wire.conversation_id)
            .field("cursor_seq", &self.wire.cursor_seq)
            .field("paused", &self.wire.paused)
            .finish_non_exhaustive()
    }
}

impl From<BotState> for StateWire {
    fn from(state: BotState) -> Self {
        *state.wire
    }
}

impl TryFrom<StateWire> for BotState {
    type Error = BotError;

    fn try_from(wire: StateWire) -> Result<Self, BotError> {
        let invalid = |_| BotError::InvalidState("keys or statements do not verify");
        if wire.v != STATE_VERSION || wire.api_version != tychat_protocol::BOT_API_VERSION {
            return Err(BotError::InvalidState("unsupported state version"));
        }
        if wire.bot_account_id != tychat_protocol::bot_account_id(&wire.bot_id)
            || wire.credential.is_empty()
            || wire.owner_account_id.is_empty()
        {
            return Err(BotError::InvalidState("ids are inconsistent"));
        }
        let statement = crate::wire::statement(&wire.identity).map_err(invalid)?;
        let identity = IdentityKeys::from_secret_bytes(
            id(&wire.identity.identity_id).map_err(invalid)?,
            bytes(&wire.identity_root_seed).map_err(invalid)?,
        );
        if identity.statement(statement.generation, statement.recovery_mode) != statement {
            return Err(BotError::InvalidState(
                "identity key does not match its statement",
            ));
        }
        let device = DeviceKeys::from_secret_bytes(
            id(&wire.device_id).map_err(invalid)?,
            bytes(&wire.device_sig_seed).map_err(invalid)?,
            bytes(&wire.device_kem_secret).map_err(invalid)?,
        );
        tychat_crypto::verify_device_certificate(
            &statement,
            &device.bundle(),
            &bytes(&wire.certificate_sig).map_err(invalid)?,
        )
        .map_err(|_| BotError::InvalidState("device certificate does not verify"))?;
        let owner = crate::wire::statement(&wire.owner_identity).map_err(invalid)?;
        tychat_crypto::verify_identity_statement(&owner)
            .map_err(|_| BotError::InvalidState("owner identity does not verify"))?;
        Ok(Self {
            bot_fingerprint: tychat_crypto::identity_fingerprint(&statement),
            wire: Box::new(wire),
            device: Box::new(device),
        })
    }
}

impl BotState {
    pub(crate) fn new(
        pairing: tychat_protocol::BotPairResponse,
        identity: &IdentityKeys,
        statement: &tychat_crypto::IdentityStatement,
        device: &DeviceKeys,
        certificate_sig: &tychat_crypto::Sig,
    ) -> Result<Self, BotError> {
        let (sig_seed, kem_secret) = device.secret_bytes();
        Self::try_from(StateWire {
            v: STATE_VERSION,
            api_version: tychat_protocol::BOT_API_VERSION,
            bot_id: pairing.bot_id,
            bot_account_id: pairing.bot_account_id,
            display_name: pairing.display_name,
            credential: pairing.credential,
            identity_root_seed: b64(&identity.root_seed()),
            identity: crate::wire::statement_wire(statement),
            device_id: hex::encode(device.device_id()),
            device_sig_seed: b64(&sig_seed),
            device_kem_secret: b64(&kem_secret),
            certificate_sig: b64(certificate_sig),
            owner_account_id: pairing.owner.account_id,
            owner_display_name: pairing.owner.display_name,
            owner_identity: pairing.owner.identity,
            conversation_id: None,
            cursor_seq: 0,
            receipt_read_through_seq: 0,
            paused: None,
        })
        .map_err(|_| BotError::Protocol("the pairing response does not verify"))
    }

    pub fn bot_id(&self) -> &str {
        &self.wire.bot_id
    }

    pub fn bot_account_id(&self) -> &str {
        &self.wire.bot_account_id
    }

    pub fn display_name(&self) -> &str {
        &self.wire.display_name
    }

    pub fn device_id(&self) -> &str {
        &self.wire.device_id
    }

    pub fn owner_account_id(&self) -> &str {
        &self.wire.owner_account_id
    }

    pub fn owner_display_name(&self) -> &str {
        &self.wire.owner_display_name
    }

    /// The owner direct conversation, once the owner confirmed and opened it.
    pub fn conversation_id(&self) -> Option<&str> {
        self.wire.conversation_id.as_deref()
    }

    /// The last conversation sequence the runner has processed.
    pub fn cursor_seq(&self) -> u64 {
        self.wire.cursor_seq
    }

    pub fn paused(&self) -> Option<PauseReason> {
        self.wire.paused
    }

    /// The bot's identity fingerprint, which the owner compares in Tychat.
    pub fn bot_fingerprint(&self) -> &str {
        &self.bot_fingerprint
    }

    /// The fingerprint of the owner identity the runner currently trusts.
    pub fn owner_fingerprint(&self) -> String {
        crate::wire::statement(&self.wire.owner_identity)
            .map(|statement| tychat_crypto::identity_fingerprint(&statement))
            .unwrap_or_default()
    }

    pub(crate) fn credential(&self) -> &str {
        &self.wire.credential
    }

    pub(crate) fn device(&self) -> &DeviceKeys {
        &self.device
    }

    pub(crate) fn owner_identity(&self) -> &IdentityStatement {
        &self.wire.owner_identity
    }

    pub(crate) fn sig_seed(&self) -> [u8; 32] {
        self.device.secret_bytes().0
    }

    pub(crate) fn receipt_read_through_seq(&self) -> u64 {
        self.wire.receipt_read_through_seq
    }

    pub(crate) fn set_conversation(&mut self, conversation_id: Option<String>) {
        if self.wire.conversation_id != conversation_id {
            self.wire.conversation_id = conversation_id;
            self.wire.cursor_seq = 0;
            self.wire.receipt_read_through_seq = 0;
        }
    }

    pub(crate) fn set_cursor(&mut self, seq: u64) {
        self.wire.cursor_seq = self.wire.cursor_seq.max(seq);
    }

    pub(crate) fn set_receipt_read_through(&mut self, seq: u64) {
        self.wire.receipt_read_through_seq = self.wire.receipt_read_through_seq.max(seq);
    }

    pub(crate) fn set_owner_identity(&mut self, identity: IdentityStatement) {
        self.wire.owner_identity = identity;
    }

    pub(crate) fn set_paused(&mut self, reason: PauseReason) {
        self.wire.paused = Some(reason);
    }
}

/// What [`crate::pair`] returns. Persist `state` before showing anything:
/// the server has already consumed the pairing code.
#[derive(Debug, Clone)]
pub struct PairingResult {
    pub state: BotState,
    pub bot_fingerprint: String,
    pub owner_fingerprint: String,
}
