//! Tychat E2EE core (ADR-0001).
//!
//! Pure functions over byte arrays. No IO, no clock, no global RNG: every
//! operation that needs randomness takes an `impl CryptoRng + RngCore`, so the
//! core is deterministic under test and identical on native and wasm32.
//!
//! Wire encodings (hex ids, base64 bytes) are the caller's business; this
//! crate speaks fixed-size arrays and `Vec<u8>` only.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub const ID_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SIG_LEN: usize = 64;
pub const TAG_LEN: usize = 16;
/// `eph_pub(32) || nonce(24) || ct(32 + 16)`.
pub const WRAPPED_LEN: usize = KEY_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

const DOMAIN_DEVICE: &[u8] = b"tychat-device-v1";
const DOMAIN_IDENTITY: &[u8] = b"tychat-identity-v1";
const DOMAIN_DEVICE_CERT: &[u8] = b"tychat-device-cert-v1";
const DOMAIN_IDENTITY_FP: &[u8] = b"tychat-identity-fp-v1";
const DOMAIN_INVITE: &[u8] = b"tychat-invite-v1";
const DOMAIN_DEVICE_ACTIVATION: &[u8] = b"tychat-device-activation-v1";
const DOMAIN_DEVICE_REVOCATION: &[u8] = b"tychat-device-revocation-v1";
const DOMAIN_GENERATION_SUCCESSION: &[u8] = b"tychat-generation-succession-v1";
const DOMAIN_DEVICE_TRANSFER: &[u8] = b"tychat-device-transfer-v1";
const DOMAIN_PUBLIC_CONTACT: &[u8] = b"tychat-public-contact-v1";
const DOMAIN_PUBLIC_CONTACT_DECISION: &[u8] = b"tychat-public-contact-decision-v1";
const DOMAIN_PUSH_SUBSCRIPTION: &[u8] = b"tychat-push-subscription-v1";
const DOMAIN_PUSH_DISABLE: &[u8] = b"tychat-push-disable-v1";
const DOMAIN_PUSH_DISABLE_DEVICE: &[u8] = b"tychat-push-disable-device-v1";
const DOMAIN_REALTIME_TICKET: &[u8] = b"tychat-ws-ticket-v1";
const DOMAIN_BOT_PAIRING: &[u8] = b"tychat-bot-pairing-v1";
const DOMAIN_BOT_REQUEST: &[u8] = b"tychat-bot-request-v1";
const DOMAIN_GRANT: &[u8] = b"tychat-grant-v1";
const DOMAIN_LOCK_RECIPIENT: &[u8] = b"tychat-lock-recipient-v1";
const DOMAIN_LOCK_WRAPPER: &[u8] = b"tychat-lock-wrapper-v1";
const DOMAIN_LOCK_GRANT: &[u8] = b"tychat-lock-grant-v1";
const DOMAIN_LOCK_PROOF: &[u8] = b"tychat-lock-proof-v1";
const DOMAIN_MSG: &[u8] = b"tychat-msg-v1";
const DOMAIN_ROSTER: &[u8] = b"tychat-roster-v1";
const MESSAGE_CONTENT_NONCE_PREFIX: &[u8; 8] = b"TYC2CONT";
const MESSAGE_SILENT_NONCE_PREFIX: &[u8; 8] = b"TYC2CTRL";
const DOMAIN_BLOB: &[u8] = b"tychat-blob-v1";
const DOMAIN_AVATAR_CAPABILITY: &[u8] = b"tychat-avatar-capability-v1";
const DOMAIN_AVATAR_COMMITMENT: &[u8] = b"tychat-avatar-commitment-v1";
const DOMAIN_AVATAR: &[u8] = b"tychat-avatar-v1";
const DOMAIN_AVATAR_STATEMENT: &[u8] = b"tychat-avatar-statement-v1";
const DOMAIN_AVATAR_GRANT: &[u8] = b"tychat-avatar-grant-v1";
const DOMAIN_RECOVERY_VAULT: &[u8] = b"tychat-recovery-vault-v1";
const DOMAIN_RECOVERY_PASSKEY: &[u8] = b"tychat-recovery-passkey-v1";
const DOMAIN_RECOVERY_CODE: &[u8] = b"tychat-recovery-code-v1";
const DOMAIN_FP: &[u8] = b"tychat-fp-v1";

pub const RECOVERY_VAULT_FORMAT: u8 = 1;
pub const RECOVERY_WRAPPER_FORMAT: u8 = 1;
pub const RECOVERY_WRAPPER_LEN: usize = 1 + KEY_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;
pub const MAX_RECOVERY_VAULT_VERSION: u64 = u32::MAX as u64;
pub const LOCK_KDF_MEMORY_KIB: u32 = 65_536;
pub const LOCK_KDF_ITERATIONS: u32 = 3;
pub const LOCK_KDF_LANES: u32 = 1;
pub const LOCK_WRAPPED_LEN: usize = NONCE_LEN + KEY_LEN * 2 + TAG_LEN;

pub type Id = [u8; ID_LEN];
pub type Key = [u8; KEY_LEN];
pub type Nonce = [u8; NONCE_LEN];
pub type Sig = [u8; SIG_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordKind {
    Pin6,
    Passphrase,
}

impl PasswordKind {
    fn byte(self) -> u8 {
        match self {
            Self::Pin6 => 0,
            Self::Passphrase => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryMode {
    Standard,
    Strict,
}

impl RecoveryMode {
    fn byte(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::Strict => 1,
        }
    }
}

#[derive(Clone)]
pub struct IdentityKeys {
    identity_id: Id,
    root: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityStatement {
    pub identity_id: Id,
    pub generation: u64,
    pub root_sig_pub: Key,
    pub recovery_mode: RecoveryMode,
    pub statement_sig: Sig,
}

impl IdentityKeys {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut identity_id = [0u8; ID_LEN];
        rng.fill_bytes(&mut identity_id);
        Self {
            identity_id,
            root: SigningKey::generate(rng),
        }
    }

    pub fn from_secret_bytes(identity_id: Id, root_seed: Key) -> Self {
        Self {
            identity_id,
            root: SigningKey::from_bytes(&root_seed),
        }
    }

    pub fn identity_id(&self) -> &Id {
        &self.identity_id
    }

    pub fn root_seed(&self) -> Key {
        self.root.to_bytes()
    }

    pub fn root_sig_pub(&self) -> Key {
        self.root.verifying_key().to_bytes()
    }

    pub fn statement(&self, generation: u64, recovery_mode: RecoveryMode) -> IdentityStatement {
        let root_sig_pub = self.root_sig_pub();
        let material =
            identity_material(&self.identity_id, generation, &root_sig_pub, recovery_mode);
        IdentityStatement {
            identity_id: self.identity_id,
            generation,
            root_sig_pub,
            recovery_mode,
            statement_sig: self.root.sign(&material).to_bytes(),
        }
    }

    pub fn certify_device(&self, generation: u64, bundle: &DeviceBundle) -> Sig {
        self.root
            .sign(&device_certificate_material(
                &self.identity_id,
                generation,
                bundle,
            ))
            .to_bytes()
    }

    pub fn avatar_capability(&self, generation: u64) -> Key {
        let mut salt = Vec::with_capacity(ID_LEN + 8);
        salt.extend_from_slice(&self.identity_id);
        salt.extend_from_slice(&generation.to_be_bytes());
        let hk = Hkdf::<Sha256>::new(Some(&salt), &self.root.to_bytes());
        let mut capability = [0u8; KEY_LEN];
        hk.expand(DOMAIN_AVATAR_CAPABILITY, &mut capability)
            .expect("32 bytes is a valid HKDF output length");
        capability
    }

    pub fn sign_avatar_statement(&self, statement: &AvatarStatement) -> Sig {
        self.root
            .sign(&avatar_statement_material(&self.identity_id, statement))
            .to_bytes()
    }

    pub fn sign_lock_recipient(&self, statement: &LockRecipientStatement) -> Sig {
        self.root
            .sign(&lock_recipient_material(statement))
            .to_bytes()
    }

    pub fn lock_recipient_statement(
        &self,
        conversation_id: Id,
        generation: u64,
        recipient_revision: u64,
        recipient: &LockRecipientKeys,
    ) -> LockRecipientStatement {
        let mut statement = LockRecipientStatement {
            conversation_id,
            identity_id: self.identity_id,
            identity_generation: generation,
            recipient_revision,
            lrk_sig_pub: recipient.sig_pub(),
            lrk_kem_pub: recipient.kem_pub(),
            statement_sig: [0; SIG_LEN],
        };
        statement.statement_sig = self.sign_lock_recipient(&statement);
        statement
    }

    pub fn sign_lock_wrapper(
        &self,
        context: &LockWrapperContext,
        salt: &Key,
        wrapped: &[u8],
    ) -> Sig {
        self.root
            .sign(&lock_wrapper_statement_material(context, salt, wrapped))
            .to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvatarStatement {
    pub generation: u64,
    pub revision: u64,
    pub blob_id: Option<Id>,
    pub mime: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub size_bytes: Option<u64>,
    pub sha256: Option<Key>,
    pub capability_commitment: Key,
}

fn push_optional<T>(material: &mut Vec<u8>, value: Option<T>, push: impl FnOnce(&mut Vec<u8>, T)) {
    match value {
        Some(value) => {
            material.push(1);
            push(material, value);
        }
        None => material.push(0),
    }
}

fn avatar_statement_material(identity_id: &Id, statement: &AvatarStatement) -> Vec<u8> {
    let mut material = Vec::with_capacity(256);
    material.extend_from_slice(DOMAIN_AVATAR_STATEMENT);
    material.extend_from_slice(identity_id);
    material.extend_from_slice(&statement.generation.to_be_bytes());
    material.extend_from_slice(&statement.revision.to_be_bytes());
    push_optional(&mut material, statement.blob_id, |out, value| {
        out.extend_from_slice(&value)
    });
    push_optional(&mut material, statement.mime.as_deref(), |out, value| {
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    });
    push_optional(&mut material, statement.width, |out, value| {
        out.extend_from_slice(&value.to_be_bytes())
    });
    push_optional(&mut material, statement.height, |out, value| {
        out.extend_from_slice(&value.to_be_bytes())
    });
    push_optional(&mut material, statement.size_bytes, |out, value| {
        out.extend_from_slice(&value.to_be_bytes())
    });
    push_optional(&mut material, statement.sha256, |out, value| {
        out.extend_from_slice(&value)
    });
    material.extend_from_slice(&statement.capability_commitment);
    material
}

pub fn avatar_capability_commitment(capability: &Key) -> Key {
    let mut digest = Sha256::new();
    digest.update(DOMAIN_AVATAR_COMMITMENT);
    digest.update(capability);
    digest.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedAvatarGrant {
    pub wrapped: Vec<u8>,
    pub grant_sig: Sig,
}

fn avatar_grant_aad(
    owner_identity_id: &Id,
    owner_generation: u64,
    sender_device_id: &Id,
    recipient_device_id: &Id,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN_AVATAR_GRANT.len() + ID_LEN * 3 + 8);
    aad.extend_from_slice(DOMAIN_AVATAR_GRANT);
    aad.extend_from_slice(owner_identity_id);
    aad.extend_from_slice(&owner_generation.to_be_bytes());
    aad.extend_from_slice(sender_device_id);
    aad.extend_from_slice(recipient_device_id);
    aad
}

pub fn seal_avatar_grant(
    rng: &mut (impl CryptoRng + RngCore),
    sender: &DeviceKeys,
    recipient: &DeviceBundle,
    owner_identity_id: &Id,
    owner_generation: u64,
    capability: &Key,
) -> SealedAvatarGrant {
    let eph = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(recipient.kem_pub));
    let key = wrap_key(shared.as_bytes(), &eph_pub, &recipient.kem_pub);
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = avatar_grant_aad(
        owner_identity_id,
        owner_generation,
        sender.device_id(),
        &recipient.device_id,
    );
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: capability,
                aad: &aad,
            },
        )
        .expect("in-memory avatar grant encryption");
    let mut wrapped = Vec::with_capacity(WRAPPED_LEN);
    wrapped.extend_from_slice(&eph_pub);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    let mut signed = aad;
    signed.extend_from_slice(&wrapped);
    SealedAvatarGrant {
        wrapped,
        grant_sig: sender.sig.sign(&signed).to_bytes(),
    }
}

pub fn open_avatar_grant(
    recipient: &DeviceKeys,
    sender: &DeviceBundle,
    owner_identity_id: &Id,
    owner_generation: u64,
    wrapped: &[u8],
    grant_sig: &Sig,
) -> Result<Key, CryptoError> {
    verify_bundle(sender)?;
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::InvalidLength {
            what: "avatar grant",
            expected: WRAPPED_LEN,
            actual: wrapped.len(),
        });
    }
    let aad = avatar_grant_aad(
        owner_identity_id,
        owner_generation,
        &sender.device_id,
        recipient.device_id(),
    );
    let mut signed = aad.clone();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(&sender.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(grant_sig))
        .map_err(|_| CryptoError::InvalidSignature)?;
    let eph_pub: Key = wrapped[..KEY_LEN].try_into().expect("checked length");
    let nonce: Nonce = wrapped[KEY_LEN..KEY_LEN + NONCE_LEN]
        .try_into()
        .expect("checked length");
    let shared = recipient.kem.diffie_hellman(&PublicKey::from(eph_pub));
    let key = wrap_key(shared.as_bytes(), &eph_pub, &recipient.kem_pub());
    XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &wrapped[KEY_LEN + NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?
        .try_into()
        .map_err(|bytes: Vec<u8>| CryptoError::InvalidLength {
            what: "avatar capability",
            expected: KEY_LEN,
            actual: bytes.len(),
        })
}

pub fn verify_avatar_statement(
    identity_id: &Id,
    root_sig_pub: &Key,
    statement: &AvatarStatement,
    signature: &Sig,
) -> Result<(), CryptoError> {
    VerifyingKey::from_bytes(root_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &avatar_statement_material(identity_id, statement),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

pub struct AvatarCipherContext<'a> {
    pub generation: u64,
    pub revision: u64,
    pub blob_id: &'a Id,
    pub mime: &'a str,
    pub width: u32,
    pub height: u32,
}

fn avatar_aad(identity_id: &Id, context: &AvatarCipherContext<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(DOMAIN_AVATAR);
    aad.extend_from_slice(identity_id);
    aad.extend_from_slice(&context.generation.to_be_bytes());
    aad.extend_from_slice(&context.revision.to_be_bytes());
    aad.extend_from_slice(context.blob_id);
    aad.extend_from_slice(&(context.mime.len() as u16).to_be_bytes());
    aad.extend_from_slice(context.mime.as_bytes());
    aad.extend_from_slice(&context.width.to_be_bytes());
    aad.extend_from_slice(&context.height.to_be_bytes());
    aad
}

pub fn encrypt_avatar(
    rng: &mut (impl CryptoRng + RngCore),
    capability: &Key,
    identity_id: &Id,
    context: &AvatarCipherContext<'_>,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(capability.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &avatar_aad(identity_id, context),
            },
        )
        .expect("valid key and nonce");
    let mut bytes = Vec::with_capacity(NONCE_LEN + ct.len());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ct);
    bytes
}

pub fn decrypt_avatar(
    capability: &Key,
    identity_id: &Id,
    context: &AvatarCipherContext<'_>,
    bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if bytes.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    XChaCha20Poly1305::new(capability.into())
        .decrypt(
            XNonce::from_slice(&bytes[..NONCE_LEN]),
            Payload {
                msg: &bytes[NONCE_LEN..],
                aad: &avatar_aad(identity_id, context),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn identity_material(
    identity_id: &Id,
    generation: u64,
    root_sig_pub: &Key,
    recovery_mode: RecoveryMode,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(DOMAIN_IDENTITY.len() + ID_LEN + 8 + KEY_LEN + 1);
    material.extend_from_slice(DOMAIN_IDENTITY);
    material.extend_from_slice(identity_id);
    material.extend_from_slice(&generation.to_be_bytes());
    material.extend_from_slice(root_sig_pub);
    material.push(recovery_mode.byte());
    material
}

pub fn verify_identity_statement(statement: &IdentityStatement) -> Result<(), CryptoError> {
    VerifyingKey::from_bytes(&statement.root_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &identity_material(
                &statement.identity_id,
                statement.generation,
                &statement.root_sig_pub,
                statement.recovery_mode,
            ),
            &Signature::from_bytes(&statement.statement_sig),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

fn device_certificate_material(
    identity_id: &Id,
    generation: u64,
    bundle: &DeviceBundle,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(
        DOMAIN_DEVICE_CERT.len()
            + ID_LEN
            + 8
            + DOMAIN_DEVICE.len()
            + ID_LEN
            + KEY_LEN * 2
            + SIG_LEN,
    );
    material.extend_from_slice(DOMAIN_DEVICE_CERT);
    material.extend_from_slice(identity_id);
    material.extend_from_slice(&generation.to_be_bytes());
    material.extend_from_slice(&bundle_material(
        &bundle.device_id,
        &bundle.sig_pub,
        &bundle.kem_pub,
    ));
    material.extend_from_slice(&bundle.bundle_sig);
    material
}

pub fn verify_device_certificate(
    statement: &IdentityStatement,
    bundle: &DeviceBundle,
    certificate_sig: &Sig,
) -> Result<(), CryptoError> {
    verify_identity_statement(statement)?;
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&statement.root_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &device_certificate_material(&statement.identity_id, statement.generation, bundle),
            &Signature::from_bytes(certificate_sig),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

fn identity_fingerprint_digest(statement: &IdentityStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_IDENTITY_FP);
    h.update(statement.identity_id);
    h.update(statement.generation.to_be_bytes());
    h.update(statement.root_sig_pub);
    h.finalize().into()
}

/// `SHA-256("tychat-identity-fp-v1" || identity_id || generation_be ||
/// root_sig_pub)` rendered by [`fingerprint`]'s display encoding.
pub fn identity_fingerprint(statement: &IdentityStatement) -> String {
    display_fingerprint(&identity_fingerprint_digest(statement))
}

/// Whether `pin`, a spaceless identity fingerprint carried by a public
/// contact link or Contact ID, names `statement`. Accepts the current
/// 24-character base64url form and the 60-digit decimal form that links
/// published before ADR-0001's 2026-10-09 amendment carry.
pub fn identity_fingerprint_matches_pin(statement: &IdentityStatement, pin: &str) -> bool {
    let digest = identity_fingerprint_digest(statement);
    if pin.len() == FINGERPRINT_CHARS && pin.bytes().all(|b| BASE64URL.contains(&b)) {
        return compact_fingerprint(&digest) == pin;
    }
    if pin.len() == LEGACY_FINGERPRINT_DIGITS && pin.bytes().all(|b| b.is_ascii_digit()) {
        return to_decimal_padded(&digest, 78)[..LEGACY_FINGERPRINT_DIGITS] == *pin;
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteDirection {
    Offer,
    Acceptance,
}

impl InviteDirection {
    fn byte(self) -> u8 {
        match self {
            Self::Offer => 0,
            Self::Acceptance => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedInvitePayload {
    pub nonce: Nonce,
    pub ct: Vec<u8>,
}

fn invite_aad(invite_id: &Id, direction: InviteDirection) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN_INVITE.len() + ID_LEN + 1);
    aad.extend_from_slice(DOMAIN_INVITE);
    aad.extend_from_slice(invite_id);
    aad.push(direction.byte());
    aad
}

fn invite_key(secret: &Key, invite_id: &Id) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(invite_id), secret);
    let mut key = [0u8; KEY_LEN];
    hk.expand(DOMAIN_INVITE, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn encrypt_invite_payload(
    rng: &mut (impl CryptoRng + RngCore),
    secret: &Key,
    invite_id: &Id,
    direction: InviteDirection,
    plaintext: &[u8],
) -> EncryptedInvitePayload {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&invite_key(secret, invite_id)).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &invite_aad(invite_id, direction),
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory inputs");
    EncryptedInvitePayload { nonce, ct }
}

pub fn decrypt_invite_payload(
    secret: &Key,
    invite_id: &Id,
    direction: InviteDirection,
    nonce: &Nonce,
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new((&invite_key(secret, invite_id)).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &invite_aad(invite_id, direction),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("{what} has length {actual}, expected {expected}")]
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("recovery vault version is outside the positive u32 range")]
    InvalidRecoveryVersion,
    #[error("public key is not a valid curve point")]
    InvalidKey,
    #[error("signature does not verify")]
    InvalidSignature,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("conversation password is empty or does not match its declared kind")]
    InvalidConversationPassword,
    #[error("conversation lock parameters are invalid")]
    InvalidConversationLock,
    #[error("receipt control is malformed or does not match its authenticated envelope")]
    InvalidReceiptControl,
    #[error("receipt control rolls back an authenticated device horizon")]
    ReceiptRollback,
    #[error("reaction control is malformed or does not match its authenticated envelope")]
    InvalidReactionControl,
    #[error("edit control is malformed or does not match its authenticated envelope")]
    InvalidEditControl,
    #[error("silent control header is malformed")]
    InvalidSilentControl,
    #[error("conversation roster attestation is malformed")]
    InvalidRoster,
}

/// A device's private key material. Never serialised by this crate except via
/// [`DeviceKeys::secret_bytes`], which the client stores in IndexedDB.
#[derive(Clone)]
pub struct DeviceKeys {
    device_id: Id,
    sig: SigningKey,
    kem: StaticSecret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceBundle {
    pub device_id: Id,
    pub sig_pub: [u8; KEY_LEN],
    pub kem_pub: [u8; KEY_LEN],
    pub bundle_sig: Sig,
}

pub struct DeviceRevocation<'a> {
    pub current_identity_id: &'a Id,
    pub current_generation: u64,
    pub target_device_id: &'a Id,
    pub replacement_statement: &'a IdentityStatement,
    pub replacement_bundle: &'a DeviceBundle,
    pub replacement_certificate: &'a Sig,
}

impl DeviceKeys {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut device_id = [0u8; ID_LEN];
        rng.fill_bytes(&mut device_id);
        Self {
            device_id,
            sig: SigningKey::generate(rng),
            kem: StaticSecret::random_from_rng(&mut *rng),
        }
    }

    pub fn from_secret_bytes(device_id: Id, sig_seed: Key, kem_secret: Key) -> Self {
        Self {
            device_id,
            sig: SigningKey::from_bytes(&sig_seed),
            kem: StaticSecret::from(kem_secret),
        }
    }

    pub fn device_id(&self) -> &Id {
        &self.device_id
    }

    /// `(sig_seed, kem_secret)`.
    pub fn secret_bytes(&self) -> (Key, Key) {
        (self.sig.to_bytes(), self.kem.to_bytes())
    }

    pub fn sig_pub(&self) -> [u8; KEY_LEN] {
        self.sig.verifying_key().to_bytes()
    }

    pub fn kem_pub(&self) -> [u8; KEY_LEN] {
        PublicKey::from(&self.kem).to_bytes()
    }

    pub fn bundle(&self) -> DeviceBundle {
        let sig_pub = self.sig_pub();
        let kem_pub = self.kem_pub();
        let material = bundle_material(&self.device_id, &sig_pub, &kem_pub);
        DeviceBundle {
            device_id: self.device_id,
            sig_pub,
            kem_pub,
            bundle_sig: self.sig.sign(&material).to_bytes(),
        }
    }

    pub fn sign_activation(&self, request_id: &Id) -> Sig {
        let mut material = Vec::with_capacity(DOMAIN_DEVICE_ACTIVATION.len() + ID_LEN * 2);
        material.extend_from_slice(DOMAIN_DEVICE_ACTIVATION);
        material.extend_from_slice(request_id);
        material.extend_from_slice(&self.device_id);
        self.sig.sign(&material).to_bytes()
    }

    pub fn sign_roster(
        &self,
        conversation_id: &Id,
        epoch: u64,
        roster: &[u8],
    ) -> Result<Sig, CryptoError> {
        Ok(self
            .sig
            .sign(&roster_material(
                conversation_id,
                epoch,
                &self.device_id,
                roster,
            )?)
            .to_bytes())
    }

    pub fn sign_public_contact_decision(&self, request_id: &Id, approve: bool) -> Sig {
        let mut material =
            Vec::with_capacity(DOMAIN_PUBLIC_CONTACT_DECISION.len() + ID_LEN * 2 + 1);
        material.extend_from_slice(DOMAIN_PUBLIC_CONTACT_DECISION);
        material.extend_from_slice(request_id);
        material.extend_from_slice(&self.device_id);
        material.push(u8::from(approve));
        self.sig.sign(&material).to_bytes()
    }

    pub fn sign_push_subscription(
        &self,
        identity_id: &Id,
        generation: u64,
        endpoint: &[u8],
        p256dh: &[u8],
        auth: &[u8],
    ) -> Sig {
        self.sig
            .sign(&push_subscription_material(
                identity_id,
                generation,
                &self.device_id,
                endpoint,
                p256dh,
                auth,
            ))
            .to_bytes()
    }

    pub fn sign_push_disable(
        &self,
        identity_id: &Id,
        generation: u64,
        subscription_id: &Id,
    ) -> Sig {
        self.sig
            .sign(&push_disable_material(
                DOMAIN_PUSH_DISABLE,
                identity_id,
                generation,
                &self.device_id,
                Some(subscription_id),
            ))
            .to_bytes()
    }

    pub fn sign_push_disable_device(&self, identity_id: &Id, generation: u64) -> Sig {
        self.sig
            .sign(&push_disable_material(
                DOMAIN_PUSH_DISABLE_DEVICE,
                identity_id,
                generation,
                &self.device_id,
                None,
            ))
            .to_bytes()
    }

    pub fn sign_realtime_ticket(
        &self,
        ticket_request_id: &Id,
        client_instance_id: &Id,
        expires_at_epoch_seconds: u64,
    ) -> Sig {
        self.sig
            .sign(&realtime_ticket_material(
                ticket_request_id,
                &self.device_id,
                client_instance_id,
                expires_at_epoch_seconds,
            ))
            .to_bytes()
    }

    pub fn sign_bot_pairing(&self, code_hash: &[u8; 32], identity_id: &Id) -> Sig {
        self.sig
            .sign(&bot_pairing_material(
                code_hash,
                identity_id,
                &self.device_id,
            ))
            .to_bytes()
    }

    pub fn sign_bot_request(
        &self,
        request_id: &Id,
        expires_at_epoch_seconds: u64,
        request: &BotRequest<'_>,
    ) -> Sig {
        self.sig
            .sign(&bot_request_material(
                request_id,
                &self.device_id,
                expires_at_epoch_seconds,
                request,
            ))
            .to_bytes()
    }

    pub fn sign_device_revocation(&self, revocation: &DeviceRevocation<'_>) -> Sig {
        self.sig
            .sign(&device_revocation_material(
                revocation.current_identity_id,
                revocation.current_generation,
                &self.device_id,
                revocation.target_device_id,
                revocation.replacement_statement,
                revocation.replacement_bundle,
                revocation.replacement_certificate,
            ))
            .to_bytes()
    }

    pub fn sign_generation_succession(
        &self,
        old_statement: &IdentityStatement,
        new_statement: &IdentityStatement,
    ) -> Sig {
        self.sig
            .sign(&generation_succession_material(
                old_statement,
                new_statement,
            ))
            .to_bytes()
    }
}

fn generation_succession_material(
    old_statement: &IdentityStatement,
    new_statement: &IdentityStatement,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(DOMAIN_GENERATION_SUCCESSION);
    material.extend_from_slice(&identity_material(
        &old_statement.identity_id,
        old_statement.generation,
        &old_statement.root_sig_pub,
        old_statement.recovery_mode,
    ));
    material.extend_from_slice(&old_statement.statement_sig);
    material.extend_from_slice(&identity_material(
        &new_statement.identity_id,
        new_statement.generation,
        &new_statement.root_sig_pub,
        new_statement.recovery_mode,
    ));
    material.extend_from_slice(&new_statement.statement_sig);
    material
}

pub fn verify_generation_succession(
    old_statement: &IdentityStatement,
    new_statement: &IdentityStatement,
    authorizing_bundle: &DeviceBundle,
    authorizing_certificate: &Sig,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_identity_statement(old_statement)?;
    verify_identity_statement(new_statement)?;
    if old_statement.identity_id != new_statement.identity_id
        || new_statement.generation != old_statement.generation.checked_add(1).unwrap_or(0)
        || old_statement.root_sig_pub == new_statement.root_sig_pub
    {
        return Err(CryptoError::InvalidSignature);
    }
    verify_device_certificate(old_statement, authorizing_bundle, authorizing_certificate)?;
    VerifyingKey::from_bytes(&authorizing_bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &generation_succession_material(old_statement, new_statement),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

fn device_revocation_material(
    current_identity_id: &Id,
    current_generation: u64,
    authorizing_device_id: &Id,
    target_device_id: &Id,
    replacement_statement: &IdentityStatement,
    replacement_bundle: &DeviceBundle,
    replacement_certificate: &Sig,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(DOMAIN_DEVICE_REVOCATION);
    material.extend_from_slice(current_identity_id);
    material.extend_from_slice(&current_generation.to_be_bytes());
    material.extend_from_slice(authorizing_device_id);
    material.extend_from_slice(target_device_id);
    material.extend_from_slice(&identity_material(
        &replacement_statement.identity_id,
        replacement_statement.generation,
        &replacement_statement.root_sig_pub,
        replacement_statement.recovery_mode,
    ));
    material.extend_from_slice(&replacement_statement.statement_sig);
    material.extend_from_slice(&bundle_material(
        &replacement_bundle.device_id,
        &replacement_bundle.sig_pub,
        &replacement_bundle.kem_pub,
    ));
    material.extend_from_slice(&replacement_bundle.bundle_sig);
    material.extend_from_slice(replacement_certificate);
    material
}

pub fn verify_device_revocation(
    authorizing_bundle: &DeviceBundle,
    revocation: &DeviceRevocation<'_>,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(authorizing_bundle)?;
    VerifyingKey::from_bytes(&authorizing_bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &device_revocation_material(
                revocation.current_identity_id,
                revocation.current_generation,
                &authorizing_bundle.device_id,
                revocation.target_device_id,
                revocation.replacement_statement,
                revocation.replacement_bundle,
                revocation.replacement_certificate,
            ),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_device_activation(
    bundle: &DeviceBundle,
    request_id: &Id,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    let mut material = Vec::with_capacity(DOMAIN_DEVICE_ACTIVATION.len() + ID_LEN * 2);
    material.extend_from_slice(DOMAIN_DEVICE_ACTIVATION);
    material.extend_from_slice(request_id);
    material.extend_from_slice(&bundle.device_id);
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&material, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_public_contact_decision(
    bundle: &DeviceBundle,
    request_id: &Id,
    approve: bool,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    let mut material = Vec::with_capacity(DOMAIN_PUBLIC_CONTACT_DECISION.len() + ID_LEN * 2 + 1);
    material.extend_from_slice(DOMAIN_PUBLIC_CONTACT_DECISION);
    material.extend_from_slice(request_id);
    material.extend_from_slice(&bundle.device_id);
    material.push(u8::from(approve));
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&material, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)
}

fn push_subscription_material(
    identity_id: &Id,
    generation: u64,
    device_id: &Id,
    endpoint: &[u8],
    p256dh: &[u8],
    auth: &[u8],
) -> Vec<u8> {
    let mut material = Vec::with_capacity(
        DOMAIN_PUSH_SUBSCRIPTION.len()
            + ID_LEN * 2
            + 8
            + 4
            + endpoint.len()
            + p256dh.len()
            + auth.len(),
    );
    material.extend_from_slice(DOMAIN_PUSH_SUBSCRIPTION);
    material.extend_from_slice(identity_id);
    material.extend_from_slice(&generation.to_be_bytes());
    material.extend_from_slice(device_id);
    material.extend_from_slice(&(endpoint.len() as u32).to_be_bytes());
    material.extend_from_slice(endpoint);
    material.extend_from_slice(p256dh);
    material.extend_from_slice(auth);
    material
}

fn push_disable_material(
    domain: &[u8],
    identity_id: &Id,
    generation: u64,
    device_id: &Id,
    subscription_id: Option<&Id>,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(domain.len() + ID_LEN * 3 + 8);
    material.extend_from_slice(domain);
    material.extend_from_slice(identity_id);
    material.extend_from_slice(&generation.to_be_bytes());
    material.extend_from_slice(device_id);
    if let Some(subscription_id) = subscription_id {
        material.extend_from_slice(subscription_id);
    }
    material
}

pub fn verify_push_subscription(
    bundle: &DeviceBundle,
    identity_id: &Id,
    generation: u64,
    endpoint: &[u8],
    p256dh: &[u8],
    auth: &[u8],
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &push_subscription_material(
                identity_id,
                generation,
                &bundle.device_id,
                endpoint,
                p256dh,
                auth,
            ),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_push_disable(
    bundle: &DeviceBundle,
    identity_id: &Id,
    generation: u64,
    subscription_id: &Id,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &push_disable_material(
                DOMAIN_PUSH_DISABLE,
                identity_id,
                generation,
                &bundle.device_id,
                Some(subscription_id),
            ),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_push_disable_device(
    bundle: &DeviceBundle,
    identity_id: &Id,
    generation: u64,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &push_disable_material(
                DOMAIN_PUSH_DISABLE_DEVICE,
                identity_id,
                generation,
                &bundle.device_id,
                None,
            ),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

fn realtime_ticket_material(
    ticket_request_id: &Id,
    device_id: &Id,
    client_instance_id: &Id,
    expires_at_epoch_seconds: u64,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(DOMAIN_REALTIME_TICKET.len() + ID_LEN * 3 + 8);
    material.extend_from_slice(DOMAIN_REALTIME_TICKET);
    material.extend_from_slice(ticket_request_id);
    material.extend_from_slice(device_id);
    material.extend_from_slice(client_instance_id);
    material.extend_from_slice(&expires_at_epoch_seconds.to_be_bytes());
    material
}

pub fn verify_realtime_ticket(
    bundle: &DeviceBundle,
    ticket_request_id: &Id,
    client_instance_id: &Id,
    expires_at_epoch_seconds: u64,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &realtime_ticket_material(
                ticket_request_id,
                &bundle.device_id,
                client_instance_id,
                expires_at_epoch_seconds,
            ),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

pub struct BotRequest<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub body: &'a [u8],
}

fn bot_pairing_material(code_hash: &[u8; 32], identity_id: &Id, device_id: &Id) -> Vec<u8> {
    let mut material = Vec::with_capacity(DOMAIN_BOT_PAIRING.len() + 32 + ID_LEN * 2);
    material.extend_from_slice(DOMAIN_BOT_PAIRING);
    material.extend_from_slice(code_hash);
    material.extend_from_slice(identity_id);
    material.extend_from_slice(device_id);
    material
}

fn bot_request_material(
    request_id: &Id,
    device_id: &Id,
    expires_at_epoch_seconds: u64,
    request: &BotRequest<'_>,
) -> Vec<u8> {
    let body_hash = Sha256::digest(request.body);
    let mut target = Sha256::new();
    target.update(request.method.as_bytes());
    target.update(b"\n");
    target.update(request.path_and_query.as_bytes());
    target.update(b"\n");
    for byte in body_hash {
        target.update([HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]]);
    }
    let mut material = Vec::with_capacity(DOMAIN_BOT_REQUEST.len() + ID_LEN * 2 + 8 + 32);
    material.extend_from_slice(DOMAIN_BOT_REQUEST);
    material.extend_from_slice(request_id);
    material.extend_from_slice(device_id);
    material.extend_from_slice(&expires_at_epoch_seconds.to_be_bytes());
    material.extend_from_slice(&target.finalize());
    material
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn verify_bot_pairing(
    bundle: &DeviceBundle,
    code_hash: &[u8; 32],
    identity_id: &Id,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &bot_pairing_material(code_hash, identity_id, &bundle.device_id),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_bot_request(
    bundle: &DeviceBundle,
    request_id: &Id,
    expires_at_epoch_seconds: u64,
    request: &BotRequest<'_>,
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_bundle(bundle)?;
    VerifyingKey::from_bytes(&bundle.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &bot_request_material(
                request_id,
                &bundle.device_id,
                expires_at_epoch_seconds,
                request,
            ),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

fn bundle_material(device_id: &Id, sig_pub: &[u8; KEY_LEN], kem_pub: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN_DEVICE.len() + ID_LEN + KEY_LEN * 2);
    m.extend_from_slice(DOMAIN_DEVICE);
    m.extend_from_slice(device_id);
    m.extend_from_slice(sig_pub);
    m.extend_from_slice(kem_pub);
    m
}

pub fn verify_bundle(bundle: &DeviceBundle) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(&bundle.sig_pub).map_err(|_| CryptoError::InvalidKey)?;
    let material = bundle_material(&bundle.device_id, &bundle.sig_pub, &bundle.kem_pub);
    key.verify_strict(&material, &Signature::from_bytes(&bundle.bundle_sig))
        .map_err(|_| CryptoError::InvalidSignature)
}

fn roster_material(
    conversation_id: &Id,
    epoch: u64,
    signer_device_id: &Id,
    roster: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let roster = canonical_roster(roster)?;
    let mut material = Vec::with_capacity(DOMAIN_ROSTER.len() + ID_LEN * 2 + 8 + 8 + roster.len());
    material.extend_from_slice(DOMAIN_ROSTER);
    material.extend_from_slice(conversation_id);
    material.extend_from_slice(&epoch.to_be_bytes());
    material.extend_from_slice(signer_device_id);
    material.extend_from_slice(&(roster.len() as u64).to_be_bytes());
    material.extend_from_slice(&roster);
    Ok(material)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RosterIdentityWire {
    identity_id: String,
    generation: u64,
    root_sig_pub: String,
    recovery_mode: RecoveryMode,
    statement_sig: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RosterMemberWire {
    account_id: String,
    identity: RosterIdentityWire,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterWire {
    v: u8,
    members: Vec<RosterMemberWire>,
}

pub fn canonical_roster(roster: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if roster.is_empty() || roster.len() > 256 * 1024 {
        return Err(CryptoError::InvalidRoster);
    }
    let mut wire: RosterWire =
        serde_json::from_slice(roster).map_err(|_| CryptoError::InvalidRoster)?;
    if wire.v != 1 || wire.members.is_empty() || wire.members.len() > 64 {
        return Err(CryptoError::InvalidRoster);
    }
    wire.members.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    if wire
        .members
        .windows(2)
        .any(|pair| pair[0].account_id == pair[1].account_id)
        || wire
            .members
            .iter()
            .any(|member| !valid_account_id(&member.account_id))
    {
        return Err(CryptoError::InvalidRoster);
    }
    serde_json::to_vec(&wire).map_err(|_| CryptoError::InvalidRoster)
}

pub fn verify_roster(
    sig_pub: &Key,
    conversation_id: &Id,
    epoch: u64,
    signer_device_id: &Id,
    roster: &[u8],
    signature: &Sig,
) -> Result<(), CryptoError> {
    VerifyingKey::from_bytes(sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &roster_material(conversation_id, epoch, signer_device_id, roster)?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

/// `SHA-256("tychat-fp-v1" || sig_pub || kem_pub)` displayed as its first
/// 18 bytes in unpadded base64url: 24 characters in 6 groups of 4.
pub fn fingerprint(sig_pub: &[u8; KEY_LEN], kem_pub: &[u8; KEY_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(DOMAIN_FP);
    h.update(sig_pub);
    h.update(kem_pub);
    display_fingerprint(&h.finalize().into())
}

const FINGERPRINT_BYTES: usize = 18;
const FINGERPRINT_CHARS: usize = FINGERPRINT_BYTES / 3 * 4;
const FINGERPRINT_GROUP: usize = 4;
const LEGACY_FINGERPRINT_DIGITS: usize = 60;
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn compact_fingerprint(digest: &[u8; 32]) -> String {
    let mut chars = String::with_capacity(FINGERPRINT_CHARS);
    for [a, b, c] in digest[..FINGERPRINT_BYTES].as_chunks::<3>().0 {
        let n = (u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c);
        for shift in [18, 12, 6, 0] {
            chars.push(char::from(BASE64URL[((n >> shift) & 63) as usize]));
        }
    }
    chars
}

fn display_fingerprint(digest: &[u8; 32]) -> String {
    let compact = compact_fingerprint(digest);
    compact
        .as_bytes()
        .chunks(FINGERPRINT_GROUP)
        .map(|c| std::str::from_utf8(c).expect("ascii base64url"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn to_decimal_padded(bytes: &[u8], width: usize) -> String {
    let mut n = bytes.to_vec();
    let mut digits = Vec::new();
    while n.iter().any(|&b| b != 0) {
        let mut rem: u32 = 0;
        for b in n.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    while digits.len() < width {
        digits.push(b'0');
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

pub fn generate_epoch_key(rng: &mut (impl CryptoRng + RngCore)) -> Key {
    let mut k = [0u8; KEY_LEN];
    rng.fill_bytes(&mut k);
    k
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedDeviceTransfer {
    pub wrapped: Vec<u8>,
    pub signature: Sig,
}

fn transfer_aad(request_id: &Id, sender_device_id: &Id, recipient_device_id: &Id) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN_DEVICE_TRANSFER.len() + ID_LEN * 3);
    aad.extend_from_slice(DOMAIN_DEVICE_TRANSFER);
    aad.extend_from_slice(request_id);
    aad.extend_from_slice(sender_device_id);
    aad.extend_from_slice(recipient_device_id);
    aad
}

pub fn seal_device_transfer(
    rng: &mut (impl CryptoRng + RngCore),
    sender: &DeviceKeys,
    recipient: &DeviceBundle,
    request_id: &Id,
    plaintext: &[u8],
) -> SealedDeviceTransfer {
    let eph = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(recipient.kem_pub));
    let key = wrap_key(shared.as_bytes(), &eph_pub, &recipient.kem_pub);
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = transfer_aad(request_id, sender.device_id(), &recipient.device_id);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("in-memory transfer encryption");
    let mut wrapped = Vec::with_capacity(KEY_LEN + NONCE_LEN + ct.len());
    wrapped.extend_from_slice(&eph_pub);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    let mut signed = aad;
    signed.extend_from_slice(&wrapped);
    SealedDeviceTransfer {
        wrapped,
        signature: sender.sig.sign(&signed).to_bytes(),
    }
}

pub fn open_device_transfer(
    recipient: &DeviceKeys,
    sender: &DeviceBundle,
    request_id: &Id,
    wrapped: &[u8],
    signature: &Sig,
) -> Result<Vec<u8>, CryptoError> {
    verify_bundle(sender)?;
    if wrapped.len() < KEY_LEN + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidLength {
            what: "device transfer",
            expected: KEY_LEN + NONCE_LEN + TAG_LEN,
            actual: wrapped.len(),
        });
    }
    let aad = transfer_aad(request_id, &sender.device_id, recipient.device_id());
    let mut signed = aad.clone();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(&sender.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)?;
    let eph_pub: Key = wrapped[..KEY_LEN].try_into().expect("checked length");
    let nonce: Nonce = wrapped[KEY_LEN..KEY_LEN + NONCE_LEN]
        .try_into()
        .expect("checked length");
    let shared = recipient.kem.diffie_hellman(&PublicKey::from(eph_pub));
    let key = wrap_key(shared.as_bytes(), &eph_pub, &recipient.kem_pub());
    XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &wrapped[KEY_LEN + NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn public_contact_aad(
    doorway_id: &Id,
    request_id: &Id,
    sender_device_id: &Id,
    recipient_device_id: &Id,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN_PUBLIC_CONTACT.len() + ID_LEN * 4);
    aad.extend_from_slice(DOMAIN_PUBLIC_CONTACT);
    aad.extend_from_slice(doorway_id);
    aad.extend_from_slice(request_id);
    aad.extend_from_slice(sender_device_id);
    aad.extend_from_slice(recipient_device_id);
    aad
}

fn public_contact_key(
    shared: &[u8; KEY_LEN],
    eph_pub: &[u8; KEY_LEN],
    recipient_kem_pub: &[u8; KEY_LEN],
) -> Key {
    let mut salt = [0_u8; KEY_LEN * 2];
    salt[..KEY_LEN].copy_from_slice(eph_pub);
    salt[KEY_LEN..].copy_from_slice(recipient_kem_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0_u8; KEY_LEN];
    hk.expand(DOMAIN_PUBLIC_CONTACT, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn seal_public_contact_request(
    rng: &mut (impl CryptoRng + RngCore),
    sender: &DeviceKeys,
    recipient: &DeviceBundle,
    doorway_id: &Id,
    request_id: &Id,
    plaintext: &[u8],
) -> SealedDeviceTransfer {
    let eph = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(recipient.kem_pub));
    let key = public_contact_key(shared.as_bytes(), &eph_pub, &recipient.kem_pub);
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = public_contact_aad(
        doorway_id,
        request_id,
        sender.device_id(),
        &recipient.device_id,
    );
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("in-memory public contact encryption");
    let mut wrapped = Vec::with_capacity(KEY_LEN + NONCE_LEN + ct.len());
    wrapped.extend_from_slice(&eph_pub);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    let mut signed = aad;
    signed.extend_from_slice(&wrapped);
    SealedDeviceTransfer {
        wrapped,
        signature: sender.sig.sign(&signed).to_bytes(),
    }
}

pub fn open_public_contact_request(
    recipient: &DeviceKeys,
    sender: &DeviceBundle,
    doorway_id: &Id,
    request_id: &Id,
    wrapped: &[u8],
    signature: &Sig,
) -> Result<Vec<u8>, CryptoError> {
    verify_bundle(sender)?;
    if wrapped.len() < KEY_LEN + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidLength {
            what: "public contact request",
            expected: KEY_LEN + NONCE_LEN + TAG_LEN,
            actual: wrapped.len(),
        });
    }
    let aad = public_contact_aad(
        doorway_id,
        request_id,
        &sender.device_id,
        recipient.device_id(),
    );
    let mut signed = aad.clone();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(&sender.sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)?;
    let eph_pub: Key = wrapped[..KEY_LEN].try_into().expect("checked length");
    let nonce: Nonce = wrapped[KEY_LEN..KEY_LEN + NONCE_LEN]
        .try_into()
        .expect("checked length");
    let shared = recipient.kem.diffie_hellman(&PublicKey::from(eph_pub));
    let key = public_contact_key(shared.as_bytes(), &eph_pub, &recipient.kem_pub());
    XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &wrapped[KEY_LEN + NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[derive(Clone)]
pub struct LockRecipientKeys {
    sig: SigningKey,
    kem: StaticSecret,
}

impl LockRecipientKeys {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            sig: SigningKey::generate(rng),
            kem: StaticSecret::random_from_rng(&mut *rng),
        }
    }

    pub fn from_secret_bytes(sig_seed: Key, kem_secret: Key) -> Self {
        Self {
            sig: SigningKey::from_bytes(&sig_seed),
            kem: StaticSecret::from(kem_secret),
        }
    }

    pub fn secret_bytes(&self) -> (Key, Key) {
        (self.sig.to_bytes(), self.kem.to_bytes())
    }

    pub fn sig_pub(&self) -> Key {
        self.sig.verifying_key().to_bytes()
    }

    pub fn kem_pub(&self) -> Key {
        PublicKey::from(&self.kem).to_bytes()
    }

    pub fn sign_proof(&self, context: &LockProofContext) -> Sig {
        self.sig.sign(&lock_proof_material(context)).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRecipientStatement {
    pub conversation_id: Id,
    pub identity_id: Id,
    pub identity_generation: u64,
    pub recipient_revision: u64,
    pub lrk_sig_pub: Key,
    pub lrk_kem_pub: Key,
    pub statement_sig: Sig,
}

fn lock_recipient_material(statement: &LockRecipientStatement) -> Vec<u8> {
    let mut material = Vec::with_capacity(DOMAIN_LOCK_RECIPIENT.len() + ID_LEN * 2 + 80);
    material.extend_from_slice(DOMAIN_LOCK_RECIPIENT);
    material.extend_from_slice(&statement.conversation_id);
    material.extend_from_slice(&statement.identity_id);
    material.extend_from_slice(&statement.identity_generation.to_be_bytes());
    material.extend_from_slice(&statement.recipient_revision.to_be_bytes());
    material.extend_from_slice(&statement.lrk_sig_pub);
    material.extend_from_slice(&statement.lrk_kem_pub);
    material
}

pub fn verify_lock_recipient_statement(
    root_sig_pub: &Key,
    statement: &LockRecipientStatement,
) -> Result<(), CryptoError> {
    if statement.recipient_revision == 0 {
        return Err(CryptoError::InvalidConversationLock);
    }
    VerifyingKey::from_bytes(root_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &lock_recipient_material(statement),
            &Signature::from_bytes(&statement.statement_sig),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockWrapperContext {
    pub recipient: LockRecipientStatement,
    pub lock_revision: u64,
    pub wrapper_revision: u64,
    pub password_kind: PasswordKind,
}

fn lock_wrapper_aad(context: &LockWrapperContext, salt: &Key) -> Vec<u8> {
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(DOMAIN_LOCK_WRAPPER);
    aad.extend_from_slice(&lock_recipient_material(&context.recipient));
    aad.extend_from_slice(&context.lock_revision.to_be_bytes());
    aad.extend_from_slice(&context.wrapper_revision.to_be_bytes());
    aad.push(context.password_kind.byte());
    aad.extend_from_slice(&LOCK_KDF_MEMORY_KIB.to_be_bytes());
    aad.extend_from_slice(&LOCK_KDF_ITERATIONS.to_be_bytes());
    aad.extend_from_slice(&LOCK_KDF_LANES.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn lock_wrapper_statement_material(
    context: &LockWrapperContext,
    salt: &Key,
    wrapped: &[u8],
) -> Vec<u8> {
    let mut material = lock_wrapper_aad(context, salt);
    material.extend_from_slice(wrapped);
    material
}

pub fn verify_lock_wrapper_statement(
    root_sig_pub: &Key,
    context: &LockWrapperContext,
    salt: &Key,
    wrapped: &[u8],
    signature: &Sig,
) -> Result<(), CryptoError> {
    verify_lock_recipient_statement(root_sig_pub, &context.recipient)?;
    if context.lock_revision == 0
        || context.wrapper_revision == 0
        || wrapped.len() != LOCK_WRAPPED_LEN
    {
        return Err(CryptoError::InvalidConversationLock);
    }
    VerifyingKey::from_bytes(root_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &lock_wrapper_statement_material(context, salt, wrapped),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

fn validate_password(password: &[u8], kind: PasswordKind) -> Result<(), CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::InvalidConversationPassword);
    }
    let is_pin = password.len() == 6 && password.iter().all(u8::is_ascii_digit);
    if (kind == PasswordKind::Pin6) != is_pin {
        return Err(CryptoError::InvalidConversationPassword);
    }
    Ok(())
}

fn derive_lock_wrapper_key(
    password: &[u8],
    kind: PasswordKind,
    salt: &Key,
) -> Result<Key, CryptoError> {
    validate_password(password, kind)?;
    let params = Params::new(
        LOCK_KDF_MEMORY_KIB,
        LOCK_KDF_ITERATIONS,
        LOCK_KDF_LANES,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidConversationLock)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::InvalidConversationLock)?;
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedLockRecipient {
    pub salt: Key,
    pub wrapped: Vec<u8>,
}

pub fn wrap_lock_recipient(
    rng: &mut (impl CryptoRng + RngCore),
    password: &[u8],
    context: &LockWrapperContext,
    recipient: &LockRecipientKeys,
) -> Result<WrappedLockRecipient, CryptoError> {
    if recipient.sig_pub() != context.recipient.lrk_sig_pub
        || recipient.kem_pub() != context.recipient.lrk_kem_pub
    {
        return Err(CryptoError::InvalidConversationLock);
    }
    let mut salt = [0_u8; KEY_LEN];
    rng.fill_bytes(&mut salt);
    let key = derive_lock_wrapper_key(password, context.password_kind, &salt)?;
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let (sig_seed, kem_secret) = recipient.secret_bytes();
    let mut plaintext = [0_u8; KEY_LEN * 2];
    plaintext[..KEY_LEN].copy_from_slice(&sig_seed);
    plaintext[KEY_LEN..].copy_from_slice(&kem_secret);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &lock_wrapper_aad(context, &salt),
            },
        )
        .expect("in-memory LRK wrapping");
    let mut wrapped = Vec::with_capacity(LOCK_WRAPPED_LEN);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    Ok(WrappedLockRecipient { salt, wrapped })
}

pub fn open_lock_recipient(
    password: &[u8],
    context: &LockWrapperContext,
    salt: &Key,
    wrapped: &[u8],
) -> Result<LockRecipientKeys, CryptoError> {
    if wrapped.len() != LOCK_WRAPPED_LEN {
        return Err(CryptoError::InvalidLength {
            what: "wrapped lock recipient",
            expected: LOCK_WRAPPED_LEN,
            actual: wrapped.len(),
        });
    }
    let key = derive_lock_wrapper_key(password, context.password_kind, salt)?;
    let plaintext = XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&wrapped[..NONCE_LEN]),
            Payload {
                msg: &wrapped[NONCE_LEN..],
                aad: &lock_wrapper_aad(context, salt),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    if plaintext.len() != KEY_LEN * 2 {
        return Err(CryptoError::DecryptionFailed);
    }
    let recipient = LockRecipientKeys::from_secret_bytes(
        plaintext[..KEY_LEN].try_into().expect("checked length"),
        plaintext[KEY_LEN..].try_into().expect("checked length"),
    );
    if recipient.sig_pub() != context.recipient.lrk_sig_pub
        || recipient.kem_pub() != context.recipient.lrk_kem_pub
    {
        return Err(CryptoError::DecryptionFailed);
    }
    Ok(recipient)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockProofContext {
    pub conversation_id: Id,
    pub identity_id: Id,
    pub lock_revision: u64,
    pub action: u8,
    pub payload_digest: Key,
}

fn lock_proof_material(context: &LockProofContext) -> Vec<u8> {
    let mut material = Vec::with_capacity(DOMAIN_LOCK_PROOF.len() + ID_LEN * 2 + 41);
    material.extend_from_slice(DOMAIN_LOCK_PROOF);
    material.extend_from_slice(&context.conversation_id);
    material.extend_from_slice(&context.identity_id);
    material.extend_from_slice(&context.lock_revision.to_be_bytes());
    material.push(context.action);
    material.extend_from_slice(&context.payload_digest);
    material
}

pub fn verify_lock_proof(
    lrk_sig_pub: &Key,
    context: &LockProofContext,
    signature: &Sig,
) -> Result<(), CryptoError> {
    VerifyingKey::from_bytes(lrk_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(
            &lock_proof_material(context),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockGrantContext {
    pub conversation_id: Id,
    pub epoch: u64,
    pub sender_device_id: Id,
    pub recipient_identity_id: Id,
    pub recipient_revision: u64,
    pub recipient_statement_digest: Key,
}

impl LockGrantContext {
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(DOMAIN_LOCK_GRANT.len() + ID_LEN * 3 + 48);
        aad.extend_from_slice(DOMAIN_LOCK_GRANT);
        aad.extend_from_slice(&self.conversation_id);
        aad.extend_from_slice(&self.epoch.to_be_bytes());
        aad.extend_from_slice(&self.sender_device_id);
        aad.extend_from_slice(&self.recipient_identity_id);
        aad.extend_from_slice(&self.recipient_revision.to_be_bytes());
        aad.extend_from_slice(&self.recipient_statement_digest);
        aad
    }
}

pub fn lock_recipient_statement_digest(statement: &LockRecipientStatement) -> Key {
    sha256(&lock_recipient_material(statement))
}

fn lock_grant_wrap_key(shared: &Key, eph_pub: &Key, recipient_kem_pub: &Key) -> Key {
    let mut salt = [0_u8; KEY_LEN * 2];
    salt[..KEY_LEN].copy_from_slice(eph_pub);
    salt[KEY_LEN..].copy_from_slice(recipient_kem_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0_u8; KEY_LEN];
    hk.expand(DOMAIN_LOCK_GRANT, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn seal_lock_grant(
    rng: &mut (impl CryptoRng + RngCore),
    sender: &DeviceKeys,
    recipient_kem_pub: &Key,
    context: &LockGrantContext,
    epoch_key: &Key,
) -> SealedGrant {
    let eph = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_kem_pub));
    let key = lock_grant_wrap_key(shared.as_bytes(), &eph_pub, recipient_kem_pub);
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = context.aad();
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: epoch_key,
                aad: &aad,
            },
        )
        .expect("in-memory lock grant encryption");
    let mut wrapped = Vec::with_capacity(WRAPPED_LEN);
    wrapped.extend_from_slice(&eph_pub);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    let mut signed = aad;
    signed.extend_from_slice(&wrapped);
    SealedGrant {
        wrapped,
        grant_sig: sender.sig.sign(&signed).to_bytes(),
    }
}

pub fn open_lock_grant(
    recipient: &LockRecipientKeys,
    sender_sig_pub: &Key,
    context: &LockGrantContext,
    wrapped: &[u8],
    grant_sig: &Sig,
) -> Result<Key, CryptoError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::InvalidLength {
            what: "wrapped lock grant",
            expected: WRAPPED_LEN,
            actual: wrapped.len(),
        });
    }
    let aad = context.aad();
    let mut signed = aad.clone();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(sender_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(grant_sig))
        .map_err(|_| CryptoError::InvalidSignature)?;
    let eph_pub: Key = wrapped[..KEY_LEN].try_into().expect("checked length");
    let recipient_kem_pub = recipient.kem_pub();
    let shared = recipient.kem.diffie_hellman(&PublicKey::from(eph_pub));
    let key = lock_grant_wrap_key(shared.as_bytes(), &eph_pub, &recipient_kem_pub);
    let plaintext = XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&wrapped[KEY_LEN..KEY_LEN + NONCE_LEN]),
            Payload {
                msg: &wrapped[KEY_LEN + NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    plaintext
        .try_into()
        .map_err(|value: Vec<u8>| CryptoError::InvalidLength {
            what: "lock grant epoch key",
            expected: KEY_LEN,
            actual: value.len(),
        })
}

pub fn verify_lock_grant(
    sender_sig_pub: &Key,
    context: &LockGrantContext,
    wrapped: &[u8],
    grant_sig: &Sig,
) -> Result<(), CryptoError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::InvalidLength {
            what: "wrapped lock grant",
            expected: WRAPPED_LEN,
            actual: wrapped.len(),
        });
    }
    let mut signed = context.aad();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(sender_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(grant_sig))
        .map_err(|_| CryptoError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantContext {
    pub conversation_id: Id,
    pub epoch: u64,
    pub sender_device_id: Id,
    pub recipient_device_id: Id,
}

impl GrantContext {
    fn aad(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(DOMAIN_GRANT.len() + ID_LEN * 3 + 8);
        a.extend_from_slice(DOMAIN_GRANT);
        a.extend_from_slice(&self.conversation_id);
        a.extend_from_slice(&self.epoch.to_be_bytes());
        a.extend_from_slice(&self.sender_device_id);
        a.extend_from_slice(&self.recipient_device_id);
        a
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedGrant {
    pub wrapped: Vec<u8>,
    pub grant_sig: Sig,
}

fn wrap_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_kem_pub: &[u8; 32]) -> Key {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recipient_kem_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(DOMAIN_GRANT, &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    okm
}

pub fn seal_grant(
    rng: &mut (impl CryptoRng + RngCore),
    sender: &DeviceKeys,
    recipient_kem_pub: &[u8; KEY_LEN],
    ctx: &GrantContext,
    epoch_key: &Key,
) -> SealedGrant {
    let eph = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_kem_pub));
    let wk = wrap_key(shared.as_bytes(), &eph_pub, recipient_kem_pub);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = ctx.aad();
    let ct = XChaCha20Poly1305::new((&wk).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: epoch_key,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory inputs");
    let mut wrapped = Vec::with_capacity(WRAPPED_LEN);
    wrapped.extend_from_slice(&eph_pub);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    let mut signed = aad;
    signed.extend_from_slice(&wrapped);
    SealedGrant {
        wrapped,
        grant_sig: sender.sig.sign(&signed).to_bytes(),
    }
}

pub fn open_grant(
    recipient: &DeviceKeys,
    sender_sig_pub: &[u8; KEY_LEN],
    ctx: &GrantContext,
    wrapped: &[u8],
    grant_sig: &Sig,
) -> Result<Key, CryptoError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::InvalidLength {
            what: "wrapped grant",
            expected: WRAPPED_LEN,
            actual: wrapped.len(),
        });
    }
    let aad = ctx.aad();
    let mut signed = aad.clone();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(sender_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(grant_sig))
        .map_err(|_| CryptoError::InvalidSignature)?;

    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&wrapped[..32]);
    let nonce = &wrapped[32..32 + NONCE_LEN];
    let ct = &wrapped[32 + NONCE_LEN..];
    let recipient_kem_pub = recipient.kem_pub();
    let shared = recipient.kem.diffie_hellman(&PublicKey::from(eph_pub));
    let wk = wrap_key(shared.as_bytes(), &eph_pub, &recipient_kem_pub);
    let pt = XChaCha20Poly1305::new((&wk).into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let mut key = [0u8; KEY_LEN];
    if pt.len() != KEY_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    key.copy_from_slice(&pt);
    Ok(key)
}

pub fn verify_grant(
    sender_sig_pub: &Key,
    context: &GrantContext,
    wrapped: &[u8],
    grant_sig: &Sig,
) -> Result<(), CryptoError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::InvalidLength {
            what: "wrapped grant",
            expected: WRAPPED_LEN,
            actual: wrapped.len(),
        });
    }
    let mut signed = context.aad();
    signed.extend_from_slice(wrapped);
    VerifyingKey::from_bytes(sender_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(grant_sig))
        .map_err(|_| CryptoError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageContext {
    pub conversation_id: Id,
    pub message_id: Id,
    pub epoch: u64,
    pub sender_device_id: Id,
    pub silent_control: bool,
}

impl MessageContext {
    fn aad(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(DOMAIN_MSG.len() + ID_LEN * 3 + 8);
        a.extend_from_slice(DOMAIN_MSG);
        a.extend_from_slice(&self.conversation_id);
        a.extend_from_slice(&self.message_id);
        a.extend_from_slice(&self.epoch.to_be_bytes());
        a.extend_from_slice(&self.sender_device_id);
        a
    }
}

pub fn message_silent_control(nonce: &[u8]) -> Result<bool, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidLength {
            what: "nonce",
            expected: NONCE_LEN,
            actual: nonce.len(),
        });
    }
    Ok(nonce.starts_with(MESSAGE_SILENT_NONCE_PREFIX))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: Nonce,
    pub ct: Vec<u8>,
    pub msg_sig: Sig,
}

pub fn encrypt_message(
    rng: &mut (impl CryptoRng + RngCore),
    epoch_key: &Key,
    sender: &DeviceKeys,
    ctx: &MessageContext,
    body: &[u8],
) -> EncryptedMessage {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    nonce[..8].copy_from_slice(if ctx.silent_control {
        MESSAGE_SILENT_NONCE_PREFIX
    } else {
        MESSAGE_CONTENT_NONCE_PREFIX
    });
    let aad = ctx.aad();
    let encrypted = XChaCha20Poly1305::new(epoch_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory inputs");
    let mut signed = aad;
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&encrypted);
    EncryptedMessage {
        nonce,
        ct: encrypted,
        msg_sig: sender.sig.sign(&signed).to_bytes(),
    }
}

/// Verifies the sender signature **before** decrypting: the shared epoch key
/// proves membership, the signature proves who.
pub fn decrypt_message(
    epoch_key: &Key,
    sender_sig_pub: &[u8; KEY_LEN],
    ctx: &MessageContext,
    nonce: &Nonce,
    ct: &[u8],
    msg_sig: &Sig,
) -> Result<Vec<u8>, CryptoError> {
    verify_message(sender_sig_pub, ctx, nonce, ct, msg_sig)?;
    let aad = ctx.aad();
    XChaCha20Poly1305::new(epoch_key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn verify_message(
    sender_sig_pub: &[u8; KEY_LEN],
    ctx: &MessageContext,
    nonce: &Nonce,
    ct: &[u8],
    msg_sig: &Sig,
) -> Result<(), CryptoError> {
    let encoded_class = message_silent_control(nonce)?;
    if encoded_class != ctx.silent_control {
        return Err(CryptoError::DecryptionFailed);
    }
    let aad = ctx.aad();
    let mut signed = aad.clone();
    signed.extend_from_slice(nonce);
    signed.extend_from_slice(ct);
    VerifyingKey::from_bytes(sender_sig_pub)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify_strict(&signed, &Signature::from_bytes(msg_sig))
        .map_err(|_| CryptoError::InvalidSignature)
}

const RECEIPT_CONTROL_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptControl {
    pub conversation_id: Id,
    pub epoch: u64,
    pub account_id: String,
    pub device_id: Id,
    pub delivered_from_seq: u64,
    pub delivered_through_seq: u64,
    pub read_through_seq: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptControlWire {
    v: u8,
    #[serde(rename = "type")]
    control_type: String,
    conversation_id: String,
    epoch: u64,
    account_id: String,
    device_id: String,
    delivered_from_seq: u64,
    delivered_through_seq: u64,
    read_through_seq: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlBodyWire {
    v: u8,
    kind: String,
    control: ReceiptControlWire,
}

fn valid_account_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

pub fn encode_receipt_control(control: &ReceiptControl) -> Result<Vec<u8>, CryptoError> {
    if !valid_account_id(&control.account_id)
        || control.delivered_from_seq == 0
        || control.delivered_from_seq > control.delivered_through_seq
        || control.read_through_seq.is_some_and(|read| {
            read < control.delivered_from_seq || read > control.delivered_through_seq
        })
    {
        return Err(CryptoError::InvalidReceiptControl);
    }
    serde_json::to_vec(&ControlBodyWire {
        v: RECEIPT_CONTROL_VERSION,
        kind: "control".to_owned(),
        control: ReceiptControlWire {
            v: RECEIPT_CONTROL_VERSION,
            control_type: "receipt".to_owned(),
            conversation_id: hex_lower(&control.conversation_id),
            epoch: control.epoch,
            account_id: control.account_id.clone(),
            device_id: hex_lower(&control.device_id),
            delivered_from_seq: control.delivered_from_seq,
            delivered_through_seq: control.delivered_through_seq,
            read_through_seq: control.read_through_seq,
        },
    })
    .map_err(|_| CryptoError::InvalidReceiptControl)
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_hex_id(value: &str, error: CryptoError) -> Result<Id, CryptoError> {
    if value.len() != ID_LEN * 2 {
        return Err(error);
    }
    let mut out = [0_u8; ID_LEN];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        out[index] = (nibble(pair[0]).ok_or_else(|| error.clone())? << 4)
            | nibble(pair[1]).ok_or_else(|| error.clone())?;
    }
    Ok(out)
}

pub struct ReceiptControlValidation<'a> {
    pub conversation_id: &'a Id,
    pub epoch: u64,
    pub account_id: &'a str,
    pub device_id: &'a Id,
    pub envelope_seq: u64,
    pub prior_delivered_through_seq: u64,
    pub prior_delivered_from_seq: u64,
    pub prior_read_through_seq: u64,
}

pub struct ClassifiedReceiptControl {
    pub control: ReceiptControl,
    pub superseded: bool,
}

pub fn classify_receipt_control(
    plaintext: &[u8],
    validation: &ReceiptControlValidation<'_>,
) -> Result<ClassifiedReceiptControl, CryptoError> {
    let body: ControlBodyWire =
        serde_json::from_slice(plaintext).map_err(|_| CryptoError::InvalidReceiptControl)?;
    let wire = body.control;
    let conversation_id = parse_hex_id(&wire.conversation_id, CryptoError::InvalidReceiptControl)?;
    let device_id = parse_hex_id(&wire.device_id, CryptoError::InvalidReceiptControl)?;
    if body.v != RECEIPT_CONTROL_VERSION
        || body.kind != "control"
        || wire.v != RECEIPT_CONTROL_VERSION
        || wire.control_type != "receipt"
        || !valid_account_id(&wire.account_id)
        || conversation_id != *validation.conversation_id
        || wire.epoch != validation.epoch
        || wire.account_id != validation.account_id
        || device_id != *validation.device_id
        || wire.delivered_from_seq == 0
        || wire.delivered_from_seq > wire.delivered_through_seq
        || wire.delivered_through_seq >= validation.envelope_seq
        || wire
            .read_through_seq
            .is_some_and(|read| read < wire.delivered_from_seq || read > wire.delivered_through_seq)
    {
        return Err(CryptoError::InvalidReceiptControl);
    }
    let superseded = wire.delivered_through_seq < validation.prior_delivered_through_seq
        || (wire.delivered_through_seq == validation.prior_delivered_through_seq
            && validation.prior_delivered_from_seq > 0
            && wire.delivered_from_seq > validation.prior_delivered_from_seq)
        || wire
            .read_through_seq
            .is_some_and(|read| read < validation.prior_read_through_seq);
    Ok(ClassifiedReceiptControl {
        control: ReceiptControl {
            conversation_id,
            epoch: wire.epoch,
            account_id: wire.account_id,
            device_id,
            delivered_from_seq: wire.delivered_from_seq,
            delivered_through_seq: wire.delivered_through_seq,
            read_through_seq: wire.read_through_seq,
        },
        superseded,
    })
}

pub fn decode_receipt_control(
    plaintext: &[u8],
    validation: &ReceiptControlValidation<'_>,
) -> Result<ReceiptControl, CryptoError> {
    let classified = classify_receipt_control(plaintext, validation)?;
    if classified.superseded {
        return Err(CryptoError::ReceiptRollback);
    }
    Ok(classified.control)
}

const REACTION_CONTROL_VERSION: u8 = 1;
pub const REACTION_VALUES: [&str; 6] = ["❤️", "👍", "👎", "😂", "‼️", "❓"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactionControl {
    pub conversation_id: Id,
    pub epoch: u64,
    pub account_id: String,
    pub device_id: Id,
    pub target_message_id: Id,
    pub target_seq: u64,
    pub reaction: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReactionControlWire {
    v: u8,
    #[serde(rename = "type")]
    control_type: String,
    conversation_id: String,
    epoch: u64,
    account_id: String,
    device_id: String,
    target_message_id: String,
    target_seq: u64,
    action: String,
    reaction: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReactionControlBodyWire {
    v: u8,
    kind: String,
    control: ReactionControlWire,
}

fn valid_reaction(value: &str) -> bool {
    REACTION_VALUES.contains(&value)
}

pub fn encode_reaction_control(control: &ReactionControl) -> Result<Vec<u8>, CryptoError> {
    if !valid_account_id(&control.account_id)
        || control.target_seq == 0
        || control
            .reaction
            .as_deref()
            .is_some_and(|value| !valid_reaction(value))
    {
        return Err(CryptoError::InvalidReactionControl);
    }
    let action = if control.reaction.is_some() {
        "set"
    } else {
        "remove"
    };
    serde_json::to_vec(&ReactionControlBodyWire {
        v: REACTION_CONTROL_VERSION,
        kind: "control".to_owned(),
        control: ReactionControlWire {
            v: REACTION_CONTROL_VERSION,
            control_type: "reaction".to_owned(),
            conversation_id: hex_lower(&control.conversation_id),
            epoch: control.epoch,
            account_id: control.account_id.clone(),
            device_id: hex_lower(&control.device_id),
            target_message_id: hex_lower(&control.target_message_id),
            target_seq: control.target_seq,
            action: action.to_owned(),
            reaction: control.reaction.clone(),
        },
    })
    .map_err(|_| CryptoError::InvalidReactionControl)
}

pub struct ReactionControlValidation<'a> {
    pub conversation_id: &'a Id,
    pub epoch: u64,
    pub account_id: &'a str,
    pub device_id: &'a Id,
    pub envelope_seq: u64,
}

pub fn decode_reaction_control(
    plaintext: &[u8],
    validation: &ReactionControlValidation<'_>,
) -> Result<ReactionControl, CryptoError> {
    let body: ReactionControlBodyWire =
        serde_json::from_slice(plaintext).map_err(|_| CryptoError::InvalidReactionControl)?;
    let wire = body.control;
    let conversation_id = parse_hex_id(&wire.conversation_id, CryptoError::InvalidReactionControl)?;
    let device_id = parse_hex_id(&wire.device_id, CryptoError::InvalidReactionControl)?;
    let target_message_id =
        parse_hex_id(&wire.target_message_id, CryptoError::InvalidReactionControl)?;
    let action_valid = match (wire.action.as_str(), wire.reaction.as_deref()) {
        ("set", Some(value)) => valid_reaction(value),
        ("remove", None) => true,
        _ => false,
    };
    if body.v != REACTION_CONTROL_VERSION
        || body.kind != "control"
        || wire.v != REACTION_CONTROL_VERSION
        || wire.control_type != "reaction"
        || !valid_account_id(&wire.account_id)
        || conversation_id != *validation.conversation_id
        || wire.epoch != validation.epoch
        || wire.account_id != validation.account_id
        || device_id != *validation.device_id
        || wire.target_seq == 0
        || wire.target_seq >= validation.envelope_seq
        || !action_valid
    {
        return Err(CryptoError::InvalidReactionControl);
    }
    Ok(ReactionControl {
        conversation_id,
        epoch: wire.epoch,
        account_id: wire.account_id,
        device_id,
        target_message_id,
        target_seq: wire.target_seq,
        reaction: wire.reaction,
    })
}

const EDIT_CONTROL_VERSION: u8 = 1;
const MAX_EDIT_TEXT_CHARS: usize = 8_000;
const MAX_EDIT_LINK_CARDS: usize = 3;
const MAX_EDIT_URL_CHARS: usize = 2_048;
const MAX_EDIT_LINK_TITLE_CHARS: usize = 120;
const MAX_EDIT_LINK_DESCRIPTION_CHARS: usize = 240;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SilentControlKind {
    Receipt,
    Reaction,
    Edit,
    AiSummary,
    SidequestScene,
    SidequestTurnStatus,
    Persona,
    Unknown,
}

#[derive(Deserialize)]
struct SilentControlHeader {
    v: u8,
    kind: String,
    control: serde_json::Value,
}

pub fn classify_silent_control(plaintext: &[u8]) -> Result<SilentControlKind, CryptoError> {
    let body: SilentControlHeader =
        serde_json::from_slice(plaintext).map_err(|_| CryptoError::InvalidSilentControl)?;
    let control = body
        .control
        .as_object()
        .ok_or(CryptoError::InvalidSilentControl)?;
    let control_type = control
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.chars().count() <= 64 && !value.chars().any(char::is_control)
        })
        .ok_or(CryptoError::InvalidSilentControl)?;
    if body.v != 1 || body.kind != "control" {
        return Err(CryptoError::InvalidSilentControl);
    }
    let version = control.get("v").and_then(serde_json::Value::as_u64);
    let legacy_version = control.get("version").and_then(serde_json::Value::as_u64);
    Ok(match (control_type, version, legacy_version) {
        ("receipt", Some(1), _) => SilentControlKind::Receipt,
        ("reaction", Some(1), _) => SilentControlKind::Reaction,
        ("edit", Some(1), _) => SilentControlKind::Edit,
        ("ai_summary_v1", _, Some(1)) => SilentControlKind::AiSummary,
        ("sidequest_scene_v1", _, Some(1)) => SilentControlKind::SidequestScene,
        ("sidequest_turn_status_v1", _, Some(1)) => SilentControlKind::SidequestTurnStatus,
        ("persona_v1", _, Some(1)) => SilentControlKind::Persona,
        _ => SilentControlKind::Unknown,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditLinkCard {
    pub url: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditControl {
    pub conversation_id: Id,
    pub epoch: u64,
    pub account_id: String,
    pub device_id: Id,
    pub target_message_id: Id,
    pub target_seq: u64,
    pub text: String,
    pub link_cards: Vec<EditLinkCard>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EditControlWire {
    v: u8,
    #[serde(rename = "type")]
    control_type: String,
    conversation_id: String,
    epoch: u64,
    account_id: String,
    device_id: String,
    target_message_id: String,
    target_seq: u64,
    text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    link_cards: Vec<EditLinkCard>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditControlBodyWire {
    v: u8,
    kind: String,
    control: EditControlWire,
}

fn valid_edit_url(value: &str) -> bool {
    value.chars().count() <= MAX_EDIT_URL_CHARS
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
        && (value.starts_with("https://") || value.starts_with("http://"))
}

fn valid_edit_metadata(value: &str, max_chars: usize, required: bool) -> bool {
    value.chars().count() <= max_chars
        && (!required || !value.trim().is_empty())
        && !value.chars().any(char::is_control)
}

fn valid_edit(control: &EditControl) -> bool {
    !control.text.trim().is_empty()
        && control.text.chars().count() <= MAX_EDIT_TEXT_CHARS
        && valid_account_id(&control.account_id)
        && control.target_seq > 0
        && control.link_cards.len() <= MAX_EDIT_LINK_CARDS
        && control.link_cards.iter().all(|card| {
            valid_edit_url(&card.url)
                && valid_edit_metadata(&card.title, MAX_EDIT_LINK_TITLE_CHARS, true)
                && card.description.as_deref().is_none_or(|value| {
                    valid_edit_metadata(value, MAX_EDIT_LINK_DESCRIPTION_CHARS, false)
                })
                && card.image_url.as_deref().is_none_or(valid_edit_url)
        })
}

pub fn encode_edit_control(control: &EditControl) -> Result<Vec<u8>, CryptoError> {
    if !valid_edit(control) {
        return Err(CryptoError::InvalidEditControl);
    }
    serde_json::to_vec(&EditControlBodyWire {
        v: EDIT_CONTROL_VERSION,
        kind: "control".to_owned(),
        control: EditControlWire {
            v: EDIT_CONTROL_VERSION,
            control_type: "edit".to_owned(),
            conversation_id: hex_lower(&control.conversation_id),
            epoch: control.epoch,
            account_id: control.account_id.clone(),
            device_id: hex_lower(&control.device_id),
            target_message_id: hex_lower(&control.target_message_id),
            target_seq: control.target_seq,
            text: control.text.clone(),
            link_cards: control.link_cards.clone(),
        },
    })
    .map_err(|_| CryptoError::InvalidEditControl)
}

pub struct EditControlValidation<'a> {
    pub conversation_id: &'a Id,
    pub epoch: u64,
    pub account_id: &'a str,
    pub device_id: &'a Id,
    pub envelope_seq: u64,
}

pub fn decode_edit_control(
    plaintext: &[u8],
    validation: &EditControlValidation<'_>,
) -> Result<EditControl, CryptoError> {
    let body: EditControlBodyWire =
        serde_json::from_slice(plaintext).map_err(|_| CryptoError::InvalidEditControl)?;
    let wire = body.control;
    let control = EditControl {
        conversation_id: parse_hex_id(&wire.conversation_id, CryptoError::InvalidEditControl)?,
        epoch: wire.epoch,
        account_id: wire.account_id,
        device_id: parse_hex_id(&wire.device_id, CryptoError::InvalidEditControl)?,
        target_message_id: parse_hex_id(&wire.target_message_id, CryptoError::InvalidEditControl)?,
        target_seq: wire.target_seq,
        text: wire.text,
        link_cards: wire.link_cards,
    };
    if body.v != EDIT_CONTROL_VERSION
        || body.kind != "control"
        || wire.v != EDIT_CONTROL_VERSION
        || wire.control_type != "edit"
        || control.conversation_id != *validation.conversation_id
        || control.epoch != validation.epoch
        || control.account_id != validation.account_id
        || control.device_id != *validation.device_id
        || control.target_seq >= validation.envelope_seq
        || !valid_edit(&control)
    {
        return Err(CryptoError::InvalidEditControl);
    }
    Ok(control)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedBlob {
    pub key: Key,
    pub nonce: Nonce,
    pub ct: Vec<u8>,
}

pub fn encrypt_blob(rng: &mut (impl CryptoRng + RngCore), plaintext: &[u8]) -> EncryptedBlob {
    let mut key = [0u8; KEY_LEN];
    rng.fill_bytes(&mut key);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: DOMAIN_BLOB,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory inputs");
    EncryptedBlob { key, nonce, ct }
}

pub fn decrypt_blob(key: &Key, nonce: &Nonce, ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: DOMAIN_BLOB,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryFactor {
    PasskeyPrf,
    RecoveryCode,
}

impl RecoveryFactor {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::PasskeyPrf => DOMAIN_RECOVERY_PASSKEY,
            Self::RecoveryCode => DOMAIN_RECOVERY_CODE,
        }
    }

    fn byte(self) -> u8 {
        match self {
            Self::PasskeyPrf => 0,
            Self::RecoveryCode => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryMaterial {
    pub vault_key: Key,
    pub recovery_code: Option<Key>,
    pub recovery_code_wrapper: Option<Vec<u8>>,
    pub passkey_wrapper: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCodeMaterial {
    pub recovery_code: Key,
    pub recovery_code_wrapper: Vec<u8>,
}

fn recovery_wrapper_aad(identity_id: &Id, generation: u64, factor: RecoveryFactor) -> Vec<u8> {
    let mut aad = Vec::with_capacity(factor.domain().len() + ID_LEN + 8 + 2);
    aad.extend_from_slice(factor.domain());
    aad.push(RECOVERY_WRAPPER_FORMAT);
    aad.extend_from_slice(identity_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.push(factor.byte());
    aad
}

fn recovery_wrapper_key(factor_bytes: &[u8], salt: &Key, factor: RecoveryFactor) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(salt), factor_bytes);
    let mut key = [0_u8; KEY_LEN];
    hk.expand(factor.domain(), &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn wrap_recovery_vault_key(
    rng: &mut (impl CryptoRng + RngCore),
    factor_bytes: &[u8],
    factor: RecoveryFactor,
    identity_id: &Id,
    generation: u64,
    vault_key: &Key,
) -> Result<Vec<u8>, CryptoError> {
    if factor_bytes.len() < KEY_LEN {
        return Err(CryptoError::InvalidLength {
            what: "recovery factor",
            expected: KEY_LEN,
            actual: factor_bytes.len(),
        });
    }
    let mut salt = [0_u8; KEY_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let key = recovery_wrapper_key(factor_bytes, &salt, factor);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: vault_key,
                aad: &recovery_wrapper_aad(identity_id, generation, factor),
            },
        )
        .expect("in-memory recovery key wrapping");
    let mut wrapper = Vec::with_capacity(RECOVERY_WRAPPER_LEN);
    wrapper.push(RECOVERY_WRAPPER_FORMAT);
    wrapper.extend_from_slice(&salt);
    wrapper.extend_from_slice(&nonce);
    wrapper.extend_from_slice(&ct);
    Ok(wrapper)
}

pub fn open_recovery_vault_key(
    factor_bytes: &[u8],
    factor: RecoveryFactor,
    identity_id: &Id,
    generation: u64,
    wrapper: &[u8],
) -> Result<Key, CryptoError> {
    if factor_bytes.len() < KEY_LEN {
        return Err(CryptoError::InvalidLength {
            what: "recovery factor",
            expected: KEY_LEN,
            actual: factor_bytes.len(),
        });
    }
    if wrapper.len() != RECOVERY_WRAPPER_LEN {
        return Err(CryptoError::InvalidLength {
            what: "recovery wrapper",
            expected: RECOVERY_WRAPPER_LEN,
            actual: wrapper.len(),
        });
    }
    if wrapper[0] != RECOVERY_WRAPPER_FORMAT {
        return Err(CryptoError::DecryptionFailed);
    }
    let salt: Key = wrapper[1..1 + KEY_LEN].try_into().expect("checked length");
    let nonce_start = 1 + KEY_LEN;
    let nonce: Nonce = wrapper[nonce_start..nonce_start + NONCE_LEN]
        .try_into()
        .expect("checked length");
    let key = recovery_wrapper_key(factor_bytes, &salt, factor);
    let plaintext = XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &wrapper[nonce_start + NONCE_LEN..],
                aad: &recovery_wrapper_aad(identity_id, generation, factor),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    plaintext
        .try_into()
        .map_err(|value: Vec<u8>| CryptoError::InvalidLength {
            what: "unwrapped vault key",
            expected: KEY_LEN,
            actual: value.len(),
        })
}

pub fn generate_recovery_material(
    rng: &mut (impl CryptoRng + RngCore),
    identity_id: &Id,
    generation: u64,
    passkey_prf: Option<&[u8]>,
) -> Result<RecoveryMaterial, CryptoError> {
    let mut vault_key = [0_u8; KEY_LEN];
    rng.fill_bytes(&mut vault_key);
    let passkey_wrapper = passkey_prf
        .map(|prf| {
            wrap_recovery_vault_key(
                rng,
                prf,
                RecoveryFactor::PasskeyPrf,
                identity_id,
                generation,
                &vault_key,
            )
        })
        .transpose()?;
    let (recovery_code, recovery_code_wrapper) = if passkey_wrapper.is_none() {
        let mut recovery_code = [0_u8; KEY_LEN];
        rng.fill_bytes(&mut recovery_code);
        let wrapper = wrap_recovery_vault_key(
            rng,
            &recovery_code,
            RecoveryFactor::RecoveryCode,
            identity_id,
            generation,
            &vault_key,
        )?;
        (Some(recovery_code), Some(wrapper))
    } else {
        (None, None)
    };
    Ok(RecoveryMaterial {
        vault_key,
        recovery_code,
        recovery_code_wrapper,
        passkey_wrapper,
    })
}

pub fn generate_recovery_code_material(
    rng: &mut (impl CryptoRng + RngCore),
    identity_id: &Id,
    generation: u64,
    vault_key: &Key,
) -> Result<RecoveryCodeMaterial, CryptoError> {
    let mut recovery_code = [0_u8; KEY_LEN];
    rng.fill_bytes(&mut recovery_code);
    let recovery_code_wrapper = wrap_recovery_vault_key(
        rng,
        &recovery_code,
        RecoveryFactor::RecoveryCode,
        identity_id,
        generation,
        vault_key,
    )?;
    Ok(RecoveryCodeMaterial {
        recovery_code,
        recovery_code_wrapper,
    })
}

fn recovery_vault_aad(identity_id: &Id, generation: u64, vault_version: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN_RECOVERY_VAULT.len() + 1 + ID_LEN + 16);
    aad.extend_from_slice(DOMAIN_RECOVERY_VAULT);
    aad.push(RECOVERY_VAULT_FORMAT);
    aad.extend_from_slice(identity_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&vault_version.to_be_bytes());
    aad
}

pub fn encrypt_recovery_vault(
    rng: &mut (impl CryptoRng + RngCore),
    vault_key: &Key,
    identity_id: &Id,
    generation: u64,
    vault_version: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if vault_version == 0 || vault_version > MAX_RECOVERY_VAULT_VERSION {
        return Err(CryptoError::InvalidRecoveryVersion);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(vault_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &recovery_vault_aad(identity_id, generation, vault_version),
            },
        )
        .expect("in-memory recovery vault encryption");
    let mut vault = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    vault.push(RECOVERY_VAULT_FORMAT);
    vault.extend_from_slice(&nonce);
    vault.extend_from_slice(&ct);
    Ok(vault)
}

pub fn decrypt_recovery_vault(
    vault_key: &Key,
    identity_id: &Id,
    generation: u64,
    vault_version: u64,
    vault: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if vault_version == 0 || vault_version > MAX_RECOVERY_VAULT_VERSION {
        return Err(CryptoError::InvalidRecoveryVersion);
    }
    let minimum = 1 + NONCE_LEN + TAG_LEN;
    if vault.len() < minimum {
        return Err(CryptoError::InvalidLength {
            what: "recovery vault",
            expected: minimum,
            actual: vault.len(),
        });
    }
    if vault[0] != RECOVERY_VAULT_FORMAT {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce: Nonce = vault[1..1 + NONCE_LEN].try_into().expect("checked length");
    XChaCha20Poly1305::new(vault_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &vault[1 + NONCE_LEN..],
                aad: &recovery_vault_aad(identity_id, generation, vault_version),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn random_id(rng: &mut (impl CryptoRng + RngCore)) -> Id {
    let mut id = [0u8; ID_LEN];
    rng.fill_bytes(&mut id);
    id
}

pub fn sidequest_key(master: &Key, scope: &str, purpose: &str) -> Key {
    let mut info = b"tychat-sidequest-v1".to_vec();
    info.extend_from_slice(&(scope.len() as u64).to_be_bytes());
    info.extend_from_slice(scope.as_bytes());
    info.extend_from_slice(purpose.as_bytes());
    let mut key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, master)
        .expand(&info, &mut key)
        .expect("fixed HKDF length");
    key
}

pub fn seal_sidequest_content(
    rng: &mut (impl CryptoRng + RngCore),
    master: &Key,
    scope: &str,
    plaintext: &[u8],
) -> Result<(Nonce, Vec<u8>), CryptoError> {
    let key = sidequest_key(master, scope, "entity-content");
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: scope.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok((nonce, ct))
}

pub fn open_sidequest_content(
    master: &Key,
    scope: &str,
    nonce: &Nonce,
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = sidequest_key(master, scope, "entity-content");
    XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: scope.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn sidequest_turn_roll(
    key: &Key,
    scope: &str,
    conversation: &str,
    message: &str,
    step: u8,
) -> u8 {
    let context = format!("{scope}/{conversation}/{message}/{step}");
    for counter in 0u64.. {
        let bytes = sidequest_key(key, &context, &format!("turn-d100-v1/{counter}"));
        if let Some(value) = bytes.into_iter().find(|value| *value < 200) {
            return value % 100 + 1;
        }
    }
    unreachable!()
}
