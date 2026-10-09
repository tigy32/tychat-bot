use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tychat_crypto::{DeviceBundle, IdentityStatement, RecoveryMode};
use tychat_protocol::CertifiedDevice;

use crate::BotError;

pub(crate) fn id(value: &str) -> Result<[u8; 16], BotError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BotError::Protocol("an id is not 32 hex characters"))
}

pub(crate) fn bytes<const N: usize>(value: &str) -> Result<[u8; N], BotError> {
    BASE64
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BotError::Protocol(
            "a key or signature has the wrong length",
        ))
}

pub(crate) fn b64(value: &[u8]) -> String {
    BASE64.encode(value)
}

pub(crate) fn decode_b64(value: &str) -> Result<Vec<u8>, BotError> {
    BASE64
        .decode(value)
        .map_err(|_| BotError::Protocol("a field is not base64"))
}

pub(crate) fn statement(
    wire: &tychat_protocol::IdentityStatement,
) -> Result<IdentityStatement, BotError> {
    Ok(IdentityStatement {
        identity_id: id(&wire.identity_id)?,
        generation: wire.generation,
        root_sig_pub: bytes(&wire.root_sig_pub)?,
        recovery_mode: match wire.recovery_mode {
            tychat_protocol::RecoveryMode::Standard => RecoveryMode::Standard,
            tychat_protocol::RecoveryMode::Strict => RecoveryMode::Strict,
        },
        statement_sig: bytes(&wire.statement_sig)?,
    })
}

pub(crate) fn statement_wire(statement: &IdentityStatement) -> tychat_protocol::IdentityStatement {
    tychat_protocol::IdentityStatement {
        identity_id: hex::encode(statement.identity_id),
        generation: statement.generation,
        root_sig_pub: b64(&statement.root_sig_pub),
        recovery_mode: match statement.recovery_mode {
            RecoveryMode::Standard => tychat_protocol::RecoveryMode::Standard,
            RecoveryMode::Strict => tychat_protocol::RecoveryMode::Strict,
        },
        statement_sig: b64(&statement.statement_sig),
    }
}

pub(crate) fn bundle(wire: &tychat_protocol::DeviceBundle) -> Result<DeviceBundle, BotError> {
    Ok(DeviceBundle {
        device_id: id(&wire.device_id)?,
        sig_pub: bytes(&wire.sig_pub)?,
        kem_pub: bytes(&wire.kem_pub)?,
        bundle_sig: bytes(&wire.bundle_sig)?,
    })
}

pub(crate) fn bundle_wire(bundle: &DeviceBundle) -> tychat_protocol::DeviceBundle {
    tychat_protocol::DeviceBundle {
        device_id: hex::encode(bundle.device_id),
        sig_pub: b64(&bundle.sig_pub),
        kem_pub: b64(&bundle.kem_pub),
        bundle_sig: b64(&bundle.bundle_sig),
    }
}

/// A device certified by `identity`, or an error when the certificate does
/// not verify against exactly that statement.
pub(crate) fn certified_bundle(
    certified: &CertifiedDevice,
    identity: &tychat_protocol::IdentityStatement,
) -> Result<DeviceBundle, BotError> {
    if certified.identity_id != identity.identity_id || certified.generation != identity.generation
    {
        return Err(BotError::Crypto);
    }
    let bundle = bundle(&certified.device)?;
    tychat_crypto::verify_device_certificate(
        &statement(identity)?,
        &bundle,
        &bytes(&certified.certificate_sig)?,
    )
    .map_err(|_| BotError::Crypto)?;
    Ok(bundle)
}

pub(crate) fn now_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) fn text_body(text: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "v": 1, "kind": "text", "text": text }))
        .unwrap_or_default()
}

/// The text of a decrypted content body: a text message, or the caption of
/// an attachment message. Anything else carries no text for a bot.
pub(crate) fn body_text(plaintext: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(plaintext).ok()?;
    if value.get("v")?.as_u64()? != 1 {
        return None;
    }
    let text = value.get("text")?.as_str()?;
    match value.get("kind")?.as_str()? {
        "text" | "media" if !text.is_empty() => Some(text.to_owned()),
        _ => None,
    }
}
