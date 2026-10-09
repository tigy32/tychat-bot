use std::collections::HashMap;

use tychat_protocol::{AccountVerification, GenerationSuccessionProof, IdentityStatement};

use crate::wire::{bytes, certified_bundle, statement};
use crate::{BotError, PauseReason};

/// The owner devices whose signatures a runner accepts, by device id, and
/// the owner identity to pin when a verified succession advanced it.
pub(crate) struct OwnerTrust {
    pub(crate) devices: HashMap<String, [u8; 32]>,
    pub(crate) advanced_pin: Option<IdentityStatement>,
}

fn verify_succession(proof: &GenerationSuccessionProof) -> Result<(), BotError> {
    let authorizing = certified_bundle(&proof.authorizing_device, &proof.old_statement)?;
    tychat_crypto::verify_generation_succession(
        &statement(&proof.old_statement)?,
        &statement(&proof.new_statement)?,
        &authorizing,
        &bytes(&proof.authorizing_device.certificate_sig)?,
        &bytes(&proof.succession_sig)?,
    )
    .map_err(|_| BotError::Crypto)
}

/// Verifies the server's owner material against the pinned owner identity
/// (ADR-0034 runner trust rules): the same identity, at the pinned
/// generation or a later one reached through verified ADR-0012 successions.
pub(crate) fn verify_owner(
    pin: &IdentityStatement,
    verification: &AccountVerification,
) -> Result<OwnerTrust, PauseReason> {
    let unverifiable = PauseReason::OwnerIdentityUnverifiable;
    let current = &verification.identity;
    if current.identity_id != pin.identity_id {
        return Err(PauseReason::OwnerIdentityReplaced);
    }
    let verified = statement(current)
        .ok()
        .is_some_and(|current| tychat_crypto::verify_identity_statement(&current).is_ok());
    if !verified || current.generation < pin.generation {
        return Err(unverifiable);
    }
    let mut chain = vec![pin.clone()];
    while chain
        .last()
        .is_some_and(|last| last.generation < current.generation)
    {
        let last = chain.last().cloned().unwrap_or_else(|| pin.clone());
        let Some(proof) = verification
            .successions
            .iter()
            .find(|proof| proof.old_statement == last)
        else {
            return Err(unverifiable);
        };
        verify_succession(proof).map_err(|_| unverifiable)?;
        chain.push(proof.new_statement.clone());
    }
    if chain.last() != Some(current) {
        return Err(unverifiable);
    }

    let mut devices = HashMap::new();
    for device in &verification.devices {
        if let Ok(bundle) = certified_bundle(device, current) {
            devices.insert(device.device.device_id.clone(), bundle.sig_pub);
        }
    }
    for historical in &verification.historical_devices {
        if chain.contains(&historical.identity) {
            if let Ok(bundle) = certified_bundle(&historical.device, &historical.identity) {
                devices
                    .entry(historical.device.device.device_id.clone())
                    .or_insert(bundle.sig_pub);
            }
        }
    }
    Ok(OwnerTrust {
        devices,
        advanced_pin: (current != pin).then(|| current.clone()),
    })
}
