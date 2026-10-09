use reqwest::StatusCode;
use tychat_crypto::{DeviceKeys, IdentityKeys, RecoveryMode};
use tychat_protocol::{BotPairRequest, BotPairResponse};
use url::Url;

use crate::api::{api_url, error_from, http_client};
use crate::wire::{b64, bundle_wire, statement_wire};
use crate::{BotError, BotState, PairingResult};

/// Redeems a one-time pairing code from Tychat Settings → Bots. Generates the
/// bot's identity root and its single device locally; only public keys and
/// signatures leave the process. Persist `result.state` before anything
/// else: the code is spent once this returns.
pub async fn pair(api_base: &Url, code: &str) -> Result<PairingResult, BotError> {
    let code = code.trim().to_ascii_lowercase();
    if !tychat_protocol::is_hex32(&code) {
        return Err(BotError::InvalidPairingCode);
    }
    let mut rng = rand_core::OsRng;
    let identity = IdentityKeys::generate(&mut rng);
    let statement = identity.statement(1, RecoveryMode::Strict);
    let device = DeviceKeys::generate(&mut rng);
    let bundle = device.bundle();
    let certificate_sig = identity.certify_device(1, &bundle);
    let pairing_sig = device.sign_bot_pairing(
        &tychat_crypto::sha256(code.as_bytes()),
        identity.identity_id(),
    );
    let request = BotPairRequest {
        pairing_code: code,
        statement: statement_wire(&statement),
        device: bundle_wire(&bundle),
        certificate_sig: b64(&certificate_sig),
        pairing_sig: b64(&pairing_sig),
    };
    let (url, _) = api_url(api_base, "/bots/pair")?;
    let response = http_client()?
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(BotError::network)?;
    if response.status() == StatusCode::NOT_FOUND {
        return Err(BotError::InvalidPairingCode);
    }
    if !response.status().is_success() {
        return Err(error_from(response).await);
    }
    let pairing: BotPairResponse = response
        .json()
        .await
        .map_err(|_| BotError::Protocol("the pairing response is not the expected JSON"))?;
    let state = BotState::new(pairing, &identity, &statement, &device, &certificate_sig)?;
    Ok(PairingResult {
        bot_fingerprint: state.bot_fingerprint().to_owned(),
        owner_fingerprint: state.owner_fingerprint(),
        state,
    })
}
