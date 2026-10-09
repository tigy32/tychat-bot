//! The owner side of a personal bot, for boundary tests against the local
//! binary (`TYCHAT_ALLOW_DEV_IDENTITY=1`). It plays a Tychat user with a
//! `dev:` session: creates the identity, creates and confirms bots, opens the
//! owner chat exactly as the web client does, and probes the bot API with
//! valid and deliberately broken bot proofs. Not for production use.

use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tychat_crypto::{
    DeviceKeys, GrantContext, IdentityKeys, MessageContext, ReceiptControlValidation, RecoveryMode,
};
use tychat_protocol::{
    BotResponse, BotStatus, BotView, BotsResponse, ConversationKind, CreateBotRequest,
    CreateBotResponse, CreateConversationRequest, CreateConversationResponse,
    CreateIdentityRequest, Grant, IdentityResponse, MessagesResponse, PostMessageRequest,
    PostMessageResponse, RosterIdentityPin, BOT_CREDENTIAL_HEADER, BOT_PROOF_HEADER,
    GUEST_TOKEN_HEADER,
};
use url::Url;

use crate::api::{api_url, error_from, http_client};
use crate::wire::{
    b64, body_text, bundle_wire, bytes, certified_bundle, decode_b64, id, statement,
    statement_wire, text_body,
};
use crate::{BotError, BotState, MessageRef};

const POLL: Duration = Duration::from_millis(200);

/// A dev-identity Tychat user on the local binary.
pub struct OwnerKit {
    http: reqwest::Client,
    base: Url,
    token: String,
    statement: tychat_crypto::IdentityStatement,
    device: DeviceKeys,
}

/// The owner's direct chat with a confirmed bot, with the epoch key the
/// owner generated for it.
pub struct OwnerChat {
    pub conversation_id: String,
    pub bot_account_id: String,
    epoch_key: tychat_crypto::Key,
    bot_device_id: String,
    bot_sig_pub: [u8; 32],
}

fn random_hex<const N: usize>() -> String {
    let mut value = [0u8; N];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

impl OwnerKit {
    /// Signs in as a fresh `dev:<prefix>-<random>` account and creates its
    /// identity and first device.
    pub async fn create(api_base: &Url, prefix: &str) -> Result<Self, BotError> {
        let identity = IdentityKeys::generate(&mut OsRng);
        let statement = identity.statement(1, RecoveryMode::Standard);
        let device = DeviceKeys::generate(&mut OsRng);
        let bundle = device.bundle();
        let certificate_sig = identity.certify_device(1, &bundle);
        let kit = Self {
            http: http_client()?,
            base: api_base.clone(),
            token: format!("dev:{prefix}-{}", random_hex::<4>()),
            statement,
            device,
        };
        let _: IdentityResponse = kit
            .json(
                Method::POST,
                "/identity",
                Some(&CreateIdentityRequest {
                    statement: statement_wire(&kit.statement),
                    device: bundle_wire(&bundle),
                    certificate_sig: b64(&certificate_sig),
                }),
            )
            .await?;
        Ok(kit)
    }

    pub fn account_id(&self) -> &str {
        &self.token
    }

    pub fn fingerprint(&self) -> String {
        tychat_crypto::identity_fingerprint(&self.statement)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<reqwest::Response, BotError> {
        let (url, _) = api_url(&self.base, path)?;
        let mut request = self
            .http
            .request(method, url)
            .header(GUEST_TOKEN_HEADER, &self.token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(BotError::network)?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(error_from(response).await)
        }
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, BotError> {
        self.send(method, path, body)
            .await?
            .json()
            .await
            .map_err(|_| BotError::Protocol("the response is not the expected JSON"))
    }

    pub async fn create_bot(&self, display_name: &str) -> Result<CreateBotResponse, BotError> {
        self.json(
            Method::POST,
            "/bots",
            Some(&CreateBotRequest {
                display_name: display_name.to_owned(),
            }),
        )
        .await
    }

    pub async fn bots(&self) -> Result<Vec<BotView>, BotError> {
        Ok(self
            .json::<BotsResponse>(Method::GET, "/bots", None::<&()>)
            .await?
            .bots)
    }

    /// Confirms a paired bot after checking that its identity matches the
    /// fingerprint the runner printed, then opens the owner chat the way the
    /// web client does: epoch 0, a signed roster pinning both identities,
    /// and a key grant for every device of both members.
    pub async fn confirm_bot(
        &self,
        bot_id: &str,
        expected_fingerprint: &str,
    ) -> Result<OwnerChat, BotError> {
        let bot = self
            .bots()
            .await?
            .into_iter()
            .find(|bot| bot.bot_id == bot_id)
            .ok_or(BotError::Protocol("no such bot"))?;
        let (Some(identity), Some(device)) = (bot.identity.clone(), bot.device.clone()) else {
            return Err(BotError::NotConfirmed);
        };
        let bot_statement = statement(&identity)?;
        tychat_crypto::verify_identity_statement(&bot_statement).map_err(|_| BotError::Crypto)?;
        if tychat_crypto::identity_fingerprint(&bot_statement) != expected_fingerprint
            || bot.bot_account_id != tychat_protocol::bot_account_id(&bot.bot_id)
        {
            return Err(BotError::Crypto);
        }
        let bot_bundle = certified_bundle(&device, &identity)?;
        let confirmed: BotResponse = self
            .json(
                Method::POST,
                &format!("/bots/{bot_id}/confirm"),
                None::<&()>,
            )
            .await?;
        if confirmed.bot.status != BotStatus::Confirmed
            || confirmed.bot.identity.as_ref() != Some(&identity)
        {
            return Err(BotError::Protocol("the bot was not confirmed as shown"));
        }

        let conversation_id = tychat_crypto::random_id(&mut OsRng);
        let conversation_hex = hex::encode(conversation_id);
        let epoch_key = tychat_crypto::generate_epoch_key(&mut OsRng);
        let mut pins = vec![
            RosterIdentityPin {
                account_id: self.token.clone(),
                identity: statement_wire(&self.statement),
            },
            RosterIdentityPin {
                account_id: bot.bot_account_id.clone(),
                identity: identity.clone(),
            },
        ];
        pins.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        let roster = serde_json::to_vec(&serde_json::json!({ "v": 1, "members": pins }))
            .map_err(|_| BotError::Protocol("roster encoding failed"))?;
        let roster_sig = self
            .device
            .sign_roster(&conversation_id, 0, &roster)
            .map_err(|_| BotError::Crypto)?;
        let grants = [
            (*self.device.device_id(), self.device.kem_pub()),
            (bot_bundle.device_id, bot_bundle.kem_pub),
        ]
        .into_iter()
        .map(|(recipient, kem_pub)| {
            let sealed = tychat_crypto::seal_grant(
                &mut OsRng,
                &self.device,
                &kem_pub,
                &GrantContext {
                    conversation_id,
                    epoch: 0,
                    sender_device_id: *self.device.device_id(),
                    recipient_device_id: recipient,
                },
                &epoch_key,
            );
            Grant {
                epoch: 0,
                recipient_device_id: hex::encode(recipient),
                sender_device_id: hex::encode(self.device.device_id()),
                wrapped: b64(&sealed.wrapped),
                grant_sig: b64(&sealed.grant_sig),
            }
        })
        .collect();
        let created: CreateConversationResponse = self
            .json(
                Method::POST,
                "/conversations",
                Some(&CreateConversationRequest {
                    conversation_id: conversation_hex.clone(),
                    kind: ConversationKind::Direct,
                    member_account_ids: vec![self.token.clone(), bot.bot_account_id.clone()],
                    member_identity_pins: pins,
                    roster_signer_device_id: Some(hex::encode(self.device.device_id())),
                    roster_sig: Some(b64(&roster_sig)),
                    title_ct: None,
                    grants,
                    lock_grants: Vec::new(),
                }),
            )
            .await?;
        if created.existing || created.conversation.conversation_id != conversation_hex {
            return Err(BotError::Protocol("the owner chat already existed"));
        }
        Ok(OwnerChat {
            conversation_id: conversation_hex,
            bot_account_id: bot.bot_account_id,
            epoch_key,
            bot_device_id: hex::encode(bot_bundle.device_id),
            bot_sig_pub: bot_bundle.sig_pub,
        })
    }

    pub async fn delete_bot(&self, bot_id: &str) -> Result<(), BotError> {
        let response = self
            .send(Method::DELETE, &format!("/bots/{bot_id}"), None::<&()>)
            .await?;
        if response.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(BotError::Protocol("deleting a bot answers 204"))
        }
    }

    /// Sends a text message into the owner chat and returns where it landed.
    pub async fn send_text(&self, chat: &OwnerChat, text: &str) -> Result<MessageRef, BotError> {
        let message_id = tychat_crypto::random_id(&mut OsRng);
        let encrypted = tychat_crypto::encrypt_message(
            &mut OsRng,
            &chat.epoch_key,
            &self.device,
            &MessageContext {
                conversation_id: id(&chat.conversation_id)?,
                message_id,
                epoch: 0,
                sender_device_id: *self.device.device_id(),
                silent_control: false,
            },
            &text_body(text),
        );
        let posted: PostMessageResponse = self
            .json(
                Method::POST,
                &format!("/conversations/{}/messages", chat.conversation_id),
                Some(&PostMessageRequest {
                    message_id: hex::encode(message_id),
                    epoch: 0,
                    sender_device_id: hex::encode(self.device.device_id()),
                    nonce: b64(&encrypted.nonce),
                    ct: b64(&encrypted.ct),
                    msg_sig: b64(&encrypted.msg_sig),
                    silent_control: false,
                    blob_ids: Vec::new(),
                }),
            )
            .await?;
        Ok(MessageRef {
            seq: posted.seq,
            epoch: 0,
        })
    }

    /// Every envelope the bot device sent after `after`, verified against the
    /// confirmed bot device and decrypted.
    async fn bot_envelopes(
        &self,
        chat: &OwnerChat,
        after: u64,
    ) -> Result<Vec<(u64, bool, Vec<u8>)>, BotError> {
        let page: MessagesResponse = self
            .json(
                Method::GET,
                &format!(
                    "/conversations/{}/messages?after={after}&limit=100&deviceId={}",
                    chat.conversation_id,
                    hex::encode(self.device.device_id())
                ),
                None::<&()>,
            )
            .await?;
        let conversation_id = id(&chat.conversation_id)?;
        let mut opened = Vec::new();
        for envelope in page.messages {
            if envelope.sender_account_id != chat.bot_account_id {
                continue;
            }
            if envelope.sender_device_id != chat.bot_device_id || envelope.epoch != 0 {
                return Err(BotError::Crypto);
            }
            let plaintext = tychat_crypto::decrypt_message(
                &chat.epoch_key,
                &chat.bot_sig_pub,
                &MessageContext {
                    conversation_id,
                    message_id: id(&envelope.message_id)?,
                    epoch: 0,
                    sender_device_id: id(&envelope.sender_device_id)?,
                    silent_control: envelope.silent_control,
                },
                &bytes(&envelope.nonce)?,
                &decode_b64(&envelope.ct)?,
                &bytes(&envelope.msg_sig)?,
            )
            .map_err(|_| BotError::Crypto)?;
            opened.push((envelope.seq, envelope.silent_control, plaintext));
        }
        Ok(opened)
    }

    /// Every text message the bot sent after `after`.
    pub async fn bot_texts(
        &self,
        chat: &OwnerChat,
        after: u64,
    ) -> Result<Vec<(u64, String)>, BotError> {
        Ok(self
            .bot_envelopes(chat, after)
            .await?
            .into_iter()
            .filter(|(_, silent, _)| !silent)
            .filter_map(|(seq, _, plaintext)| body_text(&plaintext).map(|text| (seq, text)))
            .collect())
    }

    /// Waits for the bot's first text message after `after`.
    pub async fn wait_for_bot_text(
        &self,
        chat: &OwnerChat,
        after: u64,
        timeout: Duration,
    ) -> Result<(u64, String), BotError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(first) = self.bot_texts(chat, after).await?.into_iter().next() {
                return Ok(first);
            }
            if Instant::now() >= deadline {
                return Err(BotError::Protocol("the bot did not reply in time"));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Waits for a valid read receipt from the bot device covering `seq`.
    pub async fn wait_for_read_receipt(
        &self,
        chat: &OwnerChat,
        seq: u64,
        timeout: Duration,
    ) -> Result<(), BotError> {
        let deadline = Instant::now() + timeout;
        let conversation_id = id(&chat.conversation_id)?;
        let device_id = id(&chat.bot_device_id)?;
        loop {
            for (envelope_seq, silent, plaintext) in self.bot_envelopes(chat, 0).await? {
                if !silent {
                    continue;
                }
                let receipt = tychat_crypto::decode_receipt_control(
                    &plaintext,
                    &ReceiptControlValidation {
                        conversation_id: &conversation_id,
                        epoch: 0,
                        account_id: &chat.bot_account_id,
                        device_id: &device_id,
                        envelope_seq,
                        prior_delivered_through_seq: 0,
                        prior_delivered_from_seq: 0,
                        prior_read_through_seq: 0,
                    },
                )
                .map_err(|_| BotError::Crypto)?;
                if receipt.read_through_seq.is_some_and(|read| read >= seq) {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(BotError::Protocol("no read receipt in time"));
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

/// How a [`BotProbe`] request breaks the bot authentication contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFault {
    None,
    BadSignature,
    ExpiredProof,
    MissingProof,
    UnknownCredential,
    GuestTokenAlongside,
}

/// Sends raw bot-authenticated requests and reports only the HTTP status.
pub struct BotProbe {
    http: reqwest::Client,
    base: Url,
    credential: String,
    device: DeviceKeys,
}

impl BotProbe {
    pub fn new(api_base: &Url, state: &BotState) -> Result<Self, BotError> {
        Ok(Self {
            http: http_client()?,
            base: api_base.clone(),
            credential: state.credential().to_owned(),
            device: state.device().clone(),
        })
    }

    /// `path_and_query` is relative to `/api/v1`. The proof expires 30 seconds
    /// from the local clock, so the probe expects a synchronized local server.
    pub async fn status(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        fault: ProbeFault,
    ) -> Result<u16, BotError> {
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| BotError::Protocol("invalid method"))?;
        let (url, target) = api_url(&self.base, path_and_query)?;
        let request_id = tychat_crypto::random_id(&mut OsRng);
        let now = crate::wire::now_epoch_seconds();
        let expires = if fault == ProbeFault::ExpiredProof {
            now - 1
        } else {
            now + 30
        };
        let mut signature = self.device.sign_bot_request(
            &request_id,
            expires,
            &tychat_crypto::BotRequest {
                method: method.as_str(),
                path_and_query: &target,
                body,
            },
        );
        if fault == ProbeFault::BadSignature {
            signature[0] ^= 1;
        }
        let credential = if fault == ProbeFault::UnknownCredential {
            random_hex::<32>()
        } else {
            self.credential.clone()
        };
        let mut request = self
            .http
            .request(method, url)
            .header(BOT_CREDENTIAL_HEADER, credential);
        if fault != ProbeFault::MissingProof {
            request = request.header(
                BOT_PROOF_HEADER,
                format!(
                    "{}.{}.{}",
                    hex::encode(request_id),
                    expires,
                    b64(&signature)
                ),
            );
        }
        if fault == ProbeFault::GuestTokenAlongside {
            request = request.header(GUEST_TOKEN_HEADER, "dev:bot-probe");
        }
        if !body.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        Ok(request
            .send()
            .await
            .map_err(BotError::network)?
            .status()
            .as_u16())
    }
}
