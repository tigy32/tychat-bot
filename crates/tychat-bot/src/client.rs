use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tychat_crypto::{GrantContext, MessageContext, ReceiptControl};
use tychat_protocol::{
    BotSelfResponse, ConversationKind, Envelope, MessagesResponse, PostMessageRequest,
    ReadHorizonRequest, RealtimeClientFrame, RealtimeServerFrame, RealtimeTicketRequest,
    RealtimeTicketResponse, REALTIME_PROTOCOL_VERSION,
};
use url::Url;

use crate::api::BotApi;
use crate::trust::{verify_owner, OwnerTrust};
use crate::wire::{b64, body_text, bytes, decode_b64, id, text_body};
use crate::{BotError, BotState, PauseReason};

const EVENT_CAPACITY: usize = 256;
const HEARTBEAT: Duration = Duration::from_secs(20);
const CONFIRMATION_POLL: Duration = Duration::from_secs(3);
const TYPING_RENEW: Duration = Duration::from_secs(3);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STABLE_SESSION: Duration = Duration::from_secs(60);
const TICKET_SECONDS: u64 = 25;
const PAGE_LIMIT: u32 = 100;
const MAX_TEXT_UTF16: usize = 8000;

/// A message's position in the owner conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRef {
    pub seq: u64,
    pub epoch: u64,
}

/// What a running [`BotClient`] reports. Events arrive in order on the
/// receiver returned by [`BotClient::connect`].
#[derive(Debug, Clone)]
pub enum BotEvent {
    /// Connected, and the owner conversation is known.
    Ready,
    /// Connected; the owner has not confirmed the bot or opened the chat yet.
    AwaitingOwnerConfirmation,
    /// A verified, decrypted text message from the owner.
    OwnerMessage {
        message_id: String,
        text: String,
        at: MessageRef,
    },
    /// The runner must persist this state (cursor, conversation, a verified
    /// owner succession, a pause).
    StateChanged(BotState),
    /// The connection dropped; the client reconnects by itself.
    Disconnected { reason: String },
    /// The client stopped until a new pairing. A `StateChanged` carrying the
    /// pause precedes this event.
    Paused { reason: PauseReason },
    /// The owner deleted the bot; its credential is dead. The client stopped.
    Revoked,
}

struct Session {
    state: BotState,
    keys: HashMap<u64, tychat_crypto::Key>,
    current_epoch: u64,
    lock_revision: u64,
    history_cutoff_seq: u64,
    announced: Option<bool>,
}

struct Inner {
    api: BotApi,
    session: Mutex<Session>,
    events: mpsc::Sender<BotEvent>,
    typing: SyncMutex<Option<JoinHandle<()>>>,
    dropped: AtomicU64,
}

struct Tasks {
    run: SyncMutex<Option<JoinHandle<()>>>,
    inner: Arc<Inner>,
}

impl Drop for Tasks {
    fn drop(&mut self) {
        if let Some(run) = self.run.lock().ok().and_then(|mut run| run.take()) {
            run.abort();
        }
        self.inner.stop_typing_task();
    }
}

/// A connected personal bot. Cheap to clone; the connection stops when the
/// last clone is dropped or the event receiver is dropped.
#[derive(Clone)]
pub struct BotClient {
    inner: Arc<Inner>,
    _tasks: Arc<Tasks>,
}

enum End {
    Disconnected(String),
    Paused,
    Revoked,
    Closed,
}

impl From<BotError> for End {
    fn from(error: BotError) -> Self {
        match error {
            BotError::Revoked => End::Revoked,
            BotError::Http { status: 401, .. } => End::Revoked,
            BotError::Paused(_) => End::Paused,
            BotError::Closed => End::Closed,
            other => End::Disconnected(other.to_string()),
        }
    }
}

fn revoked_on_401(error: BotError) -> BotError {
    if error.status() == Some(401) {
        BotError::Revoked
    } else {
        error
    }
}

impl BotClient {
    /// Connects a paired bot. `api_base` is the Tychat origin. A state that
    /// is already paused is refused; an owner that deleted the bot answers
    /// [`BotError::Revoked`].
    pub async fn connect(
        api_base: &Url,
        state: BotState,
    ) -> Result<(BotClient, mpsc::Receiver<BotEvent>), BotError> {
        if let Some(reason) = state.paused() {
            return Err(BotError::Paused(reason));
        }
        let api = BotApi::new(api_base, state.credential(), state.device())?;
        let me: BotSelfResponse = api.get("/bot/self").await.map_err(revoked_on_401)?;
        if me.bot_id != state.bot_id()
            || me.device_id != state.device_id()
            || me.owner.account_id != state.owner_account_id()
        {
            return Err(BotError::Protocol("the server describes a different bot"));
        }
        let (events, receiver) = mpsc::channel(EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            api,
            session: Mutex::new(Session {
                state,
                keys: HashMap::new(),
                current_epoch: 0,
                lock_revision: 0,
                history_cutoff_seq: 0,
                announced: None,
            }),
            events,
            typing: SyncMutex::new(None),
            dropped: AtomicU64::new(0),
        });
        let pending = {
            let mut session = inner.session.lock().await;
            let mut pending = Vec::new();
            inner.apply_self(&mut session, me, &mut pending);
            pending
        };
        inner.emit_all(pending).await;
        let run = tokio::spawn(Arc::clone(&inner).run());
        let tasks = Arc::new(Tasks {
            run: SyncMutex::new(Some(run)),
            inner: Arc::clone(&inner),
        });
        Ok((
            BotClient {
                inner,
                _tasks: tasks,
            },
            receiver,
        ))
    }

    /// Sends a text message to the owner. Idempotent on `message_id`: the
    /// same id and text always produce the same envelope, so a retry after a
    /// crash or a lost response never posts twice. Reusing an id for a
    /// different text answers [`BotError::MessageIdConflict`].
    pub async fn send_text(&self, message_id: [u8; 16], text: &str) -> Result<(), BotError> {
        if text.trim().is_empty() {
            return Err(BotError::Protocol("a message needs text"));
        }
        if text.encode_utf16().count() > MAX_TEXT_UTF16 {
            return Err(BotError::MessageTooLong);
        }
        let mut pending = Vec::new();
        let result = {
            let mut session = self.inner.session.lock().await;
            self.inner
                .send_locked(&mut session, message_id, text, &mut pending)
                .await
        };
        self.inner.emit_all(pending).await;
        result
    }

    /// Shows or clears the bot's typing indicator in the owner chat. While
    /// on, the client renews it until it is turned off.
    pub async fn set_typing(&self, typing: bool) -> Result<(), BotError> {
        let (conversation_id, device_id) = {
            let session = self.inner.session.lock().await;
            if let Some(reason) = session.state.paused() {
                return Err(BotError::Paused(reason));
            }
            (
                session
                    .state
                    .conversation_id()
                    .ok_or(BotError::NotConfirmed)?
                    .to_owned(),
                session.state.device_id().to_owned(),
            )
        };
        self.inner.stop_typing_task();
        if typing {
            let path = format!("/typing?deviceId={device_id}&typing={conversation_id}");
            self.inner.post_empty(&path).await?;
            let weak = Arc::downgrade(&self.inner);
            let task = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(TYPING_RENEW).await;
                    let Some(inner) = weak.upgrade() else { return };
                    if inner.post_empty(&path).await.is_err() {
                        return;
                    }
                }
            });
            if let Ok(mut slot) = self.inner.typing.lock() {
                *slot = Some(task);
            }
            Ok(())
        } else {
            self.inner
                .post_empty(&format!(
                    "/typing?deviceId={device_id}&typing_stop={conversation_id}"
                ))
                .await
        }
    }

    /// Marks the owner's messages read through `through`: advances the bot's
    /// read horizon and sends the owner a read receipt.
    pub async fn mark_read(&self, through: MessageRef) -> Result<(), BotError> {
        let mut pending = Vec::new();
        let result = {
            let mut session = self.inner.session.lock().await;
            self.inner
                .mark_read_locked(&mut session, through, &mut pending)
                .await
        };
        self.inner.emit_all(pending).await;
        result
    }

    /// Envelopes dropped because they were not from a verified owner device,
    /// had no key, or failed to verify. Never logged; only counted.
    pub fn dropped_envelopes(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// A snapshot of the current state, for persistence on shutdown.
    pub async fn state(&self) -> BotState {
        self.inner.session.lock().await.state.clone()
    }
}

impl Inner {
    async fn emit_all(&self, events: Vec<BotEvent>) {
        for event in events {
            if self.events.send(event).await.is_err() {
                return;
            }
        }
    }

    fn stop_typing_task(&self) {
        if let Some(task) = self.typing.lock().ok().and_then(|mut slot| slot.take()) {
            task.abort();
        }
    }

    async fn post_empty(&self, path: &str) -> Result<(), BotError> {
        self.api
            .send(Method::POST, path, None::<&()>)
            .await
            .map(|_| ())
            .map_err(revoked_on_401)
    }

    fn pause(
        &self,
        session: &mut Session,
        reason: PauseReason,
        pending: &mut Vec<BotEvent>,
    ) -> BotError {
        session.state.set_paused(reason);
        pending.push(BotEvent::StateChanged(session.state.clone()));
        pending.push(BotEvent::Paused { reason });
        BotError::Paused(reason)
    }

    fn apply_self(&self, session: &mut Session, me: BotSelfResponse, pending: &mut Vec<BotEvent>) {
        if me.owner.identity.identity_id != session.state.owner_identity().identity_id {
            self.pause(session, PauseReason::OwnerIdentityReplaced, pending);
            return;
        }
        if me.conversation_id.as_deref() != session.state.conversation_id() {
            session.state.set_conversation(me.conversation_id.clone());
            session.keys.clear();
            pending.push(BotEvent::StateChanged(session.state.clone()));
        }
        let ready = me.conversation_id.is_some();
        if session.announced != Some(ready) {
            session.announced = Some(ready);
            pending.push(if ready {
                BotEvent::Ready
            } else {
                BotEvent::AwaitingOwnerConfirmation
            });
        }
    }

    async fn refresh(&self, force_self: bool) -> Result<(), BotError> {
        let mut pending = Vec::new();
        let result = {
            let mut session = self.session.lock().await;
            self.refresh_locked(&mut session, force_self, &mut pending)
                .await
        };
        self.emit_all(pending).await;
        result
    }

    async fn refresh_locked(
        &self,
        session: &mut Session,
        force_self: bool,
        pending: &mut Vec<BotEvent>,
    ) -> Result<(), BotError> {
        if let Some(reason) = session.state.paused() {
            return Err(BotError::Paused(reason));
        }
        if force_self || session.state.conversation_id().is_none() {
            let me: BotSelfResponse = self.api.get("/bot/self").await.map_err(revoked_on_401)?;
            self.apply_self(session, me, pending);
            if let Some(reason) = session.state.paused() {
                return Err(BotError::Paused(reason));
            }
        }
        match self.sync_locked(session, pending).await {
            Err(BotError::Http { status: 403, .. }) => {
                let me: BotSelfResponse =
                    self.api.get("/bot/self").await.map_err(revoked_on_401)?;
                self.apply_self(session, me, pending);
                match session.state.paused() {
                    Some(reason) => Err(BotError::Paused(reason)),
                    None => Ok(()),
                }
            }
            other => other,
        }
    }

    async fn sync_locked(
        &self,
        session: &mut Session,
        pending: &mut Vec<BotEvent>,
    ) -> Result<(), BotError> {
        let Some(conversation_id) = session.state.conversation_id().map(str::to_owned) else {
            return Ok(());
        };
        let conversation_bytes = id(&conversation_id)?;
        let owner = session.state.owner_account_id().to_owned();
        let bot = session.state.bot_account_id().to_owned();
        let device_id = session.state.device_id().to_owned();
        let start = session.state.cursor_seq();
        let mut owner_content = false;
        loop {
            let page: MessagesResponse = self
                .api
                .get(&format!(
                    "/conversations/{conversation_id}/messages?after={}&limit={PAGE_LIMIT}&deviceId={device_id}",
                    session.state.cursor_seq()
                ))
                .await
                .map_err(revoked_on_401)?;
            let members: BTreeSet<&str> = page
                .conversation
                .members
                .iter()
                .map(|member| member.account_id.as_str())
                .collect();
            if page.conversation.conversation_id != conversation_id
                || page.conversation.kind != ConversationKind::Direct
                || members != BTreeSet::from([owner.as_str(), bot.as_str()])
            {
                return Err(BotError::Protocol(
                    "the owner conversation is not a direct chat with the owner",
                ));
            }
            session.current_epoch = page.conversation.current_epoch;
            session.lock_revision = page.conversation.lock_revision;
            session.history_cutoff_seq = page.conversation.history_cutoff_seq;
            let trust = match page
                .verification
                .iter()
                .find(|entry| entry.account_id == owner)
            {
                Some(verification) => {
                    match verify_owner(session.state.owner_identity(), verification) {
                        Ok(trust) => trust,
                        Err(reason) => return Err(self.pause(session, reason, pending)),
                    }
                }
                None => OwnerTrust {
                    devices: HashMap::new(),
                    advanced_pin: None,
                },
            };
            if let Some(pin) = trust.advanced_pin.clone() {
                session.state.set_owner_identity(pin);
                pending.push(BotEvent::StateChanged(session.state.clone()));
            }
            for grant in &page.grants {
                if grant.recipient_device_id != device_id
                    || grant.sender_account_id != owner
                    || session.keys.contains_key(&grant.epoch)
                {
                    continue;
                }
                let Some(sig_pub) = trust.devices.get(&grant.sender_device_id) else {
                    continue;
                };
                let opened = (|| {
                    let context = GrantContext {
                        conversation_id: conversation_bytes,
                        epoch: grant.epoch,
                        sender_device_id: id(&grant.sender_device_id)?,
                        recipient_device_id: id(&device_id)?,
                    };
                    tychat_crypto::open_grant(
                        session.state.device(),
                        sig_pub,
                        &context,
                        &decode_b64(&grant.wrapped)?,
                        &bytes(&grant.grant_sig)?,
                    )
                    .map_err(|_| BotError::Crypto)
                })();
                if let Ok(key) = opened {
                    session.keys.insert(grant.epoch, key);
                }
            }
            let mut through = session.state.cursor_seq();
            for envelope in &page.messages {
                through = through.max(envelope.seq);
                if envelope.sender_account_id == bot {
                    continue;
                }
                if envelope.sender_account_id != owner {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                match self.open(session, &trust, &conversation_bytes, envelope) {
                    Ok(Some(text)) => {
                        owner_content = true;
                        pending.push(BotEvent::OwnerMessage {
                            message_id: envelope.message_id.clone(),
                            text,
                            at: MessageRef {
                                seq: envelope.seq,
                                epoch: envelope.epoch,
                            },
                        });
                    }
                    Ok(None) => {}
                    Err(_) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            if !page.has_more {
                through = through.max(page.covered_seq);
            }
            session.state.set_cursor(through);
            if !page.has_more || page.messages.is_empty() {
                break;
            }
        }
        if owner_content {
            self.send_receipt(session, None).await?;
        }
        if session.state.cursor_seq() != start {
            pending.push(BotEvent::StateChanged(session.state.clone()));
        }
        Ok(())
    }

    fn open(
        &self,
        session: &Session,
        trust: &OwnerTrust,
        conversation_id: &[u8; 16],
        envelope: &Envelope,
    ) -> Result<Option<String>, BotError> {
        let sig_pub = trust
            .devices
            .get(&envelope.sender_device_id)
            .ok_or(BotError::Crypto)?;
        let key = session.keys.get(&envelope.epoch).ok_or(BotError::Crypto)?;
        let context = MessageContext {
            conversation_id: *conversation_id,
            message_id: id(&envelope.message_id)?,
            epoch: envelope.epoch,
            sender_device_id: id(&envelope.sender_device_id)?,
            silent_control: envelope.silent_control,
        };
        let plaintext = tychat_crypto::decrypt_message(
            key,
            sig_pub,
            &context,
            &bytes(&envelope.nonce)?,
            &decode_b64(&envelope.ct)?,
            &bytes(&envelope.msg_sig)?,
        )
        .map_err(|_| BotError::Crypto)?;
        if envelope.silent_control {
            return Ok(None);
        }
        Ok(body_text(&plaintext))
    }

    fn deterministic_rng(session: &Session, domain: &[u8], parts: &[&[u8]]) -> ChaCha20Rng {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(session.state.sig_seed());
        for part in parts {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        ChaCha20Rng::from_seed(digest.finalize().into())
    }

    async fn post_envelope(
        &self,
        session: &Session,
        conversation_id: &str,
        message_id: [u8; 16],
        silent_control: bool,
        body: &[u8],
        rng: &mut ChaCha20Rng,
    ) -> Result<(), BotError> {
        let key = session
            .keys
            .get(&session.current_epoch)
            .ok_or(BotError::Protocol("no key for the current epoch"))?;
        let device = session.state.device();
        let encrypted = tychat_crypto::encrypt_message(
            rng,
            key,
            device,
            &MessageContext {
                conversation_id: id(conversation_id)?,
                message_id,
                epoch: session.current_epoch,
                sender_device_id: *device.device_id(),
                silent_control,
            },
            body,
        );
        let request = PostMessageRequest {
            message_id: hex::encode(message_id),
            epoch: session.current_epoch,
            sender_device_id: hex::encode(device.device_id()),
            nonce: b64(&encrypted.nonce),
            ct: b64(&encrypted.ct),
            msg_sig: b64(&encrypted.msg_sig),
            silent_control,
            blob_ids: Vec::new(),
        };
        match self
            .api
            .send(
                Method::POST,
                &format!("/conversations/{conversation_id}/messages"),
                Some(&request),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(BotError::Http { status: 409, code }) if code == "conflict" => {
                Err(BotError::MessageIdConflict)
            }
            Err(error) => Err(revoked_on_401(error)),
        }
    }

    async fn send_locked(
        &self,
        session: &mut Session,
        message_id: [u8; 16],
        text: &str,
        pending: &mut Vec<BotEvent>,
    ) -> Result<(), BotError> {
        if let Some(reason) = session.state.paused() {
            return Err(BotError::Paused(reason));
        }
        if session.state.conversation_id().is_none()
            || !session.keys.contains_key(&session.current_epoch)
        {
            self.refresh_locked(session, false, pending).await?;
        }
        let conversation_id = session
            .state
            .conversation_id()
            .ok_or(BotError::NotConfirmed)?
            .to_owned();
        let mut rng = Self::deterministic_rng(
            session,
            b"tychat-bot-send-v1",
            &[
                conversation_id.as_bytes(),
                &session.current_epoch.to_be_bytes(),
                &message_id,
                text.as_bytes(),
            ],
        );
        self.post_envelope(
            session,
            &conversation_id,
            message_id,
            false,
            &text_body(text),
            &mut rng,
        )
        .await
    }

    async fn mark_read_locked(
        &self,
        session: &mut Session,
        through: MessageRef,
        pending: &mut Vec<BotEvent>,
    ) -> Result<(), BotError> {
        if let Some(reason) = session.state.paused() {
            return Err(BotError::Paused(reason));
        }
        let conversation_id = session
            .state
            .conversation_id()
            .ok_or(BotError::NotConfirmed)?
            .to_owned();
        let read = through.seq.min(session.state.cursor_seq());
        if read <= session.state.receipt_read_through_seq() {
            return Ok(());
        }
        let request = ReadHorizonRequest {
            device_id: session.state.device_id().to_owned(),
            epoch: session.current_epoch,
            lock_revision: session.lock_revision,
            read_through_seq: read,
        };
        self.api
            .send(
                Method::PUT,
                &format!("/conversations/{conversation_id}/read-horizon"),
                Some(&request),
            )
            .await
            .map_err(revoked_on_401)?;
        self.send_receipt(session, Some(read)).await?;
        session.state.set_receipt_read_through(read);
        pending.push(BotEvent::StateChanged(session.state.clone()));
        Ok(())
    }

    /// Sends the owner a delivery receipt through the cursor, carrying the
    /// read horizon when there is one.
    async fn send_receipt(&self, session: &Session, read: Option<u64>) -> Result<(), BotError> {
        let Some(conversation_id) = session.state.conversation_id().map(str::to_owned) else {
            return Ok(());
        };
        let delivered_through = session.state.cursor_seq();
        let delivered_from = session.history_cutoff_seq.saturating_add(1);
        if delivered_through < delivered_from || !session.keys.contains_key(&session.current_epoch)
        {
            return Ok(());
        }
        let read = read
            .or(Some(session.state.receipt_read_through_seq()))
            .filter(|read| *read >= delivered_from && *read <= delivered_through);
        let body = tychat_crypto::encode_receipt_control(&ReceiptControl {
            conversation_id: id(&conversation_id)?,
            epoch: session.current_epoch,
            account_id: session.state.bot_account_id().to_owned(),
            device_id: *session.state.device().device_id(),
            delivered_from_seq: delivered_from,
            delivered_through_seq: delivered_through,
            read_through_seq: read,
        })
        .map_err(|_| BotError::Protocol("receipt encoding failed"))?;
        let parts: [&[u8]; 4] = [
            conversation_id.as_bytes(),
            &session.current_epoch.to_be_bytes(),
            &delivered_through.to_be_bytes(),
            &read.unwrap_or(0).to_be_bytes(),
        ];
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(
            &Sha256::new()
                .chain_update(b"tychat-bot-receipt-id-v1")
                .chain_update(session.state.device().device_id())
                .chain_update(parts.concat())
                .finalize()[..16],
        );
        let mut rng = Self::deterministic_rng(session, b"tychat-bot-receipt-v1", &parts);
        match self
            .post_envelope(session, &conversation_id, message_id, true, &body, &mut rng)
            .await
        {
            Err(BotError::MessageIdConflict) => Ok(()),
            other => other,
        }
    }

    async fn ticket(&self) -> Result<RealtimeTicketResponse, BotError> {
        let device = {
            let session = self.session.lock().await;
            session.state.device().clone()
        };
        let mut rng = rand_core::OsRng;
        let client_instance_id = tychat_crypto::random_id(&mut rng);
        let ticket_request_id = tychat_crypto::random_id(&mut rng);
        let expires = self.api.server_now() + TICKET_SECONDS;
        let request = RealtimeTicketRequest {
            device_id: hex::encode(device.device_id()),
            client_instance_id: hex::encode(client_instance_id),
            ticket_request_id: hex::encode(ticket_request_id),
            expires_at_epoch_seconds: expires,
            possession_sig: b64(&device.sign_realtime_ticket(
                &ticket_request_id,
                &client_instance_id,
                expires,
            )),
            protocol_version: Some(REALTIME_PROTOCOL_VERSION),
        };
        let ticket: RealtimeTicketResponse = self
            .api
            .json(Method::POST, "/realtime/tickets", Some(&request))
            .await
            .map_err(revoked_on_401)?;
        if ticket.protocol != REALTIME_PROTOCOL_VERSION {
            return Err(BotError::Protocol("unsupported realtime protocol"));
        }
        Ok(ticket)
    }

    async fn still_authorized(&self) -> End {
        match self.api.get::<BotSelfResponse>("/bot/self").await {
            Err(error) if error.status() == Some(401) => End::Revoked,
            Err(error) => End::Disconnected(error.to_string()),
            Ok(_) => End::Disconnected("the realtime connection was refused".to_owned()),
        }
    }

    async fn socket_session(&self) -> End {
        let ticket = match self.ticket().await {
            Ok(ticket) => ticket,
            Err(error) => return error.into(),
        };
        let Ok(mut url) = Url::parse(&ticket.web_socket_url) else {
            return End::Disconnected("the realtime URL is invalid".to_owned());
        };
        if !matches!(url.scheme(), "ws" | "wss") {
            return End::Disconnected("the realtime URL is invalid".to_owned());
        }
        url.query_pairs_mut().append_pair("ticket", &ticket.ticket);
        let socket = match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((socket, _)) => socket,
            Err(_) => return End::Disconnected("the realtime connection failed".to_owned()),
        };
        let (mut sink, mut stream) = socket.split();
        if let Err(error) = self.refresh(true).await {
            return error.into();
        }
        let mut heartbeat = tokio::time::interval(HEARTBEAT);
        heartbeat.reset();
        let mut poll = tokio::time::interval(CONFIRMATION_POLL);
        poll.reset();
        loop {
            let awaiting = self.session.lock().await.state.conversation_id().is_none();
            tokio::select! {
                frame = stream.next() => {
                    let text = match frame {
                        Some(Ok(WsMessage::Text(text))) => text,
                        Some(Ok(WsMessage::Close(_))) | None => {
                            return End::Disconnected("the realtime connection closed".to_owned());
                        }
                        Some(Err(_)) => return End::Disconnected("the realtime connection failed".to_owned()),
                        Some(Ok(_)) => continue,
                    };
                    match serde_json::from_str::<RealtimeServerFrame>(text.as_str()) {
                        Ok(RealtimeServerFrame::Refused { .. }) => return self.still_authorized().await,
                        Ok(RealtimeServerFrame::Reconnect { reason, .. }) => {
                            return End::Disconnected(format!("the server asked to reconnect ({reason})"));
                        }
                        Ok(RealtimeServerFrame::Pong { .. } | RealtimeServerFrame::TypingChanged { .. }) => {}
                        Ok(RealtimeServerFrame::AccountEvent { .. }) => {
                            if let Err(error) = self.refresh(true).await {
                                return error.into();
                            }
                        }
                        Ok(_) | Err(_) => {
                            if let Err(error) = self.refresh(false).await {
                                return error.into();
                            }
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let frame = RealtimeClientFrame::Heartbeat { v: REALTIME_PROTOCOL_VERSION };
                    let Ok(frame) = serde_json::to_string(&frame) else { continue };
                    if sink.send(WsMessage::text(frame)).await.is_err() {
                        return End::Disconnected("the realtime connection failed".to_owned());
                    }
                    if let Err(error) = self.refresh(false).await {
                        return error.into();
                    }
                }
                _ = poll.tick(), if awaiting => {
                    if let Err(error) = self.refresh(true).await {
                        return error.into();
                    }
                }
                () = self.events.closed() => return End::Closed,
            }
        }
    }

    async fn run(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            match self.socket_session().await {
                End::Closed | End::Paused => return,
                End::Revoked => {
                    self.stop_typing_task();
                    let _ = self.events.send(BotEvent::Revoked).await;
                    return;
                }
                End::Disconnected(reason) => {
                    if self
                        .events
                        .send(BotEvent::Disconnected { reason })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            if started.elapsed() >= STABLE_SESSION {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}
