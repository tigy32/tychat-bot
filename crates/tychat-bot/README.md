# tychat-bot

The runner library for Tychat **personal bots** (ADR-0034,
`design/systems/bots.md`). A personal bot is a program its owner runs on
their own machine. It holds its own Tychat keys, talks only to its owner in
one end-to-end encrypted direct chat, and can reach nothing else. All
cryptography is the shared `tychat-crypto` core; the server never decrypts.

## API base

| Server | `api_base` |
| --- | --- |
| Production | `https://chat.tyggs.com` (`tychat_bot::PRODUCTION_API_BASE`) |
| Local binary | `http://127.0.0.1:8790` |

`api_base` is the origin; the library adds `/api/v1`. The realtime socket URL
comes from the server's ticket response (`ws://…/api/v1/realtime/socket`
locally, the edge in production).

## API

```rust
pub async fn pair(api_base: &Url, code: &str) -> Result<PairingResult, BotError>;

pub struct PairingResult {
    pub state: BotState,
    pub bot_fingerprint: String,
    pub owner_fingerprint: String,
}

impl BotClient {
    pub async fn connect(api_base: &Url, state: BotState)
        -> Result<(BotClient, mpsc::Receiver<BotEvent>), BotError>;
    pub async fn send_text(&self, message_id: [u8; 16], text: &str) -> Result<(), BotError>;
    pub async fn set_typing(&self, typing: bool) -> Result<(), BotError>;
    pub async fn mark_read(&self, through: MessageRef) -> Result<(), BotError>;
    pub fn dropped_envelopes(&self) -> u64;
    pub async fn state(&self) -> BotState;
}

pub struct MessageRef { pub seq: u64, pub epoch: u64 }

pub enum BotEvent {
    Ready,
    AwaitingOwnerConfirmation,
    OwnerMessage { message_id: String, text: String, at: MessageRef },
    StateChanged(BotState),
    Disconnected { reason: String },
    Paused { reason: PauseReason },
    Revoked,
}

pub enum PauseReason { OwnerIdentityReplaced, OwnerIdentityUnverifiable }
```

`BotState` is `Serialize + Deserialize + Clone`, with a redacted `Debug` and
read-only accessors (`bot_id`, `bot_account_id`, `display_name`,
`device_id`, `owner_account_id`, `owner_display_name`, `conversation_id`,
`cursor_seq`, `paused`, `bot_fingerprint`, `owner_fingerprint`).
Deserializing re-verifies every key and signature in it and refuses a state
that does not check out.

`BotError` variants: `Network`, `Http { status, code }`,
`InvalidPairingCode`, `Revoked`, `Paused(PauseReason)`, `NotConfirmed`,
`MessageIdConflict`, `MessageTooLong`, `Protocol`, `Crypto`, `InvalidState`,
`Closed`. No error message carries a key, the credential, plaintext or
ciphertext.

## Lifecycle

1. The owner creates a bot in Tychat Settings → Bots and gets a one-time,
   10-minute pairing code (QR or text).
2. The runner calls `pair(api_base, code)`, **persists `result.state`
   immediately**, and shows both fingerprints. The code is spent once
   `pair` returns.
3. The owner compares the bot fingerprint in Tychat with the runner's and
   confirms. Tychat opens the owner chat.
4. The runner calls `BotClient::connect` and drains events. Until the owner
   confirms it sees `AwaitingOwnerConfirmation`; then `Ready`, then one
   `OwnerMessage` per verified owner text message, in order.
5. Replies go out with `send_text`, `set_typing` and `mark_read`. Delivery
   receipts are sent automatically; `mark_read` sends the read receipt.
6. If the owner deletes the bot the runner sees `Revoked` and every call
   answers `BotError::Revoked`. Delete the state; pairing again makes a new
   bot.

The client reconnects by itself after `Disconnected`, with backoff up to 30
seconds. It stops when the last `BotClient` clone or the event receiver is
dropped. The event channel holds 256 events; a runner that stops draining it
stalls the client rather than losing events.

## Persisting `BotState`

The state is the bot. It holds the bot's identity root seed, its device
keys and its credential; anyone holding it can act as the bot until the
owner deletes it.

- Save it **before doing anything else** after `pair`.
- Save it again on **every** `BotEvent::StateChanged`, and from
  `client.state()` on shutdown. It carries the message cursor, the owner
  conversation, an advanced owner identity pin and a pause.
- Write atomically: write a sibling temporary file, `fsync` it, then rename
  it over the old one. A torn write is a lost bot.
- Owner-only permissions (`0600`), or the platform's secret store. Never
  log it, print it, commit it or send it anywhere.
- Never run two processes on the same state at once.
- Restoring an older copy is safe for keys but may redeliver messages
  after its cursor; handle `OwnerMessage` idempotently by `message_id`.
- A `Paused` state stays paused; `connect` refuses it. Pair a new bot.

`examples/echo.rs` shows all of this in about a hundred lines.

## Idempotent sends

`send_text(message_id, text)` derives the envelope deterministically from
the bot's secret keys, the conversation, epoch, message id and text. A
retry after a crash or a lost response posts the identical envelope, which
the server accepts as the existing message. Reusing an id for a different
text answers `MessageIdConflict`. Derive reply ids from the message you are
answering (the echo example hashes the owner's message id) so a restart
never double-replies.

## What a bot can do

Bot API v1 only: read and post text in the one owner conversation, read its
grants and events, move its read horizon, show typing, and open a realtime
socket. Everything else, including attachments, refuses with `403`. Text is
at most 8000 UTF-16 code units. Owner messages with attachments arrive as
their caption text alone.

## Trust

The runner pins the owner identity from pairing. It decrypts only envelopes
and grants signed by devices certified by that identity, or by a later
generation reached through verified succession proofs (which advance the pin
and emit `StateChanged`). A replaced or unverifiable owner identity pauses
the runner. Envelopes from anyone else are counted in
`dropped_envelopes()` and never decrypted or logged.

## Examples

Run the local binary with dev identities:

```sh
TYCHAT_ENVIRONMENT=local TYCHAT_STORE_BACKEND=memory TYCHAT_ALLOW_DEV_IDENTITY=1 \
  TYCHAT_SERVER_ADDR=127.0.0.1:8790 cargo run -p tychat-server --bin local
```

Echo bot (pair with a code from Settings → Bots, then run from the state):

```sh
cargo run -p tychat-bot --example echo -- http://127.0.0.1:8790 ./echo-bot.json <pairing-code>
cargo run -p tychat-bot --example echo -- http://127.0.0.1:8790 ./echo-bot.json
```

Owner test kit (feature `owner-kit`; local binary only): plays the owner
with a `dev:` identity, pairs, confirms, exchanges a message, and checks
that every route outside bot API v1, another bot's conversation,
attachments, and bad, expired or missing proofs are refused:

```sh
cargo run -p tychat-bot --features owner-kit --bin tychat-bot-kit -- round-trip http://127.0.0.1:8790
```

## Standalone export

`scripts/publish-bot-sdk.sh <out-dir>` in the Tychat repository exports this
crate with `tychat-crypto` and `tychat-protocol` into a standalone Cargo
workspace stamped with the source commit (`TYCHAT_SOURCE`). The commands
above work unchanged in the export, except the local binary, which stays in
Tychat.
