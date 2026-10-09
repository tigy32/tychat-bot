//! Drives a full personal-bot round trip against a local Tychat binary
//! started with `TYCHAT_ALLOW_DEV_IDENTITY=1`:
//!
//! ```text
//! cargo run -p tychat-bot --features owner-kit --bin tychat-bot-kit -- round-trip http://127.0.0.1:8790
//! ```
//!
//! It prints one line per verified step and never prints credentials, keys
//! or message text.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tychat_bot::owner_kit::{BotProbe, OwnerKit, ProbeFault};
use tychat_bot::{pair, BotClient, BotError, BotEvent, Url};

const STEP: Duration = Duration::from_secs(10);
const REVOKE: Duration = Duration::from_secs(25);

const OUT_OF_SCOPE: &[(&str, &str)] = &[
    ("GET", "/me"),
    ("GET", "/device/snapshot"),
    ("POST", "/identity"),
    ("PUT", "/identity/recovery-policy"),
    ("POST", "/identity/recover"),
    ("POST", "/identity/replace"),
    ("POST", "/recovery/backup/uploads"),
    ("GET", "/recovery/backups/{id}/download"),
    ("GET", "/recovery/backup"),
    ("PUT", "/recovery/backup"),
    ("DELETE", "/recovery/backup"),
    ("POST", "/recovery/devices"),
    ("POST", "/devices"),
    ("DELETE", "/devices/{device}"),
    ("POST", "/device-requests"),
    ("GET", "/device-requests/{id}"),
    ("POST", "/device-requests/{id}/approve"),
    ("POST", "/device-requests/{id}/activate"),
    ("GET", "/accounts/{owner}/devices"),
    ("GET", "/contacts"),
    ("GET", "/ai-friend"),
    ("POST", "/ai-friend/tygg/relationship"),
    ("POST", "/profile/avatar/uploads"),
    ("PUT", "/profile/avatar"),
    ("GET", "/profile/avatar/{owner}"),
    ("PUT", "/profile/avatar-capability-grants"),
    ("GET", "/profile/avatar-capability-grants/{owner}"),
    ("GET", "/push/config"),
    ("PUT", "/push/subscriptions"),
    ("POST", "/push/subscriptions/disable-device"),
    ("POST", "/push/tests"),
    ("GET", "/push/tests/{id}"),
    ("DELETE", "/push/subscriptions/{id}"),
    ("GET", "/push/subscriptions/{id}/status"),
    ("POST", "/contact-invites"),
    ("GET", "/contact-invites/{id}"),
    ("DELETE", "/contact-invites/{id}"),
    ("POST", "/contact-invites/{id}/accept"),
    ("POST", "/contact-invites/{id}/confirm"),
    ("GET", "/public-contact-doorways/current"),
    ("PUT", "/public-contact-doorways/current"),
    ("GET", "/public-contact-doorways/{id}"),
    ("DELETE", "/public-contact-doorways/{id}"),
    ("POST", "/public-contact-doorways/{id}/requests"),
    ("GET", "/public-contact-requests"),
    ("POST", "/public-contact-requests/{id}/approve"),
    ("POST", "/public-contact-requests/{id}/decline"),
    ("POST", "/conversations"),
    ("GET", "/conversations"),
    ("POST", "/conversations/{conversation}/epochs"),
    ("POST", "/conversations/{conversation}/clear-history"),
    ("POST", "/conversations/{conversation}/delete"),
    ("GET", "/conversation-locks"),
    ("GET", "/conversations/{conversation}/lock"),
    ("POST", "/conversations/{conversation}/lock/enable"),
    ("PUT", "/conversations/{conversation}/lock/enable/grants"),
    ("POST", "/conversations/{conversation}/lock/enable/activate"),
    ("GET", "/conversations/{conversation}/lock/grants"),
    ("PUT", "/conversations/{conversation}/lock/password"),
    ("POST", "/conversations/{conversation}/lock/disable"),
    ("PUT", "/conversations/{conversation}/lock/disable/grants"),
    ("POST", "/conversations/{conversation}/lock/disable/retire"),
    ("POST", "/conversations/{conversation}/lock/abort"),
    ("POST", "/conversations/{conversation}/locked-leave"),
    ("PUT", "/conversations/{conversation}/preference"),
    ("POST", "/conversations/{conversation}/blobs"),
    ("POST", "/blobs/{id}/commit"),
    ("GET", "/blobs/{id}"),
    ("POST", "/reply-suggestions"),
    ("GET", "/bots"),
    ("POST", "/bots"),
    ("DELETE", "/bots/{bot}"),
    ("POST", "/bots/{bot}/confirm"),
];

const IN_SCOPE_FOREIGN: &[(&str, &str)] = &[
    ("GET", "/conversations/{conversation}"),
    ("GET", "/conversations/{conversation}/messages"),
    ("GET", "/conversations/{conversation}/events"),
    ("GET", "/conversations/{conversation}/grants"),
    ("PUT", "/conversations/{conversation}/read-horizon"),
    ("POST", "/conversations/{conversation}/messages"),
    ("POST", "/typing?deviceId={device}&typing={conversation}"),
];

const INTERNAL: &[(&str, &str)] = &[
    ("POST", "/internal/sidequest/identity"),
    ("POST", "/internal/edge/conversation-outbox"),
    ("POST", "/internal/edge/account-outbox"),
    ("POST", "/internal/ai/context"),
    ("POST", "/internal/ai/conversations/{conversation}/messages"),
    ("POST", "/internal/ai/conversations/{conversation}/typing"),
];

fn fail(message: impl Into<String>) -> String {
    message.into()
}

fn check(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        println!("ok   {message}");
        Ok(())
    } else {
        Err(fail(message))
    }
}

fn err(context: &'static str) -> impl Fn(BotError) -> String {
    move |error| format!("{context}: {error}")
}

async fn next_event(
    events: &mut mpsc::Receiver<BotEvent>,
    within: Duration,
) -> Result<BotEvent, String> {
    tokio::time::timeout(within, events.recv())
        .await
        .map_err(|_| fail("timed out waiting for a bot event"))?
        .ok_or_else(|| fail("the bot event stream ended"))
}

async fn wait_for(
    events: &mut mpsc::Receiver<BotEvent>,
    within: Duration,
    mut wanted: impl FnMut(&BotEvent) -> bool,
) -> Result<BotEvent, String> {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let event = next_event(events, left).await?;
        if let BotEvent::Paused { reason } = &event {
            return Err(format!("the bot paused: {reason}"));
        }
        if wanted(&event) {
            return Ok(event);
        }
    }
}

fn fill(template: &str, conversation: &str, bot: &str, owner: &str, device: &str) -> String {
    let mut random = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
    template
        .replace("{conversation}", conversation)
        .replace("{bot}", bot)
        .replace("{owner}", owner)
        .replace("{device}", device)
        .replace("{id}", &hex::encode(random))
}

fn body_for(method: &str) -> &'static [u8] {
    if matches!(method, "POST" | "PUT") {
        b"{}"
    } else {
        b""
    }
}

async fn round_trip(api: Url) -> Result<(), String> {
    let started = Instant::now();
    let owner = OwnerKit::create(&api, "bot-owner")
        .await
        .map_err(err("owner identity"))?;
    let created = owner
        .create_bot("Echo Kit")
        .await
        .map_err(err("create bot"))?;
    let bot_id = created.bot.bot_id.clone();
    check(
        tychat_protocol::is_hex32(&created.pairing_code),
        "owner created a bot and received a one-time pairing code",
    )?;

    let paired = pair(&api, &created.pairing_code)
        .await
        .map_err(err("pair"))?;
    check(
        paired.owner_fingerprint == owner.fingerprint() && paired.state.bot_id() == bot_id,
        "runner paired and pinned the owner identity",
    )?;
    check(
        matches!(
            pair(&api, &created.pairing_code).await,
            Err(BotError::InvalidPairingCode)
        ),
        "the pairing code is single use",
    )?;
    let state = serde_json::to_string(&paired.state).map_err(|_| fail("state encoding"))?;
    let state: tychat_bot::BotState =
        serde_json::from_str(&state).map_err(|_| fail("state round trip"))?;

    let (client, mut events) = BotClient::connect(&api, state)
        .await
        .map_err(err("connect"))?;
    wait_for(&mut events, STEP, |event| {
        matches!(event, BotEvent::AwaitingOwnerConfirmation)
    })
    .await?;
    println!("ok   runner connected and awaits owner confirmation");
    check(
        matches!(
            client.send_text([1; 16], "too early").await,
            Err(BotError::NotConfirmed)
        ),
        "an unconfirmed bot cannot send",
    )?;

    let chat = owner
        .confirm_bot(&bot_id, &paired.bot_fingerprint)
        .await
        .map_err(err("confirm"))?;
    println!("ok   owner verified the bot fingerprint, confirmed it, and opened the chat");
    wait_for(&mut events, STEP, |event| matches!(event, BotEvent::Ready)).await?;
    println!("ok   runner saw the confirmation and is ready");

    let sent = owner
        .send_text(&chat, "hello bot")
        .await
        .map_err(err("owner send"))?;
    let event = wait_for(&mut events, STEP, |event| {
        matches!(event, BotEvent::OwnerMessage { .. })
    })
    .await?;
    let BotEvent::OwnerMessage { text, at, .. } = event else {
        return Err(fail("unreachable"));
    };
    check(
        text == "hello bot" && at == sent,
        "runner decrypted the owner message",
    )?;

    let reply_id = [7u8; 16];
    client.set_typing(true).await.map_err(err("typing on"))?;
    client
        .send_text(reply_id, &format!("Echo: {text}"))
        .await
        .map_err(err("bot send"))?;
    client.set_typing(false).await.map_err(err("typing off"))?;
    client.mark_read(at).await.map_err(err("mark read"))?;
    let (_, reply) = owner
        .wait_for_bot_text(&chat, sent.seq, STEP)
        .await
        .map_err(err("owner reply"))?;
    check(
        reply == "Echo: hello bot",
        "owner decrypted the echo reply from the confirmed bot device",
    )?;
    owner
        .wait_for_read_receipt(&chat, sent.seq, STEP)
        .await
        .map_err(err("read receipt"))?;
    println!("ok   owner received a valid read receipt from the bot");

    client
        .send_text(reply_id, "Echo: hello bot")
        .await
        .map_err(err("idempotent resend"))?;
    check(
        owner
            .bot_texts(&chat, sent.seq)
            .await
            .map_err(err("owner list"))?
            .len()
            == 1,
        "resending the same message id and text posts nothing new",
    )?;
    check(
        matches!(
            client.send_text(reply_id, "different").await,
            Err(BotError::MessageIdConflict)
        ),
        "reusing a message id for different text is a conflict",
    )?;

    let other_owner = OwnerKit::create(&api, "bot-owner-2")
        .await
        .map_err(err("second owner"))?;
    let other = other_owner
        .create_bot("Other Bot")
        .await
        .map_err(err("second bot"))?;
    let other_paired = pair(&api, &other.pairing_code)
        .await
        .map_err(err("second pair"))?;
    let other_chat = other_owner
        .confirm_bot(&other.bot.bot_id, &other_paired.bot_fingerprint)
        .await
        .map_err(err("second confirm"))?;

    let state = client.state().await;
    let probe = BotProbe::new(&api, &state).map_err(err("probe"))?;
    let device = state.device_id().to_owned();
    let own = state.conversation_id().unwrap_or_default().to_owned();
    check(
        probe
            .status("GET", "/bot/self", b"", ProbeFault::None)
            .await
            .map_err(err("probe"))?
            == 200,
        "a correctly signed probe reaches GET /bot/self",
    )?;
    for (method, template) in OUT_OF_SCOPE {
        let path = fill(template, &own, &bot_id, owner.account_id(), &device);
        let status = probe
            .status(method, &path, body_for(method), ProbeFault::None)
            .await
            .map_err(err("probe"))?;
        if status != 403 {
            return Err(format!(
                "{method} {template} answered {status} to a bot, not 403"
            ));
        }
    }
    println!(
        "ok   all {} out-of-scope routes refuse a bot with 403",
        OUT_OF_SCOPE.len()
    );
    for (method, template) in IN_SCOPE_FOREIGN {
        let path = fill(
            template,
            &other_chat.conversation_id,
            &bot_id,
            owner.account_id(),
            &device,
        );
        let status = probe
            .status(method, &path, body_for(method), ProbeFault::None)
            .await
            .map_err(err("probe"))?;
        if status != 403 {
            return Err(format!(
                "{method} {template} on another conversation answered {status}, not 403"
            ));
        }
    }
    println!(
        "ok   all {} bot routes refuse another owner's bot conversation with 403",
        IN_SCOPE_FOREIGN.len()
    );
    let attachment = serde_json::json!({
        "messageId": "0".repeat(32), "epoch": 0, "senderDeviceId": device,
        "nonce": "", "ct": "", "msgSig": "", "blobIds": ["1".repeat(32)]
    });
    let attachment = serde_json::to_vec(&attachment).map_err(|_| fail("encoding"))?;
    check(
        probe
            .status(
                "POST",
                &format!("/conversations/{own}/messages"),
                &attachment,
                ProbeFault::None,
            )
            .await
            .map_err(err("probe"))?
            == 403,
        "a bot message carrying attachments is refused with 403",
    )?;
    for (method, template) in INTERNAL {
        let path = fill(template, &own, &bot_id, owner.account_id(), &device);
        let status = probe
            .status(method, &path, body_for(method), ProbeFault::None)
            .await
            .map_err(err("probe"))?;
        if !(400..500).contains(&status) {
            return Err(format!("internal {template} answered {status} to a bot"));
        }
    }
    println!(
        "ok   all {} internal routes refuse a bot credential",
        INTERNAL.len()
    );
    for fault in [
        ProbeFault::BadSignature,
        ProbeFault::ExpiredProof,
        ProbeFault::MissingProof,
        ProbeFault::UnknownCredential,
        ProbeFault::GuestTokenAlongside,
    ] {
        let status = probe
            .status("GET", "/bot/self", b"", fault)
            .await
            .map_err(err("probe"))?;
        if status != 401 {
            return Err(format!("{fault:?} answered {status}, not 401"));
        }
    }
    println!(
        "ok   bad, expired and missing proofs, unknown credentials and mixed sessions answer 401"
    );

    owner.delete_bot(&bot_id).await.map_err(err("delete"))?;
    check(
        owner
            .bots()
            .await
            .map_err(err("list"))?
            .iter()
            .all(|bot| bot.bot_id != bot_id),
        "owner deleted the bot",
    )?;
    check(
        probe
            .status("GET", "/bot/self", b"", ProbeFault::None)
            .await
            .map_err(err("probe"))?
            == 401,
        "the deleted bot's credential answers 401",
    )?;
    check(
        matches!(
            client.send_text([9; 16], "after delete").await,
            Err(BotError::Revoked)
        ),
        "sending after deletion reports Revoked",
    )?;
    wait_for(&mut events, REVOKE, |event| {
        matches!(event, BotEvent::Revoked)
    })
    .await?;
    println!("ok   runner reported Revoked and stopped");
    other_owner
        .delete_bot(&other.bot.bot_id)
        .await
        .map_err(err("second delete"))?;
    println!("round trip passed in {} ms", started.elapsed().as_millis());
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [command, api] = args.as_slice() else {
        eprintln!("usage: tychat-bot-kit round-trip <api-base>");
        return ExitCode::from(64);
    };
    let Ok(api) = Url::parse(api) else {
        eprintln!("the API base is not a URL");
        return ExitCode::from(64);
    };
    if command != "round-trip" {
        eprintln!("usage: tychat-bot-kit round-trip <api-base>");
        return ExitCode::from(64);
    }
    match round_trip(api).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("FAIL {message}");
            ExitCode::FAILURE
        }
    }
}
