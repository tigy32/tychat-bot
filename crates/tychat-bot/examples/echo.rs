//! A personal bot that answers every owner message with `Echo: <text>`.
//!
//! ```text
//! cargo run -p tychat-bot --example echo -- <api-base> <state-file> [pairing-code]
//! ```
//!
//! With no state file it pairs with the code and saves the state. It prints
//! only status and fingerprints, never message text.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use tychat_bot::{pair, BotClient, BotEvent, BotState, Url};

fn save(path: &Path, state: &BotState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state).map_err(std::io::Error::other)?;
    let partial = path.with_extension("partial");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&partial)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&partial, path)
}

fn load(path: &Path) -> Result<Option<BotState>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| "the state file is not a valid bot state".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn reply_id(message_id: &str) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"tychat-bot-echo-reply-v1")
        .chain_update(message_id.as_bytes())
        .finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

async fn run(api: Url, path: PathBuf, code: Option<String>) -> Result<ExitCode, String> {
    let state = match load(&path)? {
        Some(state) => state,
        None => {
            let code = code.ok_or("no state file; pass the pairing code from Settings → Bots")?;
            let paired = pair(&api, &code).await.map_err(|error| error.to_string())?;
            save(&path, &paired.state).map_err(|error| error.to_string())?;
            println!("paired as {}", paired.state.display_name());
            paired.state
        }
    };
    println!("bot fingerprint: {}", state.bot_fingerprint());
    println!("owner fingerprint: {}", state.owner_fingerprint());
    let (client, mut events) = BotClient::connect(&api, state)
        .await
        .map_err(|error| error.to_string())?;
    while let Some(event) = events.recv().await {
        match event {
            BotEvent::Ready => println!("ready"),
            BotEvent::AwaitingOwnerConfirmation => println!("awaiting owner confirmation"),
            BotEvent::StateChanged(state) => {
                save(&path, &state).map_err(|error| error.to_string())?
            }
            BotEvent::Disconnected { reason } => println!("disconnected: {reason}"),
            BotEvent::Paused { reason } => {
                println!("paused: {reason}");
                return Ok(ExitCode::from(2));
            }
            BotEvent::Revoked => {
                println!("revoked");
                return Ok(ExitCode::SUCCESS);
            }
            BotEvent::OwnerMessage {
                message_id,
                text,
                at,
            } => {
                client
                    .set_typing(true)
                    .await
                    .map_err(|error| error.to_string())?;
                let sent = client
                    .send_text(reply_id(&message_id), &format!("Echo: {text}"))
                    .await;
                client
                    .set_typing(false)
                    .await
                    .map_err(|error| error.to_string())?;
                sent.map_err(|error| error.to_string())?;
                client
                    .mark_read(at)
                    .await
                    .map_err(|error| error.to_string())?;
                println!("echoed message at seq {}", at.seq);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(api), Some(path)) = (args.next(), args.next()) else {
        eprintln!("usage: echo <api-base> <state-file> [pairing-code]");
        return ExitCode::from(64);
    };
    let Ok(api) = Url::parse(&api) else {
        eprintln!("the API base is not a URL");
        return ExitCode::from(64);
    };
    match run(api, PathBuf::from(path), args.next()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("echo bot failed: {error}");
            ExitCode::FAILURE
        }
    }
}
