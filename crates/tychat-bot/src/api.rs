use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tychat_crypto::{BotRequest, DeviceKeys};
use tychat_protocol::{ErrorBody, BOT_CREDENTIAL_HEADER, BOT_PROOF_HEADER};
use url::Url;

use crate::wire::{b64, now_epoch_seconds};
use crate::BotError;

const PROOF_LIFETIME_SECONDS: u64 = 30;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn http_client() -> Result<reqwest::Client, BotError> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(BotError::network)
}

/// `api_base` is the Tychat origin (`https://chat.tyggs.com`, or
/// `http://127.0.0.1:8790` for the local binary); every route lives under
/// its `/api/v1`.
pub(crate) fn api_url(api_base: &Url, path_and_query: &str) -> Result<(Url, String), BotError> {
    if !matches!(api_base.scheme(), "http" | "https") || api_base.host_str().is_none() {
        return Err(BotError::InvalidState(
            "the API base must be an http(s) origin",
        ));
    }
    let target = format!(
        "{}{}{}",
        api_base.path().trim_end_matches('/'),
        tychat_protocol::API_PREFIX,
        path_and_query
    );
    let url = api_base
        .join(&target)
        .map_err(|_| BotError::InvalidState("the API base is not a valid URL"))?;
    Ok((url, target))
}

pub(crate) async fn error_from(response: reqwest::Response) -> BotError {
    let status = response.status().as_u16();
    let code = response
        .json::<ErrorBody>()
        .await
        .map(|body| body.error.code.as_str().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    BotError::Http { status, code }
}

/// A bot-authenticated HTTP client: every request carries the credential and
/// a fresh device-signed proof bound to its method, path and body.
pub(crate) struct BotApi {
    http: reqwest::Client,
    base: Url,
    credential: String,
    device: DeviceKeys,
    clock_offset: AtomicI64,
}

impl BotApi {
    pub(crate) fn new(base: &Url, credential: &str, device: &DeviceKeys) -> Result<Self, BotError> {
        api_url(base, "/")?;
        Ok(Self {
            http: http_client()?,
            base: base.clone(),
            credential: credential.to_owned(),
            device: device.clone(),
            clock_offset: AtomicI64::new(0),
        })
    }

    pub(crate) fn server_now(&self) -> u64 {
        now_epoch_seconds().saturating_add_signed(self.clock_offset.load(Ordering::Relaxed))
    }

    fn learn_clock(&self, response: &reqwest::Response) -> bool {
        let Some(server) = response
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        else {
            return false;
        };
        let offset = i64::try_from(server.as_secs()).unwrap_or(0)
            - i64::try_from(now_epoch_seconds()).unwrap_or(0);
        let previous = self.clock_offset.swap(offset, Ordering::Relaxed);
        (offset - previous).abs() >= 5
    }

    async fn send_once(
        &self,
        method: &Method,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<reqwest::Response, BotError> {
        let (url, target) = api_url(&self.base, path_and_query)?;
        let mut rng = rand_core::OsRng;
        let request_id = tychat_crypto::random_id(&mut rng);
        let expires = self.server_now() + PROOF_LIFETIME_SECONDS;
        let signature = self.device.sign_bot_request(
            &request_id,
            expires,
            &BotRequest {
                method: method.as_str(),
                path_and_query: &target,
                body,
            },
        );
        let mut request = self
            .http
            .request(method.clone(), url)
            .header(BOT_CREDENTIAL_HEADER, &self.credential)
            .header(
                BOT_PROOF_HEADER,
                format!(
                    "{}.{}.{}",
                    hex::encode(request_id),
                    expires,
                    b64(&signature)
                ),
            );
        if !body.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        request.send().await.map_err(BotError::network)
    }

    /// Sends one request and returns the successful response. A refusal for
    /// an expired proof caused by clock skew is retried once with the
    /// server's clock.
    pub(crate) async fn send(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&impl Serialize>,
    ) -> Result<reqwest::Response, BotError> {
        let body = match body {
            Some(body) => serde_json::to_vec(body)
                .map_err(|_| BotError::Protocol("request encoding failed"))?,
            None => Vec::new(),
        };
        let mut response = self.send_once(&method, path_and_query, &body).await?;
        let skewed = self.learn_clock(&response);
        if response.status() == StatusCode::UNAUTHORIZED && skewed {
            response = self.send_once(&method, path_and_query, &body).await?;
        }
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(error_from(response).await)
        }
    }

    pub(crate) async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, BotError> {
        self.send(method, path_and_query, body)
            .await?
            .json()
            .await
            .map_err(|_| BotError::Protocol("the response is not the expected JSON"))
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        path_and_query: &str,
    ) -> Result<T, BotError> {
        self.json(Method::GET, path_and_query, None::<&()>).await
    }
}
