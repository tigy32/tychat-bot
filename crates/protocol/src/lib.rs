//! Wire contract for the Tychat HTTP API v1 (`design/04-protocol.md`).
//!
//! Plain serde types, `camelCase` on the wire, plus the shape/limit helpers the
//! server uses to validate requests. No behaviour lives here.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const GUEST_TOKEN_HEADER: &str = "x-tigys-guest-token";
pub const API_PREFIX: &str = "/api/v1";

// ── Limits (04-protocol.md "Conventions") ───────────────────────────────────

pub const MAX_CT_BYTES: usize = 64 * 1024;
pub const MAX_BLOB_BYTES: u64 = 50 * 1024 * 1024;
/// Ciphertext cap for a Sidequest entity image (`systems/sidequest-imagery.md`).
/// Deliberately far below `MAX_BLOB_BYTES`: the world worker may write blobs,
/// so its ceiling is the one imagery actually needs, not the attachment one.
pub const MAX_SIDEQUEST_IMAGE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_AVATAR_PLAINTEXT_BYTES: u64 = 96 * 1024;
pub const MAX_AVATAR_CIPHERTEXT_BYTES: u64 = MAX_AVATAR_PLAINTEXT_BYTES + NONCE_BYTES as u64 + 16;
pub const MAX_RECOVERY_VAULT_BYTES: u64 = 8 * 1024 * 1024;
pub const MIN_RECOVERY_VAULT_BYTES: u64 = 1 + NONCE_BYTES as u64 + 16;
pub const MAX_RECOVERY_VAULT_VERSION: u64 = u32::MAX as u64;
pub const MAX_RECOVERY_CREDENTIAL_ID_BYTES: usize = 1024;
pub const MAX_GRANTS_PER_REQUEST: usize = 500;
pub const MAX_MEMBERS_PER_CONVERSATION: usize = 64;
pub const MAX_IDENTITY_MEMBER_ROWS_PER_CONVERSATION: usize = 256;
pub const MAX_LIST_LIMIT: u32 = 100;
pub const DEFAULT_LIST_LIMIT: u32 = 50;
pub const MAX_DIRECTORY_LIMIT: u32 = 20;
pub const MAX_INVITE_CIPHERTEXT_BYTES: usize = 32 * 1024;
pub const CONTACT_INVITE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const DEVICE_REQUEST_TTL_SECONDS: u64 = 15 * 60;
pub const MAX_SYNC_WAIT_SECONDS: u64 = 25;
pub const MAX_GRANT_EPOCHS: u32 = 1000;
pub const MAX_MEMBERSHIPS_READ: u32 = 500;
pub const MAX_PROFILE_CHANGES_PER_SYNC: u32 = 25;
pub const TYPING_MARK_SECONDS: u64 = 6;
pub const REALTIME_TICKET_SECONDS: u64 = 30;
pub const REALTIME_PROTOCOL_VERSION: u32 = 3;
pub const MAX_REALTIME_SERVER_FRAME_BYTES: usize = 24 * 1024;
pub const MAX_EVENT_STATE_BYTES: usize = 64 * 1024;
pub const MAX_EVENT_PAGE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_REALTIME_CONNECTIONS_PER_DEVICE: u32 = 3;
pub const MAX_REALTIME_CONNECTIONS_PER_IDENTITY: u32 = 15;
pub const REALTIME_CONNECTION_STALE_SECONDS: u64 = 9 * 60;
pub const MAX_PUSH_ENDPOINT_BYTES: usize = 2048;
pub const MAX_PUSH_SUBSCRIPTIONS_PER_IDENTITY: u32 = 5;
pub const MAX_PUBLIC_CONTACT_REQUEST_BOXES: usize = 20;
pub const MAX_PUBLIC_CONTACT_REQUEST_BOX_BYTES: usize = 32 * 1024;
pub const MAX_PENDING_PUBLIC_CONTACT_REQUESTS: u32 = 100;
pub const MAX_BLOBS_PER_MESSAGE: usize = 16;
pub const CLEANUP_BATCH_SIZE: u32 = 100;

// ── Fixed byte lengths (ADR-0001) ───────────────────────────────────────────

pub const DEVICE_ID_BYTES: usize = 16;
pub const SIG_PUB_BYTES: usize = 32;
pub const KEM_PUB_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const NONCE_BYTES: usize = 24;
/// `eph_pub(32) || nonce(24) || ct(48)`.
pub const WRAPPED_BYTES: usize = 32 + 24 + 48;
pub const RECOVERY_WRAPPER_BYTES: usize = 1 + 32 + 24 + 48;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthenticated,
    LinkedAccountRequired,
    Forbidden,
    NotFound,
    BadRequest,
    DeviceIdRequired,
    Conflict,
    StaleEpoch,
    StaleBackup,
    RotationRequired,
    MissingGrants,
    PayloadTooLarge,
    IdentityUnavailable,
    StoreUnavailable,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Unauthenticated => 401,
            ErrorCode::LinkedAccountRequired | ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::BadRequest | ErrorCode::MissingGrants => 400,
            ErrorCode::DeviceIdRequired => 409,
            ErrorCode::Conflict
            | ErrorCode::StaleEpoch
            | ErrorCode::StaleBackup
            | ErrorCode::RotationRequired => 409,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::IdentityUnavailable | ErrorCode::StoreUnavailable => 503,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::LinkedAccountRequired => "linked_account_required",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::DeviceIdRequired => "device_id_required",
            ErrorCode::Conflict => "conflict",
            ErrorCode::StaleEpoch => "stale_epoch",
            ErrorCode::StaleBackup => "stale_backup",
            ErrorCode::RotationRequired => "rotation_required",
            ErrorCode::MissingGrants => "missing_grants",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::IdentityUnavailable => "identity_unavailable",
            ErrorCode::StoreUnavailable => "store_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

// ── Identity and devices ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceBundle {
    pub device_id: String,
    pub sig_pub: String,
    pub kem_pub: String,
    pub bundle_sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryMode {
    Standard,
    Strict,
}

impl RecoveryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatement {
    pub identity_id: String,
    pub generation: u64,
    pub root_sig_pub: String,
    pub recovery_mode: RecoveryMode,
    pub statement_sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvatarState {
    Present,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedAvatar {
    pub revision: u64,
    pub state: AvatarState,
    #[serde(default)]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub mime: Option<String>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub sha256: Option<String>,
    pub capability_commitment: String,
    pub statement_sig: String,
    #[serde(default)]
    pub download: Option<DownloadTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedDevice {
    pub device: DeviceBundle,
    pub identity_id: String,
    pub generation: u64,
    pub certificate_sig: String,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationSuccessionProof {
    pub old_statement: IdentityStatement,
    pub new_statement: IdentityStatement,
    pub authorizing_device: CertifiedDevice,
    pub succession_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDevice {
    pub request_id: String,
    pub device: DeviceBundle,
    pub comparison_code: String,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub account_id: String,
    pub display_name: String,
    pub identity: Option<IdentityStatement>,
    pub devices: Vec<CertifiedDevice>,
    pub pending_devices: Vec<PendingDevice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<CertifiedAvatar>,
    /// The account holds Tyggs Pass, as last told by Tyggs Accounts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tyggs_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealtimeTicketRequest {
    pub device_id: String,
    pub client_instance_id: String,
    pub ticket_request_id: String,
    pub expires_at_epoch_seconds: u64,
    pub possession_sig: String,
    #[serde(default)]
    pub protocol_version: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealtimeTicketResponse {
    pub ticket: String,
    pub expires_at_epoch_seconds: u64,
    pub web_socket_url: String,
    pub protocol: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RealtimeClientFrame {
    Heartbeat { v: u32 },
    TypingStart { v: u32, conversation_id: String },
    TypingRenew { v: u32, conversation_id: String },
    TypingStop { v: u32, conversation_id: String },
    DeliveryAck { v: u32, message_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RealtimeServerFrame {
    EventChunk {
        v: u32,
        transfer_id: String,
        index: u32,
        count: u32,
        payload: String,
    },
    TypingChanged {
        v: u32,
        conversation_id: String,
        typing: Vec<TypingIndicator>,
    },
    Pong {
        v: u32,
    },
    Refused {
        v: u32,
        reason: String,
    },
    Reconnect {
        v: u32,
        reason: String,
    },
    ConversationEvent {
        v: u32,
        conversation_id: String,
        event: Box<ConversationEvent>,
    },
    AccountEvent {
        v: u32,
        event: AccountEvent,
        /// Set when this event also carries a visible Web Push; the client
        /// answers with `delivery_ack` so an open app is not notified.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        ack_requested: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdentityRequest {
    pub statement: IdentityStatement,
    pub device: DeviceBundle,
    pub certificate_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResponse {
    pub identity: IdentityStatement,
    pub device: CertifiedDevice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeDeviceRequest {
    pub authorizing_device_id: String,
    pub revocation_sig: String,
    pub succession_sig: String,
    pub replacement: CreateIdentityRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeDeviceResponse {
    pub identity: IdentityStatement,
    pub device: CertifiedDevice,
    pub revoked_device_ids: Vec<String>,
    pub rotation_conversation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryPolicyRequest {
    #[serde(default)]
    pub operation_id: Option<String>,
    pub statement: IdentityStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDeviceRequest {
    pub request_id: String,
    pub device: DeviceBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequestResponse {
    pub request: PendingDevice,
    #[serde(default)]
    pub transfer_nonce: Option<String>,
    #[serde(default)]
    pub transfer_ct: Option<String>,
    #[serde(default)]
    pub certificate_sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveDeviceRequest {
    pub certificate_sig: String,
    pub transfer_nonce: String,
    pub transfer_ct: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateDeviceRequest {
    pub possession_sig: String,
}

// ── Full-history recovery ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitRecoveryBackupRequest {
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitRecoveryBackupResponse {
    pub backup_id: String,
    pub upload: UploadTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitRecoveryBackupRequest {
    pub backup_id: String,
    pub vault_version: u64,
    pub vault_format: u8,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub passkey_credential_id: Option<String>,
    #[serde(default)]
    pub prf_salt: Option<String>,
    #[serde(default)]
    pub passkey_wrapper: Option<String>,
    #[serde(default)]
    pub recovery_code_wrapper: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryBackup {
    pub identity_id: String,
    pub generation: u64,
    pub backup_id: String,
    pub vault_version: u64,
    pub vault_format: u8,
    pub size_bytes: u64,
    pub sha256: String,
    pub passkey_credential_id: Option<String>,
    pub prf_salt: Option<String>,
    pub passkey_wrapper: Option<String>,
    pub recovery_code_wrapper: Option<String>,
    pub updated_at_epoch_seconds: u64,
    pub download: DownloadTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryBackupResponse {
    pub backup: Option<RecoveryBackup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateRecoveryDeviceRequest {
    pub device: DeviceBundle,
    pub certificate_sig: String,
}

pub type RegisterDeviceRequest = DeviceBundle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    pub device: DeviceBundle,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDevicesResponse {
    pub account_id: String,
    pub display_name: String,
    pub identity: IdentityStatement,
    pub devices: Vec<CertifiedDevice>,
    pub successions: Vec<GenerationSuccessionProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub historical: Option<HistoricalCertifiedDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalCertifiedDevice {
    pub identity: IdentityStatement,
    pub device: CertifiedDevice,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDevicesQuery {
    #[serde(default)]
    pub after_generation: Option<u64>,
    #[serde(default)]
    pub historical_device_id: Option<String>,
}

// ── Contacts and private invitations ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateContactInviteRequest {
    pub invite_id: String,
    pub offer_nonce: String,
    pub offer_ct: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptContactInviteRequest {
    pub acceptance_nonce: String,
    pub acceptance_ct: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactInviteState {
    Open,
    Accepted,
    Consumed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInvite {
    pub invite_id: String,
    pub offer_nonce: String,
    pub offer_ct: String,
    pub state: ContactInviteState,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    #[serde(default)]
    pub acceptance_nonce: Option<String>,
    #[serde(default)]
    pub acceptance_ct: Option<String>,
    /// True only for the authenticated identity generation that accepted this invitation.
    #[serde(default)]
    pub accepted_by_current_identity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInviteResponse {
    pub invite: ContactInvite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub account_id: String,
    pub identity: IdentityStatement,
    pub display_name: String,
    pub devices: Vec<CertifiedDevice>,
    pub successions: Vec<GenerationSuccessionProof>,
    pub created_at_epoch_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<CertifiedAvatar>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContactsQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactsResponse {
    pub contacts: Vec<Contact>,
}

// ── Public contact doorways ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicContactDoorwayState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicContactDoorway {
    pub doorway_id: String,
    pub state: PublicContactDoorwayState,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentPublicContactDoorwayResponse {
    pub doorway: Option<PublicContactDoorway>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePublicContactDoorwayRequest {
    pub doorway_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvePublicContactDoorwayResponse {
    pub doorway_id: String,
    pub account_id: String,
    pub identity: IdentityStatement,
    pub display_name: String,
    pub devices: Vec<CertifiedDevice>,
    #[serde(default)]
    pub is_contact_for_current_identity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<CertifiedAvatar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicContactRequestBox {
    pub recipient_device_id: String,
    pub wrapped: String,
    pub request_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePublicContactRequest {
    pub request_id: String,
    pub sender_device_id: String,
    pub boxes: Vec<PublicContactRequestBox>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicContactRequestState {
    Pending,
    Approved,
    Declined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicContactRequestReceipt {
    pub doorway_id: String,
    pub request_id: String,
    pub state: PublicContactRequestState,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicContactRequestReceiptResponse {
    pub request: PublicContactRequestReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicContactRequest {
    pub request_id: String,
    pub doorway_id: String,
    pub requester_identity: IdentityStatement,
    pub requester_display_name: String,
    pub sender_device: CertifiedDevice,
    pub boxes: Vec<PublicContactRequestBox>,
    pub state: PublicContactRequestState,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPublicContactRequestsQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicContactRequestsResponse {
    pub requests: Vec<PublicContactRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecidePublicContactRequest {
    pub device_id: String,
    pub decision_sig: String,
}

// ── Web Push ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushConfigResponse {
    pub enabled: bool,
    pub vapid_public_key: Option<String>,
    /// Apple endpoints from the iPhone app are accepted.
    #[serde(default)]
    pub apns_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertPushSubscriptionRequest {
    pub device_id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub possession_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisablePushSubscriptionRequest {
    pub device_id: String,
    pub possession_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisablePushDeviceRequest {
    pub device_id: String,
    pub possession_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushSubscriptionResponse {
    pub subscription_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushSubscriptionStatusQuery {
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushSubscriptionStatus {
    Active,
    ServerStale,
    ProviderStale,
    ProviderInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushSubscriptionStatusResponse {
    pub status: PushSubscriptionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPushTestRequest {
    pub device_id: String,
    pub subscription_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTestProviderStage {
    Queued,
    ProviderAccepted,
    ProviderRetry,
    ProviderStale,
    ProviderInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTestClientStage {
    Pending,
    Received,
    ShowSucceeded,
    ShowFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushTestResponse {
    pub test_id: String,
    pub provider_stage: PushTestProviderStage,
    pub client_stage: PushTestClientStage,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushTestReceiptRequest {
    pub receipt_digest: String,
    pub stage: PushTestClientStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePushEvent {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_identity_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushTestEvent {
    pub kind: String,
    pub test_id: String,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PushEvent {
    Test(PushTestEvent),
    Message(MessagePushEvent),
}

// ── Conversations ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversationKind {
    Direct,
    Group,
}

impl ConversationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConversationKind::Direct => "direct",
            ConversationKind::Group => "group",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "direct" => Some(ConversationKind::Direct),
            "group" => Some(ConversationKind::Group),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Owner,
    Member,
}

impl MemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberRole::Owner => "owner",
            MemberRole::Member => "member",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(MemberRole::Owner),
            "member" => Some(MemberRole::Member),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TitleCt {
    pub nonce: String,
    pub ct: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub epoch: u64,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    pub wrapped: String,
    pub grant_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockGrant {
    pub epoch: u64,
    pub recipient_identity_id: String,
    pub recipient_revision: u64,
    pub recipient_statement_digest: String,
    pub sender_device_id: String,
    pub wrapped: String,
    pub grant_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConversationRequest {
    pub conversation_id: String,
    pub kind: ConversationKind,
    pub member_account_ids: Vec<String>,
    #[serde(default)]
    pub member_identity_pins: Vec<RosterIdentityPin>,
    #[serde(default)]
    pub roster_signer_device_id: Option<String>,
    #[serde(default)]
    pub roster_sig: Option<String>,
    #[serde(default)]
    pub title_ct: Option<TitleCt>,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub lock_grants: Vec<LockGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterIdentityPin {
    pub account_id: String,
    pub identity: IdentityStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterAttestation {
    pub epoch: u64,
    pub signer_account_id: String,
    pub signer_device_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub account_id: String,
    pub display_name: String,
    pub role: MemberRole,
    pub joined_epoch: u64,
    #[serde(default)]
    pub identity: Option<IdentityStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub rotation_required: bool,
    pub conversation_id: String,
    pub kind: ConversationKind,
    pub title_ct: Option<TitleCt>,
    pub created_by: String,
    pub created_at_epoch_seconds: u64,
    pub current_epoch: u64,
    pub last_seq: u64,
    #[serde(default)]
    pub last_content_seq: u64,
    pub last_message_at_epoch_seconds: u64,
    #[serde(default)]
    pub inbox_visible: bool,
    pub globally_deleted: bool,
    pub history_cutoff_seq: u64,
    #[serde(default)]
    pub deletion_state_version: u64,
    #[serde(default)]
    pub authoritative_read_through_seq: u64,
    #[serde(default)]
    pub authoritative_read_content_count: u64,
    pub members: Vec<Member>,
    pub roster_members: Vec<RosterIdentityPin>,
    #[serde(default)]
    pub roster_attestation: Option<RosterAttestation>,
    #[serde(default)]
    pub lock_revision: u64,
    #[serde(default)]
    pub lock_state: LockState,
    #[serde(default)]
    pub lock_recipients: Vec<LockRecipient>,
    #[serde(default)]
    pub received_content_count: u64,
    #[serde(default)]
    pub placement_revision: u64,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DestructiveScope {
    Me,
    Everyone,
}

impl DestructiveScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Me => "me",
            Self::Everyone => "everyone",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationOperationRequest {
    pub operation_id: String,
    pub scope: DestructiveScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationOperationResponse {
    pub operation_id: String,
    pub conversation_id: String,
    pub action: String,
    pub scope: DestructiveScope,
    pub applied_through_seq: u64,
    pub deletion_state_version: u64,
    pub globally_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConversationResponse {
    pub conversation: Conversation,
    pub existing: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListConversationsQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationsResponse {
    pub conversations: Vec<Conversation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationResponse {
    pub conversation: Conversation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadHorizonRequest {
    pub device_id: String,
    pub epoch: u64,
    pub lock_revision: u64,
    pub read_through_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadHorizonResponse {
    pub conversation_id: String,
    pub authoritative_read_through_seq: u64,
    pub authoritative_read_content_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateEpochRequest {
    #[serde(default)]
    pub operation_id: Option<String>,
    pub new_epoch: u64,
    #[serde(default)]
    pub add_account_ids: Vec<String>,
    #[serde(default)]
    pub remove_account_ids: Vec<String>,
    #[serde(default)]
    pub member_identity_pins: Vec<RosterIdentityPin>,
    #[serde(default)]
    pub roster_signer_device_id: Option<String>,
    #[serde(default)]
    pub roster_sig: Option<String>,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub lock_grants: Vec<LockGrant>,
    #[serde(default)]
    pub title_ct: Option<TitleCt>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantsQuery {
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochGrant {
    pub epoch: u64,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    pub wrapped: String,
    pub grant_sig: String,
    pub sender_account_id: String,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantsResponse {
    pub grants: Vec<EpochGrant>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    #[default]
    None,
    PendingEnable,
    Active,
    PendingDisable,
    Retired,
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockPasswordKind {
    Pin6,
    Passphrase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockRecipient {
    pub identity_id: String,
    pub identity_generation: u64,
    pub recipient_revision: u64,
    pub lrk_sig_pub: String,
    pub lrk_kem_pub: String,
    pub statement_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockKdf {
    pub algorithm: String,
    pub version: u32,
    #[serde(rename = "memoryKiB")]
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockWrapper {
    pub lock_revision: u64,
    pub wrapper_revision: u64,
    pub password_kind: LockPasswordKind,
    pub kdf: LockKdf,
    pub salt: String,
    pub wrapped: String,
    pub wrapper_statement_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableConversationLockRequest {
    pub operation_id: String,
    pub recipient: LockRecipient,
    pub wrapper: LockWrapper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockEnableProgress {
    pub operation_id: String,
    pub target_epoch: u64,
    pub next_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutLockGrantBatchRequest {
    pub operation_id: String,
    pub start_epoch: u64,
    pub grants: Vec<LockGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateConversationLockRequest {
    pub operation_id: String,
    pub rotation: RotateEpochRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationLock {
    pub state: LockState,
    pub lock_revision: u64,
    pub wrapper_revision: u64,
    pub recipient: LockRecipient,
    pub wrapper: Option<LockWrapper>,
    pub received_content_count: u64,
    pub operation_id: Option<String>,
    pub target_epoch: Option<u64>,
    pub next_epoch: Option<u64>,
    #[serde(default)]
    pub disable_device_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationLockResponse {
    pub lock: Option<ConversationLock>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockGrantsQuery {
    #[serde(default)]
    pub after_epoch: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockGrantRecord {
    #[serde(flatten)]
    pub grant: LockGrant,
    pub sender_account_id: String,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockGrantsResponse {
    pub grants: Vec<LockGrantRecord>,
    pub verification: Vec<AccountVerification>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockManifestEntry {
    pub conversation_id: String,
    pub lock_revision: u64,
    pub state: LockState,
    pub received_content_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockManifestResponse {
    pub locks: Vec<LockManifestEntry>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockManifestQuery {
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeConversationPasswordRequest {
    pub recipient: LockRecipient,
    pub wrapper: LockWrapper,
    pub lrk_proof_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableConversationLockRequest {
    pub operation_id: String,
    pub lock_revision: u64,
    pub lrk_proof_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockDisableCursor {
    pub epoch: u64,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutDisableGrantBatchRequest {
    pub operation_id: String,
    pub start: LockDisableCursor,
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetireConversationLockRequest {
    pub operation_id: String,
    pub lrk_proof_sig: String,
    pub rotation: RotateEpochRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbortConversationLockRequest {
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbortConversationLockResponse {
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateConversationPreferenceRequest {
    pub operation_id: String,
    pub revision: u64,
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationPreferenceResponse {
    pub conversation_id: String,
    pub revision: u64,
    pub hidden: bool,
}

// ── AI friend ───────────────────────────────────────────────────────────────

pub const AI_FRIEND_SERVICE_NAMES: [&str; 4] = ["venice", "jenkins", "mira", "tyggs"];
pub const AI_FRIEND_MODEL: &str = "deepseek/deepseek-v4-flash-0731";
/// Image model for Sidequest entity imagery, routed through the same OpenRouter
/// credential, with the separately approved non-ZDR imagery policy
/// (`systems/sidequest-imagery.md`). Generation stays off until the worker is
/// explicitly configured for it, so this constant selects the model but does not
/// by itself enable any image spend.
pub const SIDEQUEST_IMAGE_MODEL: &str = "black-forest-labs/flux.2-klein-4b";
/// Scene illustrations draw on a separate model. Portraits, plates and outfits
/// stay on [`SIDEQUEST_IMAGE_MODEL`], so their prompt digests are untouched.
pub const SIDEQUEST_SCENE_IMAGE_MODEL: &str = "x-ai/grok-imagine-image-2.0";
/// Current art-direction version. Bumping invalidates earlier assets lazily.
pub const SIDEQUEST_IMAGE_STYLE_VERSION: u32 = 2;
/// Bounded generation attempts per entity before the fallback becomes permanent.
pub const SIDEQUEST_IMAGE_MAX_ATTEMPTS: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiFriend {
    pub service_name: String,
    pub account_id: String,
    pub display_name: String,
    pub identity: IdentityStatement,
    pub device: CertifiedDevice,
    pub provider: String,
    pub model: String,
    pub disclosure: String,
    pub personality: String,
    pub picker_art_url: String,
    pub pronouns: String,
    pub existing_conversation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiFriendResponse {
    pub friend: AiFriend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiFriendCatalogResponse {
    pub friends: Vec<AiFriend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiWakeEvent {
    pub service_name: String,
    pub conversation_id: String,
    pub message_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiWorkerMember {
    pub account_id: String,
    pub identity: IdentityStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiWorkerSenderDevice {
    pub account_id: String,
    pub identity: IdentityStatement,
    pub device: CertifiedDevice,
    pub successions: Vec<GenerationSuccessionProof>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConversationCheckpoint {
    pub summary_seq: u64,
    pub summary_covered_seq: u64,
    pub last_trigger_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiWorkerContext {
    pub friend: AiFriend,
    pub conversation_id: String,
    pub current_epoch: u64,
    pub roster: RosterAttestation,
    pub members: Vec<AiWorkerMember>,
    pub grant: EpochGrant,
    pub envelopes: Vec<Envelope>,
    pub sender_devices: Vec<AiWorkerSenderDevice>,
    pub batch_messages: Vec<AiBatchMessage>,
    pub checkpoint_before: u64,
    pub covered_through: u64,
    pub retained_history_from_seq: u64,
    pub checkpoint: AiConversationCheckpoint,
    /// A human member holds Tyggs Pass, by the server's own account rows
    /// (`systems/sidequest-imagery.md`, "Tyggs Pass portraits").
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tyggs_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiBatchMessage {
    pub message_id: String,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAppendKind {
    TurnFailure,
    ResumeAck,
    Reply,
    Scene,
    Summary,
    ReceiptDelivered,
    ReceiptRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiAppendRequest {
    pub checkpoint_before: u64,
    pub first_selected_seq: u64,
    pub covered_through: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_covered_seq: Option<u64>,
    pub messages: Vec<AiAppendMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiAppendMessage {
    pub kind: AiAppendKind,
    pub message: PostMessageRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiCommitOutcome {
    Committed,
    AlreadyCommitted,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiCommitResponse {
    pub outcome: AiCommitOutcome,
    pub reply: Option<PostMessageResponse>,
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageRequest {
    pub message_id: String,
    pub epoch: u64,
    pub sender_device_id: String,
    pub nonce: String,
    pub ct: String,
    pub msg_sig: String,
    #[serde(default)]
    pub silent_control: bool,
    #[serde(default)]
    pub blob_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageResponse {
    pub seq: u64,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesQuery {
    #[serde(default)]
    pub after: Option<u64>,
    #[serde(default)]
    pub before: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub conversation_id: String,
    pub seq: u64,
    pub message_id: String,
    pub sender_account_id: String,
    pub sender_device_id: String,
    pub epoch: u64,
    pub nonce: String,
    pub ct: String,
    pub msg_sig: String,
    #[serde(default)]
    pub silent_control: bool,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesResponse {
    pub covered_seq: u64,
    pub messages: Vec<Envelope>,
    pub has_more: bool,
    pub conversation: Conversation,
    pub verification: Vec<AccountVerification>,
    pub grants: Vec<EpochGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountVerification {
    pub account_id: String,
    pub display_name: String,
    pub identity: IdentityStatement,
    pub devices: Vec<CertifiedDevice>,
    pub successions: Vec<GenerationSuccessionProof>,
    pub historical_devices: Vec<HistoricalCertifiedDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationEpochGrant {
    pub conversation_id: String,
    pub grant: EpochGrant,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSnapshotQuery {
    pub device_id: String,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    /// The `sync_token` of the device's installed snapshot; asks for changes
    /// since it (`design/systems/sync.md`, "Change-only snapshot").
    #[serde(default)]
    pub since: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSnapshotResponse {
    pub entities: Vec<DeviceEntityProjection>,
    pub profile_revisions: std::collections::BTreeMap<String, u64>,
    pub pending_devices: Vec<PendingDevice>,
    pub invites: Vec<ContactInvite>,
    pub verification: Vec<AccountVerification>,
    pub grants: Vec<ConversationEpochGrant>,
    pub seq: u64,
    pub me: Option<MeResponse>,
    pub conversations: Vec<Conversation>,
    pub contacts: Vec<Contact>,
    pub public_requests: Option<PublicContactRequestsResponse>,
    pub doorway: Option<CurrentPublicContactDoorwayResponse>,
    pub recovery: Option<RecoveryBackupResponse>,
    pub next_cursor: Option<String>,
    /// True when the traversal returns only what changed since `since`.
    #[serde(default)]
    pub delta: bool,
    /// On a change-only page, every current membership the page covers.
    #[serde(default)]
    pub member_ids: Vec<String>,
    /// On the first page: what to send as `since` next time.
    #[serde(default)]
    pub sync_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ConversationEvent {
    Envelope {
        event_id: String,
        seq: u64,
        envelope: Envelope,
        verification: Vec<AccountVerification>,
        private: serde_json::Value,
    },
    State {
        event_id: String,
        seq: u64,
        event_type: String,
        state: serde_json::Value,
        created_at_epoch_seconds: u64,
    },
}

impl ConversationEvent {
    pub fn seq(&self) -> u64 {
        match self {
            Self::Envelope { seq, .. } | Self::State { seq, .. } => *seq,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEvent {
    pub event_id: String,
    pub seq: u64,
    pub event_type: String,
    pub state: serde_json::Value,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEntityProjection {
    pub expires_at_epoch_seconds: u64,
    pub key: String,
    pub seq: u64,
    pub deleted: bool,
    pub state: serde_json::Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsQuery {
    #[serde(default)]
    pub after: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationEventsResponse {
    pub events: Vec<ConversationEvent>,
    pub through_seq: u64,
    pub cutoff_seq: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEventHeadResponse {
    pub seq: u64,
}

// ── Typing ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingIndicator {
    pub conversation_id: String,
    pub identity_id: String,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingQuery {
    pub device_id: String,
    #[serde(default)]
    pub typing: Option<String>,
    #[serde(default, rename = "typing_stop")]
    pub typing_stop: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiTypingAction {
    Start,
    Renew,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiTypingRequest {
    pub service_name: String,
    pub lease_id: String,
    pub action: AiTypingAction,
}

// ── Blobs ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitBlobRequest {
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitAvatarUploadRequest {
    pub blob_id: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadTarget {
    pub url: String,
    pub method: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitBlobResponse {
    pub blob_id: String,
    pub upload: UploadTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitBlobResponse {
    pub blob_id: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadTarget {
    pub url: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_resolution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobDownloadResponse {
    pub download: DownloadTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutAvatarRequest {
    pub avatar: CertifiedAvatar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarResponse {
    #[serde(default)]
    pub avatar: Option<CertifiedAvatar>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarQuery {
    #[serde(default)]
    pub doorway_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarCapabilityGrantInput {
    pub recipient_device_id: String,
    pub wrapped: String,
    pub grant_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishAvatarCapabilityGrantsRequest {
    pub sender_device_id: String,
    pub grants: Vec<AvatarCapabilityGrantInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishAvatarCapabilityGrantsResponse {
    pub published: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarCapabilityGrant {
    pub owner_identity_id: String,
    pub generation: u64,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub wrapped: String,
    pub grant_sig: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarCapabilityGrantQuery {
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarCapabilityGrantResponse {
    #[serde(default)]
    pub grant: Option<AvatarCapabilityGrant>,
}

// ── Health ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub ok: bool,
    pub store: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_commit: Option<String>,
}

// ── Shape helpers ───────────────────────────────────────────────────────────

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 32 lowercase hex characters: every id on the wire.
pub fn is_hex32(value: &str) -> bool {
    is_lower_hex(value, 32)
}

/// 64 lowercase hex characters: a SHA-256 digest.
pub fn is_hex64(value: &str) -> bool {
    is_lower_hex(value, 64)
}

/// Decoded length of a standard, padded base64 string, or `None` if the text is
/// not well-formed base64. Empty input is not accepted.
pub fn base64_decoded_len(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - padding];
    if !body
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    {
        return None;
    }
    Some(bytes.len() / 4 * 3 - padding)
}

/// Well-formed base64 that decodes to exactly `len` bytes.
pub fn is_base64_of_len(value: &str, len: usize) -> bool {
    base64_decoded_len(value) == Some(len)
}

/// Well-formed base64 that decodes to at most `max_len` bytes (and at least one).
pub fn is_base64_at_most(value: &str, max_len: usize) -> bool {
    matches!(base64_decoded_len(value), Some(n) if n >= 1 && n <= max_len)
}

/// Clamp a caller-supplied list limit into `1..=max`, defaulting when absent.
pub fn clamp_limit(requested: Option<u32>, default: u32, max: u32) -> u32 {
    requested.unwrap_or(default).clamp(1, max)
}

/// `min(a,b)||':'||max(a,b)` — the one-direct-per-pair key.
pub fn direct_pair_key(a: &str, b: &str) -> String {
    if a <= b {
        format!("{a}:{b}")
    } else {
        format!("{b}:{a}")
    }
}

// ── Personal bots (ADR-0034, systems/bots.md) ───────────────────────────────

pub const BOT_CREDENTIAL_HEADER: &str = "x-tychat-bot-credential";
pub const BOT_PROOF_HEADER: &str = "x-tychat-bot-proof";
pub const BOT_API_VERSION: u32 = 1;
pub const MAX_BOTS_PER_OWNER: usize = 10;
pub const MAX_BOT_DISPLAY_NAME_CHARS: usize = 64;
pub const BOT_PAIRING_TTL_SECONDS: u64 = 600;
pub const BOT_PROOF_WINDOW_SECONDS: u64 = 60;
pub const MAX_BOT_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const BOT_ACCOUNT_PREFIX: &str = "bot:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotStatus {
    Pending,
    Expired,
    Paired,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotView {
    pub bot_id: String,
    pub bot_account_id: String,
    pub display_name: String,
    pub status: BotStatus,
    pub code_expires_at_epoch_seconds: u64,
    pub identity: Option<IdentityStatement>,
    pub device: Option<CertifiedDevice>,
    pub created_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotsResponse {
    pub bots: Vec<BotView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBotRequest {
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBotResponse {
    pub bot: BotView,
    pub pairing_code: String,
    pub code_expires_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotResponse {
    pub bot: BotView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotPairRequest {
    pub pairing_code: String,
    pub statement: IdentityStatement,
    pub device: DeviceBundle,
    pub certificate_sig: String,
    pub pairing_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotOwner {
    pub account_id: String,
    pub display_name: String,
    pub identity: IdentityStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotPairResponse {
    pub bot_id: String,
    pub bot_account_id: String,
    pub display_name: String,
    pub credential: String,
    pub owner: BotOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotSelfResponse {
    pub bot_api: u32,
    pub bot_id: String,
    pub bot_account_id: String,
    pub display_name: String,
    pub device_id: String,
    pub owner: BotOwner,
    pub conversation_id: Option<String>,
}

pub fn bot_account_id(bot_id: &str) -> String {
    format!("{BOT_ACCOUNT_PREFIX}{bot_id}")
}

pub mod sidequest;
