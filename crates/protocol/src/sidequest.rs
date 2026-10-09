use serde::{Deserialize, Serialize};

fn arrival_wait() -> bool {
    true
}

pub const RULES_VERSION: &str = "sidequest-v2";
pub const LEGACY_RULES_VERSION: &str = "sidequest-v1";
pub const MAX_STEPS: u8 = 8;
pub const WORLD_ID: &str = "00000000000000000000000000000000";
pub const LIBRARY_ID: &str = "00000000000000000000000000000002";
pub const PLAYER_CHARACTER_ID: &str = "00000000000000000000000000000003";
pub const LIBRARY_REQUEST_PREFIX: &str = "sidequest-library-v1:";
pub const LIBRARY_RESPONSE_PREFIX: &str = "sidequest-library-result-v1:";
pub const LIBRARY_LIMIT: i64 = 24;
pub const LIBRARY_DAILY_ATTEMPTS: i64 = 6;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub owner_identity_id: String,
    pub owner_generation: u64,
    pub reset_generation: u64,
    pub entity_id: String,
}
impl Scope {
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 5 || parts[0] != "sidequest" || !id(parts[1]) || !id(parts[4]) {
            return None;
        }
        let scope = Self {
            owner_identity_id: parts[1].into(),
            owner_generation: parts[2].parse().ok()?,
            reset_generation: parts[3].parse().ok()?,
            entity_id: parts[4].into(),
        };
        (scope.service_name() == value
            && scope.owner_generation > 0
            && scope.owner_generation <= i64::MAX as u64
            && scope.reset_generation <= i64::MAX as u64
            && (scope.entity_id != LIBRARY_ID || scope.reset_generation == 0))
            .then_some(scope)
    }
    pub fn service_name(&self) -> String {
        format!(
            "sidequest:{}:{}:{}:{}",
            self.owner_identity_id, self.owner_generation, self.reset_generation, self.entity_id
        )
    }
    pub fn world(&self) -> Self {
        Self {
            entity_id: WORLD_ID.into(),
            ..self.clone()
        }
    }
    pub fn library(&self) -> Self {
        Self {
            entity_id: LIBRARY_ID.into(),
            reset_generation: 0,
            ..self.clone()
        }
    }
    pub fn is_library(&self) -> bool {
        self.entity_id == LIBRARY_ID && self.reset_generation == 0
    }
}
pub fn id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

macro_rules! keyed {
    ($name:ident { $($variant:ident => $key:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const KEYS: &'static [&'static str] = &[$($key),+];
            pub fn key(&self) -> &'static str {
                match self { $(Self::$variant => $key),+ }
            }
        }
    };
}
keyed!(PlaceKind { Home => "home", Bar => "bar", Restaurant => "restaurant", Cafe => "cafe", Shop => "shop", Park => "park", Workplace => "workplace", Street => "street", Venue => "venue", Other => "other" });
keyed!(SpendCategory { Food => "food", Drink => "drink", Goods => "goods", Service => "service", Housing => "housing", Transport => "transport", Gift => "gift", Fine => "fine", Bribe => "bribe", Medical => "medical", Entertainment => "entertainment", Other => "other" });
keyed!(MealSize { Snack => "snack", Meal => "meal", Feast => "feast" });
keyed!(Activity { Wait => "wait", Sleep => "sleep", Socialize => "socialize", Leisure => "leisure", Routine => "routine" });
keyed!(CareLevel { Clinic => "clinic", Hospital => "hospital" });
keyed!(AttemptCategory { StealthCrime => "stealth_crime", ViolentCrime => "violent_crime", Fraud => "fraud", Fight => "fight", Danger => "danger", Skill => "skill" });
keyed!(Difficulty { Easy => "easy", Moderate => "moderate", Hard => "hard", Extreme => "extreme" });
keyed!(Stakes { Low => "low", Medium => "medium", High => "high" });
keyed!(JobTier { Entry => "entry", Skilled => "skilled", Professional => "professional" });
keyed!(RollResult { Success => "success", Partial => "partial", Failure => "failure", CriticalFailure => "critical_failure" });
keyed!(Luck { Lucky => "lucky", Average => "average", Unlucky => "unlucky", Cursed => "cursed" });

pub fn average_luck() -> Luck {
    Luck::Average
}

keyed!(NarrationStyle { Brief => "brief", Standard => "standard", Scenic => "scenic" });
keyed!(PlayerGender { Woman => "woman", Man => "man" });
keyed!(Ledger { Bills => "bills", Credit => "credit" });
keyed!(ChargePeriod { Weekly => "weekly", Monthly => "monthly" });
keyed!(CoreStat { Money => "money", Bills => "bills", Credit => "credit", Health => "health", Fullness => "fullness", Energy => "energy", Mood => "mood", Social => "social", Heat => "heat", Experience => "experience" });

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatChange {
    pub stat: CoreStat,
    pub delta: i64,
}

/// A starting character a player may choose when a life begins. Authored data
/// rather than a database row, identical for every player, and the authority on
/// which templates exist (`systems/sidequest-characters.md`).
///
/// A template is decoration and framing. It grants no money, job, possessions,
/// stats or place: two players who choose the same one still have unrelated
/// lives, and the backstory is an unresolved thread for the narrator rather
/// than an entitlement.
#[derive(Clone, Copy, Debug)]
pub struct StartingCharacter {
    pub id: &'static str,
    pub gender: PlayerGender,
    pub name: &'static str,
    /// Shown to the player on the selection card and given to the narrator as
    /// recent history.
    pub backstory: &'static str,
    /// Describes the shipped portrait so text prompts can draw this person.
    /// Never sent to the client, which has the picture itself.
    pub appearance: &'static str,
    /// Where and how the life opens, given to the narrator so the opening place
    /// is the one the shipped arrival picture shows. It names somewhere to
    /// stand, never something owned. Never sent to the client, which has the
    /// picture itself.
    pub arrival: &'static str,
}

/// Every template that exists. An id here is permanent: a life stores it, so
/// retiring a template means hiding it from selection, never removing the entry.
pub const STARTING_CHARACTERS: &[StartingCharacter] = &[
    StartingCharacter {
        id: "emily",
        gender: PlayerGender::Woman,
        name: "Emily",
        backstory: "She ran away from home and has just arrived in a new city.",
        appearance: "Eighteen, long straight black hair falling past her shoulders, bright green eyes, fair clear skin. A cream knit cardigan over a white blouse, a pleated dark plaid skirt, black tights and brown ankle boots, with a small tan leather shoulder bag.",
        arrival: "She has just stepped down from an overnight coach at the city coach station at first light, one travel bag in her hand, the coach still at the kerb behind her.",
    },
    StartingCharacter {
        id: "jake",
        gender: PlayerGender::Man,
        name: "Jake",
        backstory: "He left home and has just arrived in a new city.",
        appearance: "Eighteen, tall and lean, short dark cropped hair, brown eyes. A charcoal wool work coat over a navy henley, dark trousers and worn leather boots.",
        arrival: "He has just arrived in the city and is standing on a public street near the coach station at first light.",
    },
];

/// Resolves a player-supplied id. An unknown id is refused rather than
/// defaulted, because the id is untrusted input that is about to be persisted.
pub fn starting_character(id: &str) -> Option<&'static StartingCharacter> {
    STARTING_CHARACTERS.iter().find(|entry| entry.id == id)
}

/// The catalogue as the client receives it. `appearance` is deliberately absent:
/// it exists to build image prompts, and the client already has the picture.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartingCharacterView {
    pub id: String,
    pub gender: PlayerGender,
    pub name: String,
    pub backstory: String,
    /// Path within the web bundle. Kept off the `/sidequest/*` prefix, which
    /// CloudFront routes to the game API rather than to static storage.
    pub portrait: String,
    /// The shipped picture of the life's opening moment, shown before any
    /// generated imagery can exist. Same static prefix as `portrait`.
    pub arrival: String,
}

/// The catalogue offered for a new life.
pub fn starting_character_catalogue() -> Vec<StartingCharacterView> {
    STARTING_CHARACTERS
        .iter()
        .map(|entry| StartingCharacterView {
            id: entry.id.to_owned(),
            gender: entry.gender,
            name: entry.name.to_owned(),
            backstory: entry.backstory.to_owned(),
            portrait: format!("/starting-characters/{}.jpg", entry.id),
            arrival: if entry.id == "jake" {
                "/starting-characters/jake.jpg".to_owned()
            } else {
                format!("/starting-characters/{}-arrival-portrait.png", entry.id)
            },
        })
        .collect()
}

/// The voice an existing life keeps when it has never chosen one.
pub fn standard_narration() -> NarrationStyle {
    NarrationStyle::Standard
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoneyEntry {
    pub units: i64,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    ResolveTurn {
        minutes: u32,
        payments: Vec<MoneyEntry>,
        changes: Vec<StatChange>,
    },
    Chance {
        chance: u8,
    },
    AdjustStats {
        changes: Vec<StatChange>,
    },
    SetStat {
        stat_id: Option<String>,
        value: i64,
        minimum: i64,
        maximum: i64,
    },
    RemoveStat {
        stat_id: String,
    },
    CreatePlace {
        category: PlaceKind,
        go: bool,
    },
    Travel {
        place_id: String,
    },
    SetHome {
        place_id: String,
    },
    CreateCharacter {},
    SetOutfit {
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        preserve_image: bool,
    },
    UpdateEntity {
        entity_id: String,
    },
    ExchangeContact {
        character_id: String,
    },
    BookLodging {
        place_id: String,
        units: i64,
    },
    Spend {
        units: i64,
        category: SpendCategory,
    },
    Eat {
        size: MealSize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        units: Option<i64>,
    },
    PassTime {
        activity: Activity,
        minutes: u32,
    },
    Treat {
        level: CareLevel,
    },
    Attempt {
        category: AttemptCategory,
        difficulty: Difficulty,
        stakes: Stakes,
        character_id: Option<String>,
    },
    ScheduleObligation {
        place_id: String,
        due_game_minute: i64,
        duration_minutes: i64,
        repeat_minutes: Option<i64>,
        window_minutes: i64,
        on_complete: Vec<StatChange>,
        on_miss: Vec<StatChange>,
    },
    AttendObligation {
        obligation_id: String,
    },
    CompleteObligation {
        obligation_id: String,
    },
    ArriveForObligation {
        obligation_id: String,
        #[serde(default = "arrival_wait")]
        wait_for_start: bool,
    },
    DoPaidTask {
        minutes: u32,
        units: i64,
    },
    FulfillObligation {
        obligation_id: String,
    },
    WorkRoutine {
        obligation_ids: Vec<String>,
        days: u32,
    },
    RemoveObligation {
        obligation_id: String,
    },
    TakeJob {
        tier: JobTier,
        workplace_id: String,
    },
    QuitJob {},
    GainItem {},
    BuyItem {
        units: i64,
    },
    SellItem {
        possession_id: String,
    },
    DropItem {
        possession_id: String,
    },
    Remember {},
    Forget {
        note_id: String,
    },
    Repay {
        ledger: Ledger,
        units: i64,
    },
    AddObligation {
        units: i64,
        period: ChargePeriod,
        bound_kind: Option<String>,
        bound_id: Option<String>,
    },
    CancelObligation {
        obligation_id: String,
    },
}
impl Command {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ResolveTurn { .. } => "resolve_turn",
            Self::Chance { .. } => "chance",
            Self::AdjustStats { .. } => "adjust_stats",
            Self::SetStat { .. } => "set_stat",
            Self::RemoveStat { .. } => "remove_stat",
            Self::CreatePlace { .. } => "create_place",
            Self::Travel { .. } => "travel",
            Self::SetHome { .. } => "set_home",
            Self::CreateCharacter {} => "create_character",
            Self::SetOutfit { .. } => "set_outfit",
            Self::UpdateEntity { .. } => "update_entity",
            Self::ExchangeContact { .. } => "exchange_contact",
            Self::BookLodging { .. } => "book_lodging",
            Self::Spend { .. } => "spend",
            Self::Eat { .. } => "eat",
            Self::PassTime { .. } => "pass_time",
            Self::Treat { .. } => "treat",
            Self::Attempt { .. } => "attempt",
            Self::ScheduleObligation { .. } => "schedule_obligation",
            Self::AttendObligation { .. } => "attend_obligation",
            Self::CompleteObligation { .. } => "complete_obligation",
            Self::ArriveForObligation { .. } => "arrive_for_obligation",
            Self::DoPaidTask { .. } => "do_paid_task",
            Self::FulfillObligation { .. } => "fulfill_obligation",
            Self::WorkRoutine { .. } => "work_routine",
            Self::RemoveObligation { .. } => "remove_obligation",
            Self::TakeJob { .. } => "take_job",
            Self::QuitJob {} => "quit_job",
            Self::GainItem {} => "gain_item",
            Self::BuyItem { .. } => "buy_item",
            Self::SellItem { .. } => "sell_item",
            Self::DropItem { .. } => "drop_item",
            Self::Remember {} => "remember",
            Self::Forget { .. } => "forget",
            Self::Repay { .. } => "repay",
            Self::AddObligation { .. } => "add_obligation",
            Self::CancelObligation { .. } => "cancel_obligation",
        }
    }
    pub fn model_owned_allowed(&self) -> bool {
        matches!(
            self,
            Self::ResolveTurn { .. }
                | Self::Chance { .. }
                | Self::SetStat { .. }
                | Self::RemoveStat { .. }
                | Self::CreatePlace { .. }
                | Self::Travel { .. }
                | Self::SetHome { .. }
                | Self::CreateCharacter {}
                | Self::SetOutfit { .. }
                | Self::UpdateEntity { .. }
                | Self::ExchangeContact { .. }
                | Self::GainItem {}
                | Self::DropItem { .. }
                | Self::Remember {}
                | Self::Forget { .. }
        )
    }
    pub fn needs_content(&self) -> bool {
        matches!(
            self,
            Self::SetStat { .. }
                | Self::ScheduleObligation { .. }
                | Self::CreatePlace { .. }
                | Self::CreateCharacter {}
                | Self::SetOutfit { .. }
                | Self::UpdateEntity { .. }
                | Self::GainItem {}
                | Self::BuyItem { .. }
                | Self::Remember {}
                | Self::AddObligation { .. }
        )
    }
    pub fn ids(&self) -> Vec<&str> {
        match self {
            Self::WorkRoutine { obligation_ids, .. } => {
                obligation_ids.iter().map(String::as_str).collect()
            }
            Self::SetStat { stat_id, .. } => stat_id.iter().map(String::as_str).collect(),
            Self::RemoveStat { stat_id } => vec![stat_id],
            Self::BookLodging { place_id, .. }
            | Self::Travel { place_id }
            | Self::SetHome { place_id } => vec![place_id],
            Self::UpdateEntity { entity_id } => vec![entity_id],
            Self::ExchangeContact { character_id } => vec![character_id],
            Self::Attempt { character_id, .. } => character_id.iter().map(String::as_str).collect(),
            Self::ScheduleObligation { place_id, .. } => vec![place_id],
            Self::AttendObligation { obligation_id }
            | Self::CompleteObligation { obligation_id }
            | Self::ArriveForObligation { obligation_id, .. }
            | Self::FulfillObligation { obligation_id }
            | Self::RemoveObligation { obligation_id } => vec![obligation_id],
            Self::TakeJob { workplace_id, .. } => vec![workplace_id],
            Self::SellItem { possession_id } | Self::DropItem { possession_id } => {
                vec![possession_id]
            }
            Self::Forget { note_id } => vec![note_id],
            Self::CancelObligation { obligation_id } => vec![obligation_id],
            Self::AddObligation { bound_id, .. } => bound_id.iter().map(String::as_str).collect(),
            _ => Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedContent {
    pub nonce: String,
    pub ct: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Turn {
    pub service_name: String,
    pub source_conversation_id: String,
    pub source_message_id: String,
    pub source_step: u8,
    pub expected_state_version: i64,
    pub command: Command,
    pub content: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TurnSession {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub model_owned: bool,
    pub service_name: String,
    pub source_conversation_id: String,
    pub source_message_id: String,
    pub expected_state_version: i64,
    pub replaces_source_message_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TurnBatch {
    pub session: TurnSession,
    pub turns: Vec<Turn>,
    pub reply: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnPreview {
    pub snapshot: Snapshot,
    pub outcomes: Vec<Outcome>,
    pub roll_source_message_id: String,
    pub cached_reply: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Player {
    pub player_id: String,
    pub reset_generation: i64,
    pub status: String,
    pub birth_game_minute: i64,
    pub game_minute: i64,
    pub money_units: i64,
    pub health: i32,
    pub hunger: i32,
    pub energy: i32,
    pub mood: i32,
    pub social: i32,
    pub heat: i32,
    pub experience_minutes: i64,
    pub state_version: i64,
    pub current_place_id: Option<String>,
    pub residence_place_id: Option<String>,
    pub mature_content: bool,
    #[serde(default = "average_luck")]
    pub luck: Luck,
    #[serde(default = "standard_narration")]
    pub narration_style: NarrationStyle,
    #[serde(default)]
    pub gender: Option<PlayerGender>,
    /// The starting character this life was created from. Null for lives that
    /// began before templates existed, which keep working with gender alone.
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub custom_character_id: Option<String>,
    #[serde(default)]
    pub custom_character_revision: Option<i64>,
    #[serde(default)]
    pub bills_units: i64,
    #[serde(default)]
    pub credit_units: i64,
    #[serde(default)]
    pub credit_limit_units: i64,
    pub world_service_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledObligation {
    pub obligation_id: String,
    pub place_id: String,
    pub due_game_minute: i64,
    pub duration_minutes: i64,
    pub repeat_minutes: Option<i64>,
    pub window_minutes: i64,
    pub status: String,
    pub started_game_minute: Option<i64>,
    pub attended_count: i64,
    pub missed_count: i64,
    pub on_complete: Vec<StatChange>,
    pub on_miss: Vec<StatChange>,
    pub content: Option<SealedContent>,
}
/// A standing charge. `label` is the sealed content reference; the amount,
/// period and due minute are the mechanical facts the server owns.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Obligation {
    pub obligation_id: String,
    pub amount_units: i64,
    pub period: ChargePeriod,
    pub next_due_game_minute: i64,
    pub bound_kind: Option<String>,
    pub bound_id: Option<String>,
    #[serde(default)]
    pub content: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Employment {
    pub job_key: String,
    pub workplace_id: String,
    pub paid_minutes: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub contact: bool,
    #[serde(default)]
    pub place_id: Option<String>,
    pub content: Option<SealedContent>,
    /// Sealed [`Image`] descriptor from the `img:<entity_id>` content row
    /// (`systems/sidequest-imagery.md`). Absent means no image has been
    /// generated yet, which is also the loading state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<SealedContent>,
}

/// The plaintext inside an `img:<entity_id>` content row. The game API stores
/// this sealed and never parses it; only the worker and the owning client do.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    /// `ready` carries `blob`; `failed` carries only `attempts`.
    pub status: ImageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<ImageBlob>,
    /// Bounded generation attempts already spent on this entity.
    pub attempts: u8,
    /// Monotonic art-direction version, so a style change can invalidate
    /// earlier assets lazily rather than through a migration.
    pub style_version: u32,
    /// Provider seed, so a retry reproduces the same subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Digest of the exact prompt this descriptor was generated from, plus the
    /// model. A deliberate appearance change through `update_entity` changes the
    /// prompt, which changes this digest, which invalidates the portrait —
    /// without needing a separate invalidation path.
    #[serde(default)]
    pub prompt_sha256: String,
    #[serde(default)]
    pub model: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageStatus {
    Ready,
    Failed,
}

/// Blob reference plus the key needed to open it. Never leaves sealed content.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageBlob {
    pub blob_id: String,
    pub key: String,
    pub nonce: String,
    pub mime: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Written to `sidequest_content` at `img:<entity_id>`. Carries no mechanical
/// effect: it never advances `state_version` and never creates an action.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageWrite {
    pub service_name: String,
    pub entity_id: String,
    pub content: SealedContent,
    /// Compare-and-set guard: the `ct` the writer believes is currently stored,
    /// or `None` to mean "no row yet". The game API compares it as an opaque
    /// string without decrypting anything, which lets concurrent workers
    /// serialise without exposing any image metadata to a mechanical column.
    #[serde(default)]
    pub expected_ct: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageWriteResult {
    /// False when the guard did not match, meaning another writer got there
    /// first and this writer must not proceed.
    pub written: bool,
}

/// `content_id` for an entity's image descriptor row.
pub const PLAYER_OUTFIT_ID: &str = "00000000000000000000000000000001";
pub const PLAYER_OUTFIT_CONTENT: &str = "player-outfit";
pub fn image_content_id(entity_id: &str) -> String {
    let entity_id = if entity_id == PLAYER_CHARACTER_ID {
        "player-character"
    } else if entity_id == PLAYER_OUTFIT_ID {
        PLAYER_OUTFIT_CONTENT
    } else {
        entity_id
    };
    format!("img:{entity_id}")
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Possession {
    pub id: String,
    pub value_units: i64,
    pub stolen: bool,
    pub content: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub id: String,
    pub content: SealedContent,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    #[serde(default)]
    pub custom_character: Option<Entity>,
    #[serde(default)]
    pub outfit: Option<Entity>,
    #[serde(default)]
    pub latest_turn_source: Option<String>,
    pub player: Player,
    pub employment: Option<Employment>,
    pub places: Vec<Entity>,
    pub characters: Vec<Entity>,
    #[serde(default)]
    pub possessions: Vec<Possession>,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
    #[serde(default)]
    pub scheduled_obligations: Vec<ScheduledObligation>,
    #[serde(default)]
    pub custom_stats: Vec<CustomStat>,
    #[serde(default)]
    pub recent_actions: Vec<ActionReceipt>,
    /// The templates a new life may choose from. Static and identical for every
    /// player; sent with the snapshot so the client cannot hold a stale copy.
    #[serde(default)]
    pub starting_characters: Vec<StartingCharacterView>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionReceipt {
    pub game_minute: i64,
    #[serde(flatten)]
    pub outcome: Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomStat {
    pub stat_id: String,
    pub value: i64,
    pub minimum: i64,
    pub maximum: i64,
    pub content: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Roll {
    pub chance: u8,
    pub value: u8,
    pub result: RollResult,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Outcome {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payments: Vec<MoneyEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<WorkReceipt>,
    pub action_id: String,
    pub action_kind: String,
    pub step: u8,
    pub accepted: bool,
    pub reason: String,
    pub money_delta: i64,
    pub elapsed_minutes: i64,
    pub health_delta: i64,
    pub hunger_delta: i64,
    pub energy_delta: i64,
    pub mood_delta: i64,
    pub social_delta: i64,
    pub heat_delta: i64,
    pub entity_id: Option<String>,
    pub roll: Option<Roll>,
    pub arrested: bool,
    pub hospitalized: bool,
    pub died: bool,
    pub state_version: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkReceipt {
    pub requested_minutes: i64,
    pub completed: u32,
    pub earned_units: i64,
    pub meal_units: i64,
    pub stopped: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub step: u8,
    pub command: Command,
    pub outcome: Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub mature_content: bool,
    #[serde(default)]
    pub luck: Option<Luck>,
    #[serde(default = "standard_narration")]
    pub narration_style: NarrationStyle,
    pub gender: PlayerGender,
    /// Set once, when the life begins. Later settings writes carry it as null
    /// and leave the stored value alone.
    #[serde(default)]
    pub template_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityRegistration {
    pub service_name: String,
    pub owner_account_id: String,
    pub identity: crate::IdentityStatement,
    pub device: crate::CertifiedDevice,
}

pub fn principal_id(service: &str, purpose: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest =
        Sha256::digest(format!("tychat-sidequest-principal-v1:{service}:{purpose}").as_bytes());
    hex::encode(&digest[..16])
}

pub fn action_id(scope: &Scope, conversation: &str, message: &str, step: u8) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(
        format!(
            "sidequest-action-v2:{}:{conversation}:{message}:{step}",
            scope.world().service_name()
        )
        .as_bytes(),
    );
    hex::encode(&digest[..16])
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomCharacter {
    pub name: String,
    pub gender: PlayerGender,
    pub appearance: String,
    pub backstory: String,
}
impl CustomCharacter {
    pub fn valid(&self) -> bool {
        [
            (&self.name, 80),
            (&self.appearance, 1000),
            (&self.backstory, 3000),
        ]
        .iter()
        .all(|(text, limit)| !text.trim().is_empty() && text.chars().count() <= *limit)
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= 6144)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryEntry {
    pub retired: Vec<RetiredPortrait>,
    pub character_id: String,
    pub revision: i64,
    pub draft_revision: i64,
    pub accepted: Option<SealedContent>,
    pub draft: SealedContent,
    pub portrait: Option<SealedContent>,
    pub draft_portrait: Option<SealedContent>,
    pub status: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LibraryRequest {
    pub request_id: String,
    pub action: String,
    #[serde(default)]
    pub character_id: Option<String>,
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub character: Option<CustomCharacter>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub world_conversation_id: Option<String>,
    #[serde(default)]
    pub reset_generation: Option<u64>,
    #[serde(default)]
    pub luck: Option<Luck>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LibraryWrite {
    #[serde(default)]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub retired: Vec<RetiredPortrait>,
    pub service_name: String,
    pub source_conversation_id: String,
    pub source_message_id: String,
    pub source_seq: u64,
    pub character_id: String,
    pub revision: i64,
    pub action: String,
    #[serde(default)]
    pub content: Option<SealedContent>,
    #[serde(default)]
    pub portrait: Option<SealedContent>,
    #[serde(default)]
    pub result: Option<SealedContent>,
    #[serde(default)]
    pub reset_generation: Option<u64>,
    #[serde(default)]
    pub gender: Option<PlayerGender>,
    #[serde(default)]
    pub luck: Option<Luck>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryJob {
    pub retry_until: i64,
    pub source_message_id: String,
    pub status: String,
    pub result: Option<SealedContent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryState {
    pub entries: Vec<LibraryEntry>,
    pub next_cursor: Option<String>,
    pub attempts_remaining: i64,
    pub job: Option<LibraryJob>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetiredPortrait {
    pub revision: i64,
    pub portrait: SealedContent,
}
