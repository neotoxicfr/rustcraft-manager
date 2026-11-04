//! Joueurs et accès d'un serveur (onglet « Joueurs ») : liste blanche, opérateurs,
//! bannissements de joueurs et d'adresses, en visuel (ces routes) ou en JSON (routes des
//! réglages, mêmes fichiers).

use serde::{Deserialize, Serialize};

/// Les quatre listes du jeu, dans le dossier du serveur.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AccessList {
    Whitelist,
    Ops,
    BannedPlayers,
    BannedIps,
}

impl AccessList {
    pub const ALL: [AccessList; 4] =
        [AccessList::Whitelist, AccessList::Ops, AccessList::BannedPlayers, AccessList::BannedIps];

    /// Fichier du jeu.
    pub fn file(self) -> &'static str {
        match self {
            AccessList::Whitelist => "whitelist.json",
            AccessList::Ops => "ops.json",
            AccessList::BannedPlayers => "banned-players.json",
            AccessList::BannedIps => "banned-ips.json",
        }
    }

    pub fn from_file(f: &str) -> Option<AccessList> {
        AccessList::ALL.into_iter().find(|l| l.file() == f)
    }

    pub fn code(self) -> &'static str {
        match self {
            AccessList::Whitelist => "whitelist",
            AccessList::Ops => "ops",
            AccessList::BannedPlayers => "banned_players",
            AccessList::BannedIps => "banned_ips",
        }
    }

    pub fn from_code(s: &str) -> Option<AccessList> {
        AccessList::ALL.into_iter().find(|l| l.code() == s)
    }
}

/// Entrée d'une liste (champs absents selon la liste).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessEntry {
    /// Pseudo (listes de joueurs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Adresse (`banned-ips.json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Niveau d'opérateur (1 à 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypasses_player_limit: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Date de fin au format du jeu (`2026-10-20 12:30:00 +0200`), `forever` ou absente.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// `GET /api/servers/{id}/access` : les quatre listes et les réglages liés.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessState {
    pub whitelist: Vec<AccessEntry>,
    pub ops: Vec<AccessEntry>,
    pub banned_players: Vec<AccessEntry>,
    pub banned_ips: Vec<AccessEntry>,
    /// Fichier illisible (JSON invalide) : liste vide ci-dessus, à corriger en mode texte.
    #[serde(default)]
    pub unreadable: Vec<AccessList>,
    /// `white-list` de `server.properties`.
    pub white_list: bool,
    /// `enforce-whitelist` : les joueurs connectés absents de la liste sont expulsés.
    pub enforce_whitelist: bool,
    /// `online-mode` (UUID officiels) ; sinon UUID « hors ligne » calculés depuis le pseudo.
    pub online_mode: bool,
    /// `op-permission-level` : niveau donné par la commande `op` (serveur en marche).
    pub default_op_level: u8,
}

/// `POST /api/servers/{id}/access/add`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccessAddRequest {
    pub list: AccessList,
    /// Pseudo (listes de joueurs) ou adresse (`banned_ips`).
    pub target: String,
    #[serde(default)]
    pub level: Option<u8>,
    #[serde(default)]
    pub bypasses_player_limit: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Fin du bannissement, instant Unix (s) ; absent : définitif.
    #[serde(default)]
    pub expires: Option<i64>,
}

/// `POST /api/servers/{id}/access/remove`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccessRemoveRequest {
    pub list: AccessList,
    pub target: String,
}

/// `POST /api/servers/{id}/access/whitelist` : interrupteurs de la liste blanche.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WhitelistModeRequest {
    pub enabled: bool,
    pub enforce: bool,
}

/// Résultat d'une action : appliquée par la console (serveur en marche, immédiat) ou écrite
/// dans le fichier (serveur arrêté) ; `restart_needed` pour un réglage lu au démarrage seulement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccessApplied {
    pub by_console: bool,
    #[serde(default)]
    pub restart_needed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<AccessEntry>,
}

/// `GET /api/servers/{id}/access/resolve?name=…` : pseudo et UUID.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPlayer {
    /// Pseudo avec la casse officielle.
    pub name: String,
    /// UUID avec tirets.
    pub uuid: String,
    /// UUID hors ligne (calculé depuis le pseudo, `online-mode=false`).
    pub offline: bool,
}

/// Niveaux d'opérateur du jeu.
pub const OP_LEVELS: std::ops::RangeInclusive<u8> = 1..=4;
/// Raison d'un bannissement : longueur maximale (caractères).
pub const BAN_REASON_MAX: usize = 200;
