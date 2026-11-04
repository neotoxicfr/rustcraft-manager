//! Serveurs Minecraft pilotés : logiciels, versions, état, opérations, console, joueurs,
//! mesures, favoris. Mêmes types pour l'API, le WebSocket et l'interface.

use serde::{Deserialize, Serialize};

/// Logiciel serveur. Forge et NeoForge viendront plus tard.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Software {
    Vanilla,
    Paper,
    Purpur,
    Folia,
    Fabric,
    Quilt,
}

impl Software {
    pub const ALL: [Software; 6] =
        [Software::Vanilla, Software::Paper, Software::Purpur, Software::Folia, Software::Fabric, Software::Quilt];

    /// Identifiant stable (base, API).
    pub fn code(self) -> &'static str {
        match self {
            Software::Vanilla => "vanilla",
            Software::Paper => "paper",
            Software::Purpur => "purpur",
            Software::Folia => "folia",
            Software::Fabric => "fabric",
            Software::Quilt => "quilt",
        }
    }

    pub fn from_code(s: &str) -> Option<Software> {
        Software::ALL.into_iter().find(|x| x.code() == s)
    }

    /// Nom propre affiché (identique dans toutes les langues, sauf « officiel » traduit par
    /// l'interface).
    pub fn name(self) -> &'static str {
        match self {
            Software::Vanilla => "Vanilla",
            Software::Paper => "Paper",
            Software::Purpur => "Purpur",
            Software::Folia => "Folia",
            Software::Fabric => "Fabric",
            Software::Quilt => "Quilt",
        }
    }
}

/// Version du jeu proposée par l'assistant (`GET /api/catalog/{logiciel}`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GameVersion {
    /// Identifiant Mojang (`26.3`, `1.21.11`).
    pub id: String,
    /// Version stable (ni pré-version, ni instantané).
    pub stable: bool,
}

/// Bornes de la mémoire d'un serveur, en Mio.
pub const MEMORY_MIN_MB: u32 = 512;
pub const MEMORY_MAX_MB: u32 = 65_536;
/// Longueur maximale du nom d'un serveur, en caractères.
pub const SERVER_NAME_MAX: usize = 48;
/// Port de jeu par défaut.
pub const DEFAULT_GAME_PORT: u16 = 25565;
/// Ports de jeu acceptés (les ports privilégiés sous 1024 sont refusés).
pub const PORT_MIN: u16 = 1024;

/// Nom de serveur accepté ? (affiché seulement, jamais un chemin).
pub fn server_name_valid(name: &str) -> bool {
    let n = name.trim();
    // Pas d'antislash final : le nom sert de `motd` dans server.properties (continuation de ligne).
    !n.is_empty() && n.chars().count() <= SERVER_NAME_MAX && !n.chars().any(char::is_control) && !n.ends_with('\\')
}

/// Java à utiliser : géré (Temurin téléchargé selon la version du jeu) ou un Java installé.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JavaChoice {
    #[default]
    Managed,
    /// Chemin de l'exécutable `java` (administrateur seulement).
    Path { path: String },
}

/// `POST /api/servers` : création (puis installation en tâche de fond).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CreateServerRequest {
    pub name: String,
    pub software: Software,
    pub version: String,
    pub memory_mb: u32,
    pub port: u16,
    #[serde(default)]
    pub java: JavaChoice,
    /// L'utilisateur a coché l'EULA de Mojang (jamais coché à sa place).
    #[serde(default)]
    pub accept_eula: bool,
}

/// `POST /api/servers/{id}/settings`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerSettingsRequest {
    pub name: String,
    pub memory_mb: u32,
    pub port: u16,
    pub auto_restart: bool,
    #[serde(default)]
    pub java: JavaChoice,
}

/// `POST /api/servers/{id}/eula` : l'utilisateur coche l'EULA.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EulaRequest {
    pub accept: bool,
}

/// `POST /api/servers/{id}/delete` : ré-authentification et nom recopié.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeleteServerRequest {
    pub reauth: crate::Reauth,
    pub confirm_name: String,
}

/// `POST /api/servers/{id}/command`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    pub command: String,
}

/// Longueur maximale d'une commande envoyée à la console.
pub const COMMAND_MAX: usize = 4096;

/// État d'un serveur.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// Pas encore installé (téléchargement à faire ou échoué).
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
    /// Arrêté tout seul (code de sortie non nul ou arrêt non demandé).
    Crashed,
}

/// Panne repérée par le gestionnaire.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerAlert {
    /// Démarré, mais le port de jeu n'est jamais devenu joignable.
    PortNeverOpened,
    /// Plantages répétés : redémarrage automatique abandonné.
    CrashLoop,
    /// Installation ou démarrage impossible (voir `error`).
    Failed,
}

/// Nature d'une opération longue.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    Install,
    Start,
    Stop,
    Restart,
    Delete,
}

/// Étape en cours d'une opération.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpStep {
    Resolve,
    DownloadServer,
    DownloadLibraries,
    DownloadJava,
    Extract,
    Launch,
    WaitPort,
    WaitExit,
}

/// Opération en cours (une seule par serveur).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OperationInfo {
    pub id: u64,
    pub kind: OpKind,
    pub step: OpStep,
    /// Octets reçus et attendus (téléchargements).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// Un serveur, tel que listé et poussé par le WebSocket.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub id: i64,
    pub name: String,
    pub software: Software,
    pub version: String,
    pub state: ServerState,
    pub port: u16,
    pub memory_mb: u32,
    pub auto_restart: bool,
    pub java: JavaChoice,
    /// Version de Java requise par le jeu (majeure).
    pub java_major: u32,
    /// EULA de Mojang acceptée par un utilisateur.
    pub eula: bool,
    /// Instant Unix (s) du dernier démarrage réussi, s'il tourne.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<OperationInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<ServerAlert>,
    /// Dernière erreur (installation, démarrage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::ErrorCode>,
    /// Démarrage refusé par un fichier de réglages (`error` = `LaunchRefused`) : lequel, pourquoi.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<LaunchRefusal>,
    /// Joueurs connectés et maximum (`max-players`).
    pub players: u32,
    pub max_players: u32,
}

/// Fichier qui empêche le démarrage (modifié hors du gestionnaire) et la cause.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LaunchRefusal {
    pub file: String,
    pub cause: LaunchCause,
    /// Réglage en cause (`level-name`, `settings.restart-script`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LaunchCause {
    /// Trop grand, pas du texte, ou lien à la place du fichier.
    Unreadable,
    /// Arbre que le gestionnaire ne sait pas vérifier (ancre, alias, plusieurs documents…).
    Unverifiable(crate::Unverifiable),
    /// Chemin hors du dossier du serveur, ou script de redémarrage refusé.
    UnsafeValue,
}

/// Java installé (`GET /api/java`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JavaInfo {
    pub major: u32,
    pub version: String,
    pub path: String,
    /// Téléchargé par le gestionnaire (`<données>/java/<version>`).
    pub managed: bool,
}

/// Flux d'une ligne de console.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LineSource {
    Out,
    Err,
    /// Commande envoyée depuis le gestionnaire (écho).
    Input,
    /// Message du gestionnaire (démarrage, arrêt, plantage).
    Manager,
}

/// Événement reconnu dans une ligne (vue lisible).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsoleEvent {
    Join {
        player: String,
    },
    Leave {
        player: String,
    },
    Chat {
        player: String,
        text: String,
    },
    Advancement {
        player: String,
        title: String,
    },
    Saved,
    /// Retard du serveur (« Can't keep up »).
    Lag {
        ms: u64,
        ticks: u64,
    },
    /// Serveur prêt (« Done (4.2s)! »), durée en millisecondes.
    Ready {
        ms: u64,
    },
    Stopping,
    Warn {
        text: String,
    },
    Error {
        text: String,
    },
    /// Commande envoyée par un compte du gestionnaire.
    Command {
        user: String,
        command: String,
    },
    /// Message du gestionnaire.
    Manager {
        what: ManagerNote,
    },
}

/// Messages du gestionnaire dans la console.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagerNote {
    Starting,
    Stopped,
    Crashed,
    Killed,
    AutoRestart,
    PortNeverOpened,
}

/// Une ligne de console : texte exact (vue brute) et événement reconnu (vue lisible).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsoleLine {
    /// Numéro croissant par serveur (reprise après reconnexion).
    pub seq: u64,
    /// Instant Unix en millisecondes.
    pub ts: i64,
    pub source: LineSource,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<ConsoleEvent>,
}

/// Joueur connecté.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PlayerInfo {
    pub name: String,
    /// Instant Unix (s) de connexion vu dans le journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
}

/// Mesures d'un serveur, échantillonnées seulement quand quelqu'un regarde.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ServerStats {
    pub ts: i64,
    /// Processeur en % de la machine entière (0 à 100 ; cœurs disponibles pour le gestionnaire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f32>,
    /// Cœurs occupés (1,5 = un cœur et demi).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores_used: Option<f32>,
    /// Cœurs disponibles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<u32>,
    /// Mémoire résidente du processus, en octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tps: Option<f32>,
    /// Temps moyen d'un tick, en millisecondes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mspt: Option<f32>,
}

/// Commande favorite (par compte et par serveur).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Favorite {
    pub id: i64,
    pub label: String,
    pub command: String,
}

/// `POST /api/servers/{id}/favorites`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FavoriteRequest {
    pub label: String,
    pub command: String,
}

/// `POST /api/servers/{id}/favorites/delete`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FavoriteDeleteRequest {
    pub id: i64,
}

/// Favoris par compte et serveur, au plus.
pub const FAVORITES_MAX: usize = 32;
/// Longueur maximale du libellé d'un favori.
pub const FAVORITE_LABEL_MAX: usize = 40;

/// Suggestion d'objet (noms tirés des fichiers de langue de la version du serveur).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ItemSuggestion {
    /// Identifiant sans espace de noms (`diamond_sword`).
    pub id: String,
    pub fr: String,
    pub en: String,
}

/// Suggestion de joueur (connectés, puis déjà venus d'après `usercache.json`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PlayerSuggestion {
    pub name: String,
    pub online: bool,
}

/// Historique de console (`GET /api/servers/{id}/console`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsoleHistory {
    pub lines: Vec<ConsoleLine>,
    pub players: Vec<PlayerInfo>,
}

/// Messages du client sur le WebSocket.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMessage {
    /// Suivre la console et les mesures d'un serveur (`None` : plus aucun).
    Watch { server: Option<i64> },
}
