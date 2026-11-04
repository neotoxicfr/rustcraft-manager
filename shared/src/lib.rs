//! Types de l'API de Rustcraft Manager, communs au binaire (`rc-manager`) et à l'interface
//! WebAssembly (`rc-manager-web`). Aucune dépendance hors `serde` : la crate compile pour les deux
//! cibles.
//!
//! Convention : toutes les routes sont sous `/api`, corps JSON. Toute requête qui modifie quelque
//! chose (POST) porte `Content-Type: application/json` ; une fois connecté, elle porte aussi
//! l'en-tête [`CSRF_HEADER`] avec le jeton reçu dans [`Me::csrf_token`].

use serde::{Deserialize, Serialize};

pub mod access;
pub mod configs;
pub mod files;
pub mod network;
pub mod servers;
pub mod theme;
pub use access::*;
pub use configs::*;
pub use files::*;
pub use network::*;
pub use servers::*;
pub use theme::ThemeSettings;

/// Nom du cookie de session en HTTP simple (HttpOnly, SameSite=Strict).
pub const SESSION_COOKIE: &str = "rcm_session";
/// Nom du cookie de session quand il est `Secure` (HTTPS) : le préfixe `__Host-` interdit qu'un
/// sous-domaine le pose ou l'écrase (Secure, Path=/, aucun Domain imposés par le navigateur).
pub const SESSION_COOKIE_HOST: &str = "__Host-rcm_session";
/// En-tête qui porte le jeton anti-CSRF de la session.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Bornes du nom d'utilisateur (caractères ASCII `a-z A-Z 0-9 _ . -`).
pub const USERNAME_MIN: usize = 3;
pub const USERNAME_MAX: usize = 32;
/// Bornes du mot de passe, en caractères. Le maximum évite de faire hacher des mégaoctets.
pub const PASSWORD_MIN: usize = 10;
pub const PASSWORD_MAX: usize = 256;

/// Nom d'utilisateur accepté ? (même règle des deux côtés).
pub fn username_valid(name: &str) -> bool {
    (USERNAME_MIN..=USERNAME_MAX).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Mot de passe accepté ? (longueur seulement : la longueur fait la force, pas les règles de
/// composition).
pub fn password_valid(pw: &str) -> bool {
    (PASSWORD_MIN..=PASSWORD_MAX).contains(&pw.chars().count())
}

/// Codes d'erreur de l'API, traduits par l'interface.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    InvalidCredentials,
    TooManyAttempts,
    InvalidTotp,
    Unauthorized,
    CsrfRejected,
    SetupNotNeeded,
    InvalidSetupToken,
    InvalidUsername,
    WeakPassword,
    TotpAlreadyEnabled,
    TotpNotEnabled,
    TotpSetupMissing,
    NotFound,
    Internal,
    /// Serveur occupé (hachages de mots de passe saturés, trop de connexions) : réessayer après
    /// `retry_after_secs`.
    Busy,
    /// Requête trop lente (corps non reçu à temps).
    RequestTimeout,
    /// Passkeys désactivées (`RCM_PUBLIC_URL` absente).
    PasskeysDisabled,
    /// Passkey refusée (défi inconnu, expiré ou déjà utilisé, origine, signature, compteur).
    PasskeyRejected,
    /// Nom vide ou trop long.
    InvalidName,
    /// Téléchargement impossible (réseau, hôte, taille, délai).
    DownloadFailed,
    /// Somme de contrôle ou taille d'un téléchargement différente de celle annoncée.
    ChecksumMismatch,
    /// EULA de Mojang pas encore acceptée par un utilisateur.
    EulaRequired,
    /// Port déjà pris (autre serveur du gestionnaire ou autre programme).
    PortInUse,
    /// Port hors bornes.
    InvalidPort,
    /// Mémoire hors bornes.
    InvalidMemory,
    /// Version inconnue pour ce logiciel.
    InvalidVersion,
    /// Une opération est déjà en cours sur ce serveur.
    OperationInProgress,
    /// Serveur pas encore installé.
    NotInstalled,
    /// Serveur arrêté (commande impossible).
    NotRunning,
    /// Java introuvable ou inutilisable.
    JavaNotFound,
    /// Le nom recopié ne correspond pas (suppression).
    NameMismatch,
    /// Action réservée aux administrateurs.
    Forbidden,
    /// Trop d'éléments (favoris…).
    LimitReached,
    /// Commande vide, trop longue ou avec des caractères de contrôle.
    InvalidCommand,
    /// Réglage du thème invalide.
    InvalidTheme,
    /// Le processus serveur n'a pas pu être lancé.
    LaunchFailed,
    /// Fichier de configuration refusé par son analyseur, ou clé gérée par le gestionnaire changée.
    ConfigInvalid,
    /// Le fichier a changé sur le disque depuis son ouverture.
    ConfigChanged,
    /// Fichier trop grand pour l'éditeur.
    FileTooLarge,
    /// Écriture refusée pendant un démarrage ou un arrêt.
    ServerBusy,
    /// Fichier binaire : téléchargeable, pas éditable.
    NotText,
    /// Le monde est ouvert par le serveur (démarrage, marche, arrêt) : l'arrêter d'abord.
    WorldInUse,
    /// Réglage qui ne s'applique que serveur arrêté (niveau d'opérateur, expiration…).
    StopFirst,
    /// Un fichier ou dossier de ce nom existe déjà.
    AlreadyExists,
    /// Pseudo inconnu de Mojang.
    UnknownPlayer,
    /// Mojang injoignable : réessayer.
    LookupFailed,
    /// Fichier tenu par le gestionnaire (`eula.txt`) : modifiable par son écran seulement.
    ManagedFile,
    /// Nom ou chemin refusé (caractère interdit, nom réservé, dossier interne).
    InvalidPath,
    /// Le nom recopié ne correspond pas, ou adresse IP invalide, ou valeur hors bornes.
    InvalidValue,
    /// Place libre insuffisante sur le disque du serveur.
    DiskFull,
    /// Plus grand que toute la corbeille : un administrateur peut l'effacer définitivement.
    TrashTooLarge,
    /// Corbeille pleine : un administrateur doit d'abord la vider (rien n'est effacé en silence).
    TrashFull,
    /// Dossier trop grand pour que ses réglages réservés soient vérifiés : administrateurs.
    TreeTooLarge,
    /// Démarrage refusé par un fichier de réglages (détail dans `ServerInfo::refusal`).
    LaunchRefused,
    /// Nom public invalide (FQDN attendu).
    InvalidHostname,
    /// Nom public hors de la zone DNS configurée (`RCM_DNS_ZONE`).
    OutsideZone,
    /// Aiguilleur coupé (`RCM_ROUTER_PORT` absent).
    RouterDisabled,
    /// Cloudflare injoignable ou en erreur (jeton refusé, zone inconnue).
    DnsFailed,
    /// Le plan a changé depuis l'aperçu : en refaire un.
    PreviewOutdated,
}

/// Corps de toute réponse d'erreur.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
    /// Pour `TooManyAttempts` : secondes avant de pouvoir réessayer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

/// `GET /api/health`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub ok: bool,
    /// Seulement pour une requête locale ou une session ouverte (ne pas annoncer la version à
    /// tout Internet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `GET /version` : empreinte de l'interface (le service worker et l'interface ouverte la
/// comparent pour se recharger après une mise à jour) ; version et commit seulement pour une
/// requête locale ou une session ouverte.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub ui: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// Ré-authentification exigée par les actions sensibles : mot de passe actuel, plus un code TOTP
/// (ou un code de secours) si la double authentification est active.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Reauth {
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// `GET /api/setup` : faut-il créer le premier compte ?
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SetupStatus {
    pub needed: bool,
    /// Connexion par passkey possible (adresse publique configurée).
    #[serde(default)]
    pub passkeys: bool,
}

/// `POST /api/setup` : création du premier compte administrateur, protégée par le jeton à usage
/// unique affiché dans la console du binaire.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SetupRequest {
    pub token: String,
    pub username: String,
    pub password: String,
}

/// `POST /api/auth/login`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Réponse de `POST /api/auth/login` (et de `POST /api/setup`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginResponse {
    /// Connecté : la session est ouverte (cookie posé).
    LoggedIn { me: Me },
    /// Mot de passe bon, double authentification active : envoyer le code à
    /// `POST /api/auth/totp` (session provisoire de quelques minutes, cookie posé).
    TotpRequired,
}

/// `POST /api/auth/totp` : code à 6 chiffres de l'application, ou un code de secours.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TotpLoginRequest {
    pub code: String,
}

/// `GET /api/auth/me` : l'utilisateur connecté.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Me {
    pub username: String,
    pub is_admin: bool,
    pub totp_enabled: bool,
    /// Codes de secours encore utilisables.
    pub recovery_codes_left: u32,
    /// Codes de secours encore utilisables au format de la version 1 (SHA-256 salée) : à
    /// régénérer (`POST /api/account/recovery/regenerate`).
    #[serde(default)]
    pub recovery_codes_legacy: u32,
    /// Jeton anti-CSRF à renvoyer dans [`CSRF_HEADER`].
    pub csrf_token: String,
    /// Thème choisi par ce compte (`None` : thème par défaut).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<ThemeSettings>,
}

/// `POST /api/account/password`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasswordChangeRequest {
    pub reauth: Reauth,
    pub new: String,
}

/// `POST /api/account/totp/setup` : secret proposé (pas encore actif).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TotpSetupResponse {
    /// Secret en base32, pour une saisie à la main.
    pub secret: String,
    /// Lien `otpauth://` (contenu du QR code).
    pub otpauth_uri: String,
    /// QR code en SVG autonome (aucun script, aucun style).
    pub qr_svg: String,
}

/// `POST /api/account/totp/enable` : mot de passe actuel et premier code, qui prouve que
/// l'application est réglée. Les autres sessions sont fermées.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TotpEnableRequest {
    pub reauth: Reauth,
    pub code: String,
}

/// Réponse de `POST /api/account/totp/enable` : codes de secours, montrés une seule fois.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TotpEnableResponse {
    pub recovery_codes: Vec<String>,
}

/// `POST /api/account/totp/disable` : mot de passe et code actuel exigés (dans `reauth`). Les
/// autres sessions sont fermées.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TotpDisableRequest {
    pub reauth: Reauth,
}

/// `POST /api/account/recovery/regenerate` : nouveaux codes de secours (les anciens sont
/// effacés), derrière la ré-authentification. Réponse : [`TotpEnableResponse`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRegenerateRequest {
    pub reauth: Reauth,
}

/// Longueur maximale du nom d'une passkey, en caractères.
pub const PASSKEY_NAME_MAX: usize = 64;

/// Défi WebAuthn rendu par `…/start` : à usage unique, 5 min. `options` est le JSON de
/// WebAuthn (`{"publicKey": …}`, binaires en base64url) à passer à
/// `PublicKeyCredential.parse{Creation,Request}OptionsFromJSON`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyChallenge {
    pub challenge_id: String,
    pub options: String,
}

/// Réponse du navigateur à un défi (`credential.toJSON()` sérialisé).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyFinishRequest {
    pub challenge_id: String,
    pub credential: String,
}

/// `POST /api/account/passkeys/start` : ajout d'une passkey, derrière la ré-authentification.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegisterRequest {
    pub reauth: Reauth,
    pub name: String,
}

/// `POST /api/account/passkeys/delete`, derrière la ré-authentification.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyDeleteRequest {
    pub reauth: Reauth,
    pub id: i64,
}

/// Une passkey du compte (`GET /api/account/passkeys`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub id: i64,
    pub name: String,
    /// Instants Unix (secondes).
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Moyens de transport déclarés (`internal`, `hybrid`, `usb`…).
    pub transports: Vec<String>,
}

/// Messages poussés par le serveur sur `GET /api/ws`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMessage {
    Hello {
        version: String,
    },
    /// Liste complète des serveurs (à l'ouverture, puis à chaque changement d'état).
    Servers {
        servers: Vec<ServerInfo>,
    },
    /// Nouvelles lignes de la console du serveur suivi.
    Console {
        server: i64,
        lines: Vec<ConsoleLine>,
    },
    /// Joueurs connectés du serveur suivi.
    Players {
        server: i64,
        players: Vec<PlayerInfo>,
    },
    /// Mesures du serveur suivi.
    Stats {
        server: i64,
        stats: ServerStats,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_et_mots_de_passe() {
        assert!(username_valid("admin"));
        assert!(username_valid("a.b-c_9"));
        assert!(!username_valid("ab"));
        assert!(!username_valid("é-admin"));
        assert!(!username_valid("a b c"));
        assert!(!username_valid(&"x".repeat(USERNAME_MAX + 1)));
        assert!(password_valid("0123456789"));
        assert!(!password_valid("012345678"));
        assert!(password_valid("éééééééééé"));
        assert!(!password_valid(&"x".repeat(PASSWORD_MAX + 1)));
    }

    #[test]
    fn formes_json_stables() {
        let r = LoginResponse::TotpRequired;
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"status":"totp_required"}"#);
        let e = ApiError { code: ErrorCode::TooManyAttempts, retry_after_secs: Some(30) };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"code":"too_many_attempts","retry_after_secs":30}"#);
        let w = WsServerMessage::Hello { version: "1".into() };
        assert_eq!(serde_json::to_string(&w).unwrap(), r#"{"type":"hello","version":"1"}"#);
    }
}
