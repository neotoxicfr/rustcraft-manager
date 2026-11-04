//! Gestionnaire de fichiers d'un serveur (onglet « Fichiers ») : tout est confiné au dossier du
//! serveur ; chemins relatifs, séparateur `/`, racine = chaîne vide.

use serde::{Deserialize, Serialize};

/// Nature d'une entrée.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Dir,
    File,
    /// Lien symbolique ou jonction : listé, jamais suivi.
    Link,
}

/// Entrée d'un dossier (`GET /api/servers/{id}/files?path=…`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
    /// Dernière modification, instant Unix (s).
    pub modified: i64,
    /// Texte éditable dans l'interface (taille et contenu) ; sinon téléchargeable seulement.
    pub editable: bool,
    /// Porte des secrets (mots de passe, jetons, clés) : lectures tracées.
    pub sensitive: bool,
    /// Tenu par le gestionnaire (`eula.txt`) : modifiable par son écran seulement.
    pub managed: bool,
    /// Nom que le gestionnaire refuse (réservé de Windows, caractère interdit) : listé seulement.
    #[serde(default)]
    pub blocked: bool,
}

/// Contenu d'un dossier.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileList {
    pub path: String,
    pub entries: Vec<FileEntry>,
    /// Liste coupée à [`FILE_LIST_MAX`] entrées.
    #[serde(default)]
    pub truncated: bool,
    /// Dossier du monde (verrouillé pendant démarrage, marche et arrêt).
    #[serde(default)]
    pub world: bool,
}

/// Fichier texte ouvert (`GET /api/servers/{id}/files/read?path=…`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileText {
    pub path: String,
    pub text: String,
    pub hash: String,
    /// Format connu (coloration et vérification par l'analyseur).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<crate::ConfigFormat>,
    pub sensitive: bool,
}

/// `POST /api/servers/{id}/files/write` : écrit un fichier texte (créé si `base_hash` est vide
/// et que le fichier n'existe pas).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileWriteRequest {
    pub path: String,
    pub text: String,
    #[serde(default)]
    pub base_hash: String,
}

/// `POST /api/servers/{id}/files/check` : vérification d'un texte par l'analyseur de son format
/// et par les gardes des réglages (clés gérées, réglages réservés, chemins).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileCheckRequest {
    pub path: String,
    pub text: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileWritten {
    pub hash: String,
    /// Fichier de réglages modifié serveur en marche : pris en compte au prochain démarrage.
    #[serde(default)]
    pub restart_needed: bool,
}

/// `POST /api/servers/{id}/files/mkdir`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilePathRequest {
    pub path: String,
}

/// `POST /api/servers/{id}/files/move` : renommer ou déplacer (`to` : nouveau chemin complet).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileMoveRequest {
    pub from: String,
    pub to: String,
}

/// `POST /api/servers/{id}/files/delete` : vers la corbeille. Dossier : `confirm` = son nom.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileDeleteRequest {
    pub path: String,
    #[serde(default)]
    pub confirm: String,
}

/// Élément de la corbeille (`GET /api/servers/{id}/files/trash`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrashItem {
    pub id: String,
    /// Chemin d'origine.
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    /// Instant Unix (s) de la suppression.
    pub deleted: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// `POST /api/servers/{id}/files/trash/restore`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrashRequest {
    pub id: String,
}

/// `POST /api/servers/{id}/files/trash/purge` : effacement définitif, administrateurs seulement,
/// ré-authentification (mot de passe, + code TOTP s'il est actif).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrashPurgeRequest {
    pub id: String,
    pub reauth: crate::Reauth,
}

/// `POST /api/servers/{id}/files/erase` : effacement définitif d'un élément trop grand pour la
/// corbeille ; administrateurs seulement, ré-authentification, dossier : `confirm` = son nom.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileEraseRequest {
    pub path: String,
    #[serde(default)]
    pub confirm: String,
    pub reauth: crate::Reauth,
}

/// Entrées listées au plus par dossier.
pub const FILE_LIST_MAX: usize = 2000;
/// Taille maximale d'un fichier ouvert dans l'éditeur.
pub const FILE_EDIT_MAX: u64 = 1024 * 1024;
/// Jours avant qu'un élément de la corbeille ne parte de lui-même.
pub const TRASH_DAYS: i64 = 30;
/// Quotas de la corbeille d'un serveur : éléments et octets.
pub const TRASH_MAX_ITEMS: usize = 200;
pub const TRASH_MAX_BYTES: u64 = 16 << 30;
/// Longueur maximale d'un chemin relatif (octets).
pub const FILE_PATH_MAX: usize = 1024;
