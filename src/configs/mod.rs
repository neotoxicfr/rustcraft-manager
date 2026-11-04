//! Fichiers de configuration propres au logiciel d'un serveur (onglet « Réglages ») : liste
//! détectée sur le disque, confinement au dossier du serveur, lecture bornée, vérification par
//! l'analyseur du format, éditions ciblées vérifiées (rien d'autre ne bouge), empreintes.
//!
//! Garde : un chemin n'est accepté que s'il appartient à la liste blanche du logiciel
//! (`server.properties`, fichiers Bukkit/Spigot/Paper/Purpur, `config/` des mods), segment par
//! segment sans `..` ni nom réservé, sans lien symbolique sur le trajet, et si sa forme
//! canonique reste sous le dossier canonique du serveur.

pub mod json;
pub mod toml;
pub mod yaml;

use rc_manager_shared::{
    CONFIG_MAX_BYTES, ConfigCheck, ConfigEdit, ConfigEntry, ConfigError, ConfigFileInfo, ConfigFormat, ConfigSeg,
    ConfigValue, EntryKind, Software, Unverifiable,
};
use std::path::{Path, PathBuf};

/// Profondeur et nombre de fichiers parcourus au plus dans `config/` (mods).
const SCAN_DEPTH: usize = 5;
const SCAN_MAX: usize = 400;

pub fn error_at(line: u32, col: u32, message: String) -> ConfigError {
    // La position est affichée à part : celle que l'analyseur ajoute au message (serde : « … at
    // line 3 column 5 ») ferait doublon.
    let message = match message.rfind(" at line ") {
        Some(i)
            if message[i + 9..].split_once(" column ").is_some_and(|(l, c)| {
                !l.is_empty() && !c.is_empty() && l.bytes().chain(c.bytes()).all(|b| b.is_ascii_digit())
            }) =>
        {
            message[..i].to_string()
        }
        _ => message,
    };
    ConfigError { line, col, message, ..Default::default() }
}

/// Bornes d'un arbre du mode visuel. Chaque entrée porte son chemin complet (et son commentaire) :
/// sans plafond, un texte de 1 Mio très imbriqué ou à longues clés (`- - - - … x`, mille clés de
/// 1 Kio puis vingt mille feuilles) coûte nœuds × profondeur, soit des Gio. Le compte se fait à
/// chaque entrée créée : l'analyse s'arrête dès le dépassement.
pub const MAX_NEST: usize = 64;
pub const MAX_ENTRIES: usize = 20_000;
/// Octets portés par l'arbre (chemins, commentaires, valeurs) : borne aussi la réponse JSON.
pub const MAX_TREE_BYTES: usize = 8 * 1024 * 1024;

/// Compteur des bornes d'un arbre en construction.
#[derive(Default)]
pub struct Budget {
    entries: usize,
    bytes: usize,
}

impl Budget {
    /// Profondeur d'un cadre ouvert (pile de l'analyseur).
    pub fn nest(depth: usize, line: u32) -> Result<(), ConfigError> {
        if depth > MAX_NEST {
            return Err(error_at(line, 0, format!("imbrication trop profonde (au plus {MAX_NEST} niveaux)")));
        }
        Ok(())
    }

    /// Compte une entrée ; erreur dès qu'une borne est dépassée.
    pub fn take(&mut self, e: &ConfigEntry) -> Result<(), ConfigError> {
        Self::nest(e.path.len(), e.line)?;
        let path: usize = e
            .path
            .iter()
            .map(|s| match s {
                ConfigSeg::Key(k) => 24 + k.len(),
                ConfigSeg::Index(_) => 24,
            })
            .sum();
        let value = match &e.value {
            Some(ConfigValue::Str(s)) => s.len(),
            _ => 8,
        };
        self.entries += 1;
        self.bytes +=
            64 + path + e.comment.as_ref().map_or(0, String::len) + e.raw.as_ref().map_or(0, String::len) + value;
        if self.entries > MAX_ENTRIES || self.bytes > MAX_TREE_BYTES {
            return Err(error_at(
                e.line,
                0,
                format!(
                    "fichier trop complexe pour le mode visuel (au plus {MAX_ENTRIES} entrées) : mode texte seulement"
                ),
            ));
        }
        Ok(())
    }
}

/// Lignes d'un texte : débuts de ligne et correspondance caractère → octet (positions de
/// saphyr-parser en caractères).
pub struct Lines<'a> {
    text: &'a str,
    starts: Vec<usize>,
    /// Octet de chaque caractère (absent si le texte est en ASCII).
    chars: Option<Vec<usize>>,
}

impl<'a> Lines<'a> {
    pub fn new(text: &'a str) -> Self {
        let mut starts = vec![0];
        let b = text.as_bytes();
        for (i, &c) in b.iter().enumerate() {
            if c == b'\n' || (c == b'\r' && b.get(i + 1) != Some(&b'\n')) {
                starts.push(i + 1);
            }
        }
        let chars = (!text.is_ascii()).then(|| text.char_indices().map(|(i, _)| i).chain([text.len()]).collect());
        Lines { text, starts, chars }
    }

    /// Octet du caractère `ci`.
    pub fn char_to_byte(&self, ci: usize) -> usize {
        match &self.chars {
            None => ci.min(self.text.len()),
            Some(v) => v.get(ci).copied().unwrap_or(self.text.len()),
        }
    }

    /// Ligne et colonne (à partir de 1, colonne en caractères) d'un octet.
    pub fn pos(&self, byte: usize) -> (u32, u32) {
        let l = self.starts.partition_point(|&s| s <= byte).max(1);
        let ls = self.starts[l - 1];
        let col = self.text.get(ls..byte.min(self.text.len())).map_or(0, |s| s.chars().count());
        (l as u32, col as u32 + 1)
    }

    /// Texte de la ligne `n` (à partir de 1), sans fin de ligne.
    pub fn line(&self, n: u32) -> &'a str {
        let Some(&s) = self.starts.get(n as usize - 1) else { return "" };
        let rest = &self.text[s..];
        &rest[..rest.find(['\n', '\r']).unwrap_or(rest.len())]
    }

    pub fn line_start_of(&self, byte: usize) -> usize {
        Self::line_start(self.text, byte)
    }

    pub fn line_start(text: &str, byte: usize) -> usize {
        text[..byte].rfind(['\n', '\r']).map_or(0, |i| i + 1)
    }

    /// Fin de la ligne qui contient `byte` : (fin du contenu, début de la suivante).
    pub fn line_end(text: &str, byte: usize) -> (usize, usize) {
        let e = text[byte..].find(['\n', '\r']).map_or(text.len(), |i| byte + i);
        let next = if text[e..].starts_with("\r\n") { e + 2 } else { (e + 1).min(text.len()) };
        (e, next)
    }
}

/// Commentaire `#` collé au-dessus de la ligne `line` (à partir de 1).
pub fn comment_above(lines: &Lines, line: u32) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    let mut l = line;
    while l > 1 {
        l -= 1;
        match lines.line(l).trim().strip_prefix('#') {
            Some(c) => out.push(c.trim()),
            None => break,
        }
    }
    out.reverse();
    let s = out.join("\n");
    (!s.trim().is_empty()).then_some(s)
}

/// Fichiers fixes de chaque logiciel (relatifs au dossier du serveur).
fn fixed_files(sw: Software) -> &'static [&'static str] {
    const PAPER: &[&str] = &[
        "server.properties",
        "bukkit.yml",
        "spigot.yml",
        "config/paper-global.yml",
        "config/paper-world-defaults.yml",
    ];
    const PURPUR: &[&str] = &[
        "server.properties",
        "bukkit.yml",
        "spigot.yml",
        "config/paper-global.yml",
        "config/paper-world-defaults.yml",
        "purpur.yml",
    ];
    match sw {
        Software::Paper | Software::Folia => PAPER,
        Software::Purpur => PURPUR,
        Software::Vanilla | Software::Fabric | Software::Quilt => &["server.properties"],
    }
}

/// `config/` des mods (Fabric, Quilt).
fn mod_configs(sw: Software) -> bool {
    matches!(sw, Software::Fabric | Software::Quilt)
}

/// Segment de chemin sûr : non vide, ni `.` ni `..` en tête, pas de séparateur, de `:`, de
/// caractère de contrôle, ni de nom réservé de Windows ; pas d'espace ou de point final (Windows
/// les retire : deux noms pour un même fichier).
fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && !s.ends_with(['.', ' '])
        && !s.chars().any(|c| c.is_control() || matches!(c, '\\' | '/' | ':' | '%' | '*' | '?' | '"' | '<' | '>' | '|'))
        && !crate::paths::is_windows_reserved(s)
        && !crate::paths::is_short_name(s)
}

/// Chemin relatif accepté pour ce logiciel (sans regarder le disque).
pub fn rel_allowed(sw: Software, rel: &str) -> bool {
    if rel.len() > 512 || !rel.split('/').all(segment_ok) {
        return false;
    }
    // Listes d'accès du jeu : éditées dans l'onglet « Joueurs » (mode JSON), pas listées ici.
    if fixed_files(sw).contains(&rel) || rc_manager_shared::AccessList::from_file(rel).is_some() {
        return true;
    }
    mod_configs(sw)
        && rel.starts_with("config/")
        && rel.split('/').count() <= SCAN_DEPTH + 1
        && ConfigFormat::from_name(rel).is_some()
}

/// Résout un chemin demandé : liste blanche, aucun lien symbolique (ni jonction) sur le trajet,
/// fichier ordinaire, forme canonique sous le dossier canonique du serveur.
pub fn resolve(dir: &Path, sw: Software, rel: &str) -> Option<PathBuf> {
    if !rel_allowed(sw, rel) {
        return None;
    }
    let mut p = dir.to_path_buf();
    for seg in rel.split('/') {
        p.push(seg);
        let m = std::fs::symlink_metadata(&p).ok()?;
        if m.file_type().is_symlink() {
            return None;
        }
    }
    if !std::fs::symlink_metadata(&p).ok()?.is_file() {
        return None;
    }
    let root = std::fs::canonicalize(dir).ok()?;
    let canon = std::fs::canonicalize(&p).ok()?;
    // Le nom réel sur le disque (nom long, vraie casse) est bien celui de la liste blanche.
    let segs: Vec<&str> = rel.split('/').collect();
    (canon.starts_with(&root) && crate::paths::real_names_match(&root, &canon, &segs)).then_some(p)
}

/// Fichiers présents (dans l'ordre : fixes puis `config/` trié).
pub fn discover(dir: &Path, sw: Software) -> Vec<ConfigFileInfo> {
    let mut out = Vec::new();
    let info = |rel: &str| {
        let p = resolve(dir, sw, rel)?;
        let size = std::fs::metadata(&p).ok()?.len();
        Some(ConfigFileInfo { path: rel.to_string(), format: ConfigFormat::from_name(rel)?, size })
    };
    for rel in fixed_files(sw) {
        out.extend(info(rel));
    }
    if mod_configs(sw) {
        let mut found = Vec::new();
        scan(&dir.join("config"), "config", 1, &mut found);
        found.sort();
        for rel in found {
            if !out.iter().any(|f| f.path == rel) {
                out.extend(info(&rel));
            }
        }
    }
    out
}

fn scan(dir: &Path, rel: &str, depth: usize, out: &mut Vec<String>) {
    if depth > SCAN_DEPTH || out.len() >= SCAN_MAX {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if out.len() >= SCAN_MAX {
            return;
        }
        let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
        if !segment_ok(&name) {
            continue;
        }
        // Liens : ni suivis ni listés.
        let Ok(ft) = e.file_type() else { continue };
        let child = format!("{rel}/{name}");
        if ft.is_dir() {
            scan(&e.path(), &child, depth + 1, out);
        } else if ft.is_file() && ConfigFormat::from_name(&name).is_some() {
            out.push(child);
        }
    }
}

/// Empreinte d'un contenu (SHA-256 en hexadécimal).
pub fn hash(bytes: &[u8]) -> String {
    crate::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Lecture bornée et décodage : UTF-8 ; pour `.properties`, repli ISO-8859-1 comme le jeu.
pub enum ReadError {
    TooLarge,
    NotText,
    Io,
}

pub fn read(path: &Path, format: ConfigFormat) -> Result<(Vec<u8>, String), ReadError> {
    let bytes = crate::fsutil::read_bounded(path, CONFIG_MAX_BYTES as u64)
        .map_err(|e| if e.kind() == std::io::ErrorKind::Other { ReadError::TooLarge } else { ReadError::Io })?;
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) if format == ConfigFormat::Properties => bytes.iter().map(|&b| b as char).collect(),
        Err(_) => return Err(ReadError::NotText),
    };
    Ok((bytes, text))
}

/// Arbre du texte selon le format.
pub fn entries(format: ConfigFormat, text: &str) -> Result<Vec<ConfigEntry>, ConfigError> {
    match format {
        ConfigFormat::Properties => crate::props::entries(text),
        ConfigFormat::Yaml => yaml::entries(text),
        ConfigFormat::Json => json::entries(text, false),
        ConfigFormat::Json5 => json::entries(text, true),
        ConfigFormat::Toml => toml::entries(text),
        ConfigFormat::Text => Ok(Vec::new()),
    }
}

fn shown(v: &Option<ConfigValue>, raw: &Option<String>) -> String {
    match (v, raw) {
        (Some(v), _) => props_text(v),
        (None, Some(r)) => r.clone(),
        (None, None) => String::new(),
    }
}

/// Nature d'une valeur de l'arbre (un texte `"true"` n'est pas le booléen `true`).
fn kind_of(v: &Option<ConfigValue>) -> &'static str {
    match v {
        Some(ConfigValue::Bool(_)) => "bool",
        Some(ConfigValue::Int(_)) => "int",
        Some(ConfigValue::Float(_)) => "float",
        Some(ConfigValue::Str(_)) => "str",
        Some(ConfigValue::Null) => "null",
        None => "raw",
    }
}

/// Toutes les valeurs du fichier tel que le LIT LE JEU, indépendamment du mode visuel :
/// (chemin, valeur, nature), toutes les occurrences, dans l'ordre. YAML : ancres et alias résolus,
/// fusions `<<` appliquées ; JSON : racine en liste comprise. Erreur : arbre illisible ou non
/// représentable par des chemins (clé complexe, plusieurs documents…), avec la construction en
/// cause : JAMAIS « aucune clé ».
fn all_values(format: ConfigFormat, text: &str) -> Result<Vec<(Vec<ConfigSeg>, String, String)>, Unverifiable> {
    let tree = |e: Vec<ConfigEntry>| {
        e.into_iter()
            .filter(|e| e.kind == EntryKind::Value)
            .map(|e| {
                let k = kind_of(&e.value).to_string();
                (e.path, shown(&e.value, &e.raw), k)
            })
            .collect()
    };
    let syntax = |_| Unverifiable::Syntax;
    Ok(match format {
        ConfigFormat::Properties => crate::props::parse(text)
            .map_err(syntax)?
            .into_iter()
            .map(|e| (vec![ConfigSeg::Key(e.key)], e.value, String::new()))
            .collect(),
        ConfigFormat::Yaml => yaml::flat(text)?,
        ConfigFormat::Json => tree(json::entries_all(text, false).map_err(syntax)?),
        ConfigFormat::Json5 => tree(json::entries_all(text, true).map_err(syntax)?),
        ConfigFormat::Toml => tree(toml::entries(text).map_err(syntax)?),
        ConfigFormat::Text => Vec::new(),
    })
}

/// Construction qui empêche de vérifier les réglages de `text` (`None` : vérifiable).
pub fn unverifiable(format: ConfigFormat, text: &str) -> Option<Unverifiable> {
    all_values(format, text).err()
}

/// Valeurs des réglages réservés aux administrateurs ([`rc_manager_shared::admin_only`]), TOUTES
/// les occurrences comprises (le jeu lit la dernière), dans l'ordre : (chemin, nature et valeur).
/// Texte seulement (`.cfg`) : chaque ligne qui contient un mot réservé. `None` : texte illisible
/// ou arbre non représentable (inconnu : traité comme un changement réservé).
fn flagged(format: ConfigFormat, rel: &str, text: &str) -> Option<Vec<(String, String)>> {
    use rc_manager_shared::admin_only;
    Some(match format {
        ConfigFormat::Text => text
            .lines()
            .filter(|l| admin_only(rel, &[ConfigSeg::Key(l.to_string())]))
            .map(|l| (l.trim().to_string(), String::new()))
            .collect(),
        _ => all_values(format, text)
            .ok()?
            .into_iter()
            .filter(|(p, _, _)| admin_only(rel, p))
            .map(|(p, v, k)| (path_key(&p), format!("{k}:{v}")))
            .collect(),
    })
}

/// Clé rendue quand le fichier ne peut pas être vérifié (arbre non représentable).
pub const UNKNOWN_KEY: &str = "*";

/// Chemin d'une entrée écrit `a.b.0`.
pub fn path_key(p: &[ConfigSeg]) -> String {
    p.iter()
        .map(|s| match s {
            ConfigSeg::Key(k) => k.clone(),
            ConfigSeg::Index(i) => i.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Réglages réservés aux administrateurs qui diffèrent entre deux textes (ajout, retrait,
/// valeur, ordre des doublons). Texte illisible d'un côté : `["*"]` (rien ne peut être vérifié).
pub fn sensitive_changes(format: ConfigFormat, rel: &str, old: &str, new: &str) -> Vec<String> {
    if old == new {
        return Vec::new();
    }
    let (Some(a), Some(b)) = (flagged(format, rel, old), flagged(format, rel, new)) else {
        return vec![UNKNOWN_KEY.into()];
    };
    if a == b {
        return Vec::new();
    }
    let mut keys: Vec<String> = a.iter().chain(&b).map(|(k, _)| k.clone()).collect();
    keys.sort();
    keys.dedup();
    keys.retain(|k| {
        let of = |l: &[(String, String)]| l.iter().filter(|(x, _)| x == k).map(|(_, v)| v.clone()).collect::<Vec<_>>();
        of(&a) != of(&b)
    });
    if keys.is_empty() {
        // Même contenu, autre ordre : la dernière occurrence (celle du jeu) peut changer.
        keys.push(a.first().or_else(|| b.first()).map(|(k, _)| k.clone()).unwrap_or_default());
    }
    keys
}

/// Réglages réservés aux administrateurs que la disparition du fichier `rel` (suppression,
/// départ d'un renommage) ou son apparition (création, restauration) changerait : toutes ses
/// valeurs réservées. Texte illisible ou arbre non représentable : `["*"]`.
pub fn sensitive_present(format: ConfigFormat, rel: &str, text: &str) -> Vec<String> {
    let Some(all) = flagged(format, rel, text) else { return vec![UNKNOWN_KEY.into()] };
    let mut keys: Vec<String> = all.into_iter().map(|(k, _)| k).collect();
    keys.dedup();
    keys
}

/// Chemin relatif sûr pour une valeur de réglage qui désigne un fichier ou un dossier du serveur
/// (`level-name`, `restart-script`) : ni absolu, ni lecteur, ni `..`, ni caractère de contrôle,
/// ni nom réservé de Windows.
pub fn value_path_ok(v: &str) -> bool {
    !v.starts_with(['/', '\\', '~'])
        && !v.contains(':')
        && !v.chars().any(char::is_control)
        && !v.split(['/', '\\']).any(|s| s.trim_end_matches([' ', '.']).is_empty() && s.contains(".."))
        && !v.split(['/', '\\']).any(|s| s == ".." || crate::paths::is_windows_reserved(s))
        // Nom court 8.3 : un autre dossier que celui que le gestionnaire croit (monde verrouillé).
        && !v.split(['/', '\\']).any(crate::paths::is_short_name)
}

/// Valeur refusée quel que soit le compte : réglage qui désigne un chemin hors du dossier du
/// serveur. Rend le chemin de la clé fautive. Fichier illisible ou arbre non représentable
/// (rien ne peut être vérifié) : refusé aussi, sous la première clé surveillée.
pub fn unsafe_value(format: ConfigFormat, rel: &str, text: &str) -> Option<String> {
    const PATHS: &[(&str, &str)] = &[("server.properties", "level-name"), ("spigot.yml", "settings.restart-script")];
    let watched: Vec<&str> = PATHS.iter().filter(|(f, _)| *f == rel).map(|(_, k)| *k).collect();
    let first = watched.first()?;
    let Ok(all) = all_values(format, text) else { return Some(first.to_string()) };
    let all = all.into_iter().map(|(p, v, _)| (path_key(&p), v));
    // Script de redémarrage : Paper 26.3 (RestartCommand) le lance par `Runtime.exec("cmd /c start " + script)`
    // ou `"sh " + script` : jeu de caractères fermé, sinon `&`, `;`, espaces… y glisseraient
    // une autre commande (un fichier ainsi nommé peut exister : vérifié par isFile seulement).
    let script_ok = |v: &str| v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    all.into_iter()
        .find(|(k, v): &(String, String)| {
            watched.contains(&k.as_str()) && (!value_path_ok(v) || (k == "settings.restart-script" && !script_ok(v)))
        })
        .map(|(k, _)| k)
}

/// Premier chemin présent deux fois dans l'arbre (YAML, JSON : le jeu lit la dernière
/// occurrence, les éditions ciblées viseraient la première).
pub fn duplicate(entries: &[ConfigEntry]) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    entries.iter().find(|e| !seen.insert(&e.path)).map(|e| path_key(&e.path))
}

/// Texte d'une valeur dans `server.properties` (tout y est texte).
fn props_text(v: &ConfigValue) -> String {
    match v {
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        ConfigValue::Float(f) => f.to_string(),
        ConfigValue::Str(s) => s.clone(),
        ConfigValue::Null => String::new(),
    }
}

/// Édition normalisée pour le format (`server.properties` : valeurs en texte).
fn normalize(format: ConfigFormat, e: &ConfigEdit) -> ConfigEdit {
    match (format, e) {
        (ConfigFormat::Properties, ConfigEdit::Set { path, value }) => {
            ConfigEdit::Set { path: path.clone(), value: ConfigValue::Str(props_text(value)) }
        }
        _ => e.clone(),
    }
}

fn apply_one(format: ConfigFormat, text: &str, e: &ConfigEdit) -> Result<String, ConfigError> {
    match format {
        ConfigFormat::Properties => match e {
            ConfigEdit::Set { path, value: ConfigValue::Str(v) } => match path.as_slice() {
                [ConfigSeg::Key(k)] if !k.is_empty() && !v.chars().any(char::is_control) => {
                    crate::props::set_values(text, &[(k.as_str(), v.as_str())])
                }
                _ => Err(error_at(0, 0, "valeur invalide".into())),
            },
            _ => Err(error_at(0, 0, "valeur non éditable en mode visuel".into())),
        },
        ConfigFormat::Yaml => yaml::apply(text, e),
        ConfigFormat::Json => json::apply(text, false, e),
        ConfigFormat::Json5 => json::apply(text, true, e),
        ConfigFormat::Toml => toml::apply(text, e),
        ConfigFormat::Text => Err(error_at(0, 0, "format texte seulement".into())),
    }
}

fn same_value(a: &Option<ConfigValue>, b: &Option<ConfigValue>) -> bool {
    match (a, b) {
        (Some(ConfigValue::Float(x)), Some(ConfigValue::Float(y))) => x == y || (x.is_nan() && y.is_nan()),
        _ => a == b,
    }
}

/// Entrées comparables (sans la ligne : elle bouge quand une liste grandit).
fn same(a: &[ConfigEntry], b: &[ConfigEntry]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            x.path == y.path
                && x.kind == y.kind
                && same_value(&x.value, &y.value)
                && x.raw == y.raw
                && x.comment == y.comment
        })
}

fn under(p: &[ConfigSeg], root: &[ConfigSeg]) -> bool {
    p.len() > root.len() && p.starts_with(root)
}

/// Arbre attendu après une édition (tout le reste identique) ; `None` si l'édition ne vise rien.
fn expected(before: &[ConfigEntry], e: &ConfigEdit) -> Option<Vec<ConfigEntry>> {
    let mut out = before.to_vec();
    match e {
        ConfigEdit::Set { path, value } => match out.iter_mut().find(|x| &x.path == path) {
            Some(x) => x.value = Some(value.clone()),
            None => out.push(ConfigEntry {
                path: path.clone(),
                kind: rc_manager_shared::EntryKind::Value,
                value: Some(value.clone()),
                raw: None,
                comment: None,
                editable_list: false,
                line: 0,
            }),
        },
        ConfigEdit::Push { path, value } => {
            let n = before.iter().filter(|x| x.path.len() == path.len() + 1 && under(&x.path, path)).count();
            let at = before.iter().rposition(|x| &x.path == path || under(&x.path, path))? + 1;
            let mut p = path.clone();
            p.push(ConfigSeg::Index(n));
            out.insert(
                at,
                ConfigEntry {
                    path: p,
                    kind: rc_manager_shared::EntryKind::Value,
                    value: Some(value.clone()),
                    raw: None,
                    comment: None,
                    editable_list: false,
                    line: 0,
                },
            );
        }
        ConfigEdit::Remove { path } => {
            let (ConfigSeg::Index(i), parent) = (path.last()?, &path[..path.len() - 1]) else { return None };
            before.iter().find(|x| &x.path == path)?;
            out.retain(|x| x.path != *path && !under(&x.path, path));
            for x in &mut out {
                if under(&x.path, parent)
                    && let ConfigSeg::Index(j) = &mut x.path[parent.len()]
                    && *j > *i
                {
                    *j -= 1;
                }
            }
        }
    }
    Some(out)
}

/// Le texte obtenu se relit comme l'arbre d'avant avec la seule édition appliquée (une clé
/// ajoutée à `server.properties` arrive en fin de fichier, comme dans l'arbre attendu).
/// Rend l'arbre relu (réutilisé : une analyse de moins par édition).
fn verified(format: ConfigFormat, before: &[ConfigEntry], next: &str, e: &ConfigEdit) -> Option<Vec<ConfigEntry>> {
    match (entries(format, next), expected(before, e)) {
        (Ok(after), Some(want)) if same(&want, &after) => Some(after),
        _ => None,
    }
}

/// Analyse un texte et applique des éditions ciblées. Chaque édition est contrôlée : le texte
/// obtenu est relu et son arbre doit être exactement l'arbre d'avant avec la seule valeur
/// changée ; sinon l'édition est refusée (rien ne peut se perdre en silence).
pub fn check(format: ConfigFormat, text: &str, edits: &[ConfigEdit]) -> ConfigCheck {
    let mut cur = text.to_string();
    // Arbre du texte courant quand il est déjà connu (relu par la vérification précédente).
    let mut known: Option<Vec<ConfigEntry>> = None;
    for e in edits {
        let e = normalize(format, e);
        let before = match known.take().map_or_else(|| entries(format, &cur), Ok) {
            Ok(b) => b,
            Err(err) => return ConfigCheck { error: Some(err), ..Default::default() },
        };
        if let Some(d) = duplicate(&before) {
            return ConfigCheck { duplicate: Some(d), ..Default::default() };
        }
        // Valeur déjà en place : rien à réécrire (le fichier reste identique à l'octet).
        if let ConfigEdit::Set { path, value } = &e
            && before.iter().any(|x| &x.path == path && same_value(&x.value, &Some(value.clone())))
        {
            known = Some(before);
            continue;
        }
        let refused = |msg: &str, before: Vec<ConfigEntry>| ConfigCheck {
            error: Some(error_at(0, 0, msg.into())),
            entries: before,
            ..Default::default()
        };
        let Ok(next) = apply_one(format, &cur, &e) else {
            return refused("valeur non éditable en mode visuel", before);
        };
        match verified(format, &before, &next, &e) {
            Some(after) => known = Some(after),
            None => return refused("édition refusée : le fichier ne se relirait pas à l'identique", before),
        }
        cur = next;
    }
    if let Some(entries) = known {
        return ConfigCheck { text: Some(cur), entries, ..Default::default() };
    }
    let text = (!edits.is_empty()).then_some(cur.clone());
    match entries(format, &cur) {
        // Chemin en double : le visuel viserait la première occurrence, le jeu lit la dernière.
        Ok(entries) => match duplicate(&entries) {
            Some(d) => ConfigCheck { text, duplicate: Some(d), ..Default::default() },
            None => ConfigCheck { text, entries, ..Default::default() },
        },
        Err(err) => ConfigCheck { text, error: Some(err), ..Default::default() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Erreur JSON : la position est rendue à part, une seule fois (pas dans le message).
    #[test]
    fn position_une_seule_fois() {
        let e = check(ConfigFormat::Json, "{\n  \"a\": 1\n  \"b\": 2\n}", &[]).error.unwrap();
        assert_eq!((e.line, e.col), (3, 3));
        assert!(!e.message.contains("line") && !e.message.is_empty(), "{}", e.message);
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rcm-cfg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Liste blanche : chaque chemin hostile est refusé avant le disque.
    #[test]
    fn chemins_hostiles_refuses() {
        for bad in [
            "../server.properties",
            "config/../server.properties",
            "config/../../x.yml",
            "/etc/passwd",
            "C:/x.yml",
            "config\\a.json",
            "config/%2e%2e/a.json",
            "config/CON.json",
            "config/a.json ",
            "config/.secret.json",
            "config/a.jar",
            "server.jar",
            "world/level.dat",
            "",
            "config//a.json",
        ] {
            assert!(!rel_allowed(Software::Fabric, bad), "{bad}");
        }
        assert!(rel_allowed(Software::Fabric, "config/sodium-options.json"));
        assert!(rel_allowed(Software::Quilt, "config/mod/sub/a.toml"));
        assert!(!rel_allowed(Software::Paper, "config/sodium-options.json"), "pas de config/ libre hors mods");
        assert!(rel_allowed(Software::Paper, "config/paper-global.yml"));
        assert!(!rel_allowed(Software::Paper, "purpur.yml"));
        assert!(rel_allowed(Software::Purpur, "purpur.yml"));
        assert!(!rel_allowed(Software::Vanilla, "bukkit.yml"));
    }

    /// Lien symbolique ou jonction sur le trajet : refusé même si le nom est dans la liste.
    #[test]
    fn liens_refuses() {
        let d = tmp("liens");
        let outside = tmp("liens-dehors");
        std::fs::write(outside.join("a.json"), "{}").unwrap();
        std::fs::write(d.join("server.properties"), "a=1\n").unwrap();
        assert!(resolve(&d, Software::Fabric, "server.properties").is_some());
        assert!(resolve(&d, Software::Fabric, "config/a.json").is_none(), "absent");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside, d.join("config")).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&outside, d.join("config")).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(d.join("config"))
                .arg(&outside)
                .output()
                .is_ok_and(|o| o.status.success());
        assert!(linked, "lien ou jonction impossible à créer pour le test");
        assert!(d.join("config/a.json").exists(), "le lien mène bien dehors");
        assert!(resolve(&d, Software::Fabric, "config/a.json").is_none());
        assert!(discover(&d, Software::Fabric).iter().all(|f| f.path == "server.properties"));
        // Lien qui reste DANS le dossier du serveur (vers le monde) : refusé aussi (la forme
        // canonique seule le laisserait passer).
        let world = d.join("world");
        std::fs::create_dir_all(&world).unwrap();
        std::fs::write(world.join("b.json"), "{}").unwrap();
        let _ = std::fs::remove_dir(d.join("config")).or_else(|_| std::fs::remove_file(d.join("config")));
        #[cfg(unix)]
        std::os::unix::fs::symlink(&world, d.join("config")).unwrap();
        #[cfg(windows)]
        assert!(
            std::os::windows::fs::symlink_dir(&world, d.join("config")).is_ok()
                || std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(d.join("config"))
                    .arg(&world)
                    .output()
                    .is_ok_and(|o| o.status.success())
        );
        assert!(d.join("config/b.json").exists());
        assert!(resolve(&d, Software::Fabric, "config/b.json").is_none());
        // Dossier : pas un fichier.
        std::fs::create_dir_all(d.join("x.yml")).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn decouverte() {
        let d = tmp("decouverte");
        std::fs::write(d.join("server.properties"), "a=1\n").unwrap();
        std::fs::write(d.join("bukkit.yml"), "a: 1\n").unwrap();
        std::fs::create_dir_all(d.join("config/sous")).unwrap();
        std::fs::write(d.join("config/b.json5"), "{}").unwrap();
        std::fs::write(d.join("config/sous/a.toml"), "a = 1\n").unwrap();
        std::fs::write(d.join("config/x.jar"), "").unwrap();
        let paths = |sw| discover(&d, sw).into_iter().map(|f| f.path).collect::<Vec<_>>();
        assert_eq!(paths(Software::Paper), vec!["server.properties", "bukkit.yml"]);
        assert_eq!(paths(Software::Fabric), vec!["server.properties", "config/b.json5", "config/sous/a.toml"]);
        assert_eq!(paths(Software::Vanilla), vec!["server.properties"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn lignes_et_positions() {
        let l = Lines::new("ab\r\nçd\ne");
        assert_eq!(l.pos(0), (1, 1));
        assert_eq!(l.pos(4), (2, 1));
        assert_eq!(l.pos(6), (2, 2), "colonne en caractères");
        assert_eq!(l.line(2), "çd");
        assert_eq!(l.char_to_byte(5), 6);
    }

    /// Éditions vérifiées : une édition qui toucherait autre chose est refusée.
    #[test]
    fn editions_controlees() {
        let k = |s: &str| vec![ConfigSeg::Key(s.into())];
        let c = check(
            ConfigFormat::Properties,
            "motd=a\nview-distance=10\n",
            &[ConfigEdit::Set { path: k("view-distance"), value: ConfigValue::Int(12) }],
        );
        assert_eq!(c.text.as_deref(), Some("motd=a\nview-distance=12\n"));
        assert!(c.error.is_none());
        let c = check(
            ConfigFormat::Properties,
            "motd=a\n",
            &[ConfigEdit::Set { path: k("pvp"), value: ConfigValue::Bool(false) }],
        );
        assert_eq!(c.text.as_deref(), Some("motd=a\npvp=false\n"));
        let c = check(
            ConfigFormat::Properties,
            "motd=a\n",
            &[ConfigEdit::Set { path: k("motd"), value: ConfigValue::Str("x\ny=1".into()) }],
        );
        assert!(c.error.is_some() && c.text.is_none(), "retour à la ligne refusé");
        let c = check(
            ConfigFormat::Yaml,
            "a: 1\nb: [x]\n",
            &[ConfigEdit::Push { path: k("b"), value: ConfigValue::Int(2) }],
        );
        assert_eq!(c.text.as_deref(), Some("a: 1\nb: [x, 2]\n"));
        let c =
            check(ConfigFormat::Yaml, "a: |\n  x\n", &[ConfigEdit::Set { path: k("a"), value: ConfigValue::Int(2) }]);
        assert!(c.error.is_some());
        let c = check(ConfigFormat::Json, "{\"a\": [1,]}", &[]);
        assert!(c.error.is_some() && c.text.is_none());
    }

    /// Contrôle de relecture : un texte où autre chose que la valeur visée a bougé est refusé.
    #[test]
    fn relecture_controlee() {
        let src = "a: 1\nb: [x, y]\nc: z\n";
        let before = entries(ConfigFormat::Yaml, src).unwrap();
        let set = ConfigEdit::Set { path: vec![ConfigSeg::Key("a".into())], value: ConfigValue::Int(2) };
        assert!(verified(ConfigFormat::Yaml, &before, "a: 2\nb: [x, y]\nc: z\n", &set).is_some());
        assert!(
            verified(ConfigFormat::Yaml, &before, "a: 2\nb: [x, y]\nc: w\n", &set).is_none(),
            "autre valeur changée"
        );
        assert!(verified(ConfigFormat::Yaml, &before, "a: 2\nb: [x, y]\n", &set).is_none(), "clé perdue");
        assert!(verified(ConfigFormat::Yaml, &before, "a: '2'\nb: [x, y]\nc: z\n", &set).is_none(), "type changé");
        assert!(verified(ConfigFormat::Yaml, &before, "a: 2\nb: [x, y\n", &set).is_none(), "illisible");
        let push = ConfigEdit::Push { path: vec![ConfigSeg::Key("b".into())], value: ConfigValue::Str("v".into()) };
        assert!(verified(ConfigFormat::Yaml, &before, "a: 1\nb: [x, y, v]\nc: z\n", &push).is_some());
        assert!(verified(ConfigFormat::Yaml, &before, "a: 1\nb: [x, v]\nc: z\n", &push).is_none());
        let rm = ConfigEdit::Remove { path: vec![ConfigSeg::Key("b".into()), ConfigSeg::Index(0)] };
        assert!(verified(ConfigFormat::Yaml, &before, "a: 1\nb: [y]\nc: z\n", &rm).is_some());
        assert!(verified(ConfigFormat::Yaml, &before, "a: 1\nb: [x]\nc: z\n", &rm).is_none());
    }

    /// Déni de service mémoire : imbrication, nombre d'entrées et octets portés par l'arbre bornés
    /// dans les trois analyseurs, erreur claire dès le dépassement (relecture B1).
    #[test]
    fn arbres_bornes() {
        let too_deep = |f: ConfigFormat, t: &str| {
            let e = entries(f, t).expect_err("imbrication refusée");
            assert!(e.message.contains("imbrication"), "{f:?} : {}", e.message);
        };
        // YAML en blocs : aucun plafond chez saphyr (40 Ko ≈ plusieurs Gio sans borne).
        let mut y = String::new();
        for i in 0..200 {
            y.push_str(&" ".repeat(2 * i));
            y.push_str("- \n");
        }
        y.push_str(&" ".repeat(400));
        y.push_str("x\n");
        too_deep(ConfigFormat::Yaml, &y);
        too_deep(ConfigFormat::Yaml, &"- ".repeat(5000));
        too_deep(ConfigFormat::Yaml, &format!("{}x{}", "[".repeat(100), "]".repeat(100)));
        too_deep(ConfigFormat::Json, &format!("{}1{}", "[".repeat(100), "]".repeat(100)));
        too_deep(ConfigFormat::Json5, &format!("{{a:{}1{}}}", "[".repeat(70), "]".repeat(70)));
        // 64 niveaux : encore accepté.
        assert!(entries(ConfigFormat::Json, &format!("{{\"a\":{}1{}}}", "[".repeat(62), "]".repeat(62))).is_ok());
        // Nombre d'entrées.
        let many = |n: usize| {
            let body: Vec<String> = (0..n).map(|i| format!("\"k{i}\":1")).collect();
            format!("{{{}}}", body.join(","))
        };
        assert!(entries(ConfigFormat::Json, &many(MAX_ENTRIES)).is_ok());
        let e = entries(ConfigFormat::Json, &many(MAX_ENTRIES + 1)).unwrap_err();
        assert!(e.message.contains("trop complexe"), "{}", e.message);
        let toml: String = (0..=MAX_ENTRIES).map(|i| format!("k{i} = 1\n")).collect();
        assert!(entries(ConfigFormat::Toml, &toml).unwrap_err().message.contains("trop complexe"));
        let yaml: String = (0..=MAX_ENTRIES).map(|i| format!("k{i}: 1\n")).collect();
        assert!(entries(ConfigFormat::Yaml, &yaml).unwrap_err().message.contains("trop complexe"));
        // Octets : 40 clés de 12 Kio imbriquées (≈ 480 Kio de chemin), puis des feuilles qui
        // recopient chacune ce chemin : 20 feuilles ≈ 9,6 Mio d'arbre pour 0,5 Mio de texte.
        let key = "k".repeat(12 * 1024);
        let mut j = String::new();
        for _ in 0..40 {
            j.push_str(&format!("{{\"{key}\":"));
        }
        let leaves: Vec<String> = (0..20).map(|i| format!("\"f{i}\":1")).collect();
        j.push_str(&format!("{{{}}}", leaves.join(",")));
        j.push_str(&"}".repeat(40));
        assert!(j.len() < CONFIG_MAX_BYTES);
        assert!(entries(ConfigFormat::Json, &j).unwrap_err().message.contains("trop complexe"));
        // YAML : clé simple de 1 024 caractères au plus ; 60 niveaux de 1 000, 200 feuilles.
        let key = "k".repeat(1000);
        let mut y = String::new();
        for d in 0..60 {
            y.push_str(&format!("{}{key}:\n", " ".repeat(d)));
        }
        for i in 0..200 {
            y.push_str(&format!("{}f{i}: 1\n", " ".repeat(60)));
        }
        assert!(entries(ConfigFormat::Yaml, &y).unwrap_err().message.contains("trop complexe"));
    }
}
