//! Fichiers de configuration d'un serveur (onglet « Réglages ») : liste, lecture, vérification
//! par le vrai analyseur, éditions ciblées (visuel), enregistrement, historique.

use serde::{Deserialize, Serialize};

/// Taille maximale d'un fichier de configuration lu ou écrit par le gestionnaire.
pub const CONFIG_MAX_BYTES: usize = 1024 * 1024;
/// Versions gardées par fichier dans l'historique (les plus anciennes partent).
pub const CONFIG_HISTORY_MAX: usize = 50;

/// Clés de `server.properties` tenues par le gestionnaire : lecture seule dans l'éditeur, refusées
/// à l'enregistrement si elles changent. Le serveur de gestion JSON-RPC du jeu (26.x) est coupé à
/// chaque lancement : allumé sur `0.0.0.0`, il ouvrirait le pilotage complet du serveur au réseau.
pub const MANAGED_PROPERTIES: &[&str] = &[
    "server-port",
    "enable-rcon",
    "rcon.password",
    "rcon.port",
    "query.port",
    "management-server-enabled",
    "management-server-host",
    "management-server-port",
    "management-server-secret",
    "management-server-tls-enabled",
    "management-server-tls-keystore",
    "management-server-tls-keystore-password",
    "management-server-allowed-origins",
];

/// Clés de `server.properties` réservées aux administrateurs (en plus des mots repérés par
/// [`admin_only`]) : identité des joueurs, dossier du monde, service de filtrage contacté par le
/// jeu, interfaces d'écoute et services ouverts.
const ADMIN_PROPERTIES: &[&str] =
    &["online-mode", "level-name", "text-filtering-config", "server-ip", "enable-query", "enable-jmx-monitoring"];

/// Chemins (clés jointes par `.`) réservés aux administrateurs dans les fichiers des logiciels.
const ADMIN_PATHS: &[(&str, &str)] = &[
    // Script lancé par `/restart` et après un plantage (Spigot et dérivés).
    ("spigot.yml", "settings.restart-script"),
    ("spigot.yml", "settings.restart-on-crash"),
    // Confiance dans les adresses et identités transmises par un mandataire : sans mandataire
    // devant, n'importe qui se connecte sous n'importe quel compte.
    ("spigot.yml", "settings.bungeecord"),
];

/// Mots de clé qui ouvrent un service, contactent une adresse, lancent un programme ou touchent
/// à l'identité des joueurs (mods compris) : `web-port`, `bindAddress`, `webhook_url`…
const ADMIN_WORDS: &[&str] = &[
    "port",
    "host",
    "hostname",
    "bind",
    "address",
    "ip",
    "url",
    "uri",
    "webhook",
    "endpoint",
    "script",
    "exec",
    "command",
    "secret",
    "token",
    "password",
    "bungeecord",
    "bungee",
    "velocity",
    "proxies",
    "proxy",
];

/// Mots d'une clé (`webPort`, `web-port`, `web_port` → `web`, `port`), en minuscules.
fn key_words(k: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in k.chars() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Réglage réservé aux administrateurs (vérifié par le serveur, texte comme visuel ; l'interface
/// le signale). `file` : chemin relatif au dossier du serveur.
pub fn admin_only(file: &str, path: &[ConfigSeg]) -> bool {
    // Listes d'accès (`banned-ips.json` porte des `ip`) : ouvertes à tous les comptes.
    if crate::AccessList::from_file(file).is_some() {
        return false;
    }
    let keys: Vec<&str> = path
        .iter()
        .filter_map(|s| match s {
            ConfigSeg::Key(k) => Some(k.as_str()),
            ConfigSeg::Index(_) => None,
        })
        .collect();
    if file == "server.properties"
        && let [k] = keys.as_slice()
        && (ADMIN_PROPERTIES.contains(k) || MANAGED_PROPERTIES.contains(k))
    {
        return true;
    }
    let joined = keys.join(".");
    if ADMIN_PATHS.iter().any(|(f, p)| *f == file && joined == *p) {
        return true;
    }
    keys.iter().any(|k| key_words(k).iter().any(|w| ADMIN_WORDS.contains(&w.as_str())))
}

/// Format d'un fichier, d'après son nom.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFormat {
    Properties,
    Yaml,
    Json,
    Json5,
    Toml,
    /// Format sans analyseur commun (`.cfg`) : texte seulement.
    Text,
}

impl ConfigFormat {
    pub fn from_name(name: &str) -> Option<ConfigFormat> {
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match ext.as_str() {
            "properties" => ConfigFormat::Properties,
            "yml" | "yaml" => ConfigFormat::Yaml,
            "json" => ConfigFormat::Json,
            "json5" => ConfigFormat::Json5,
            "toml" => ConfigFormat::Toml,
            "cfg" => ConfigFormat::Text,
            _ => return None,
        })
    }

    /// Texte d'un fichier créé vide (« Nouveau fichier ») : valide pour l'analyseur de son format
    /// (un texte vide n'est pas du JSON). `name` : nom du fichier (casse indifférente).
    pub fn new_file_text(name: &str) -> &'static str {
        let lower = name.to_lowercase();
        if crate::AccessList::from_file(&lower).is_some() {
            return "[]\n";
        }
        match ConfigFormat::from_name(&lower) {
            Some(ConfigFormat::Json | ConfigFormat::Json5) => "{}\n",
            _ => "",
        }
    }

    /// Mode visuel possible.
    pub fn visual(self) -> bool {
        self != ConfigFormat::Text
    }
}

/// Fichier listé (`GET /api/servers/{id}/configs`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigFileInfo {
    /// Chemin relatif au dossier du serveur, séparateur `/`.
    pub path: String,
    pub format: ConfigFormat,
    pub size: u64,
}

/// Contenu d'un fichier (`GET /api/servers/{id}/config?path=…`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    pub path: String,
    pub format: ConfigFormat,
    pub text: String,
    /// Empreinte du contenu lu (alerte si le fichier change sur le disque avant l'enregistrement).
    pub hash: String,
}

/// Segment d'un chemin dans l'arbre : clé de section ou rang dans une liste.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ConfigSeg {
    Index(usize),
    Key(String),
}

/// Valeur simple.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum ConfigValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Null,
}

/// Édition ciblée demandée par le mode visuel.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ConfigEdit {
    /// Remplace la valeur d'une clé ou d'un élément (ajoutée si la clé manque, `server.properties`).
    Set { path: Vec<ConfigSeg>, value: ConfigValue },
    /// Ajoute un élément en fin de liste.
    Push { path: Vec<ConfigSeg>, value: ConfigValue },
    /// Retire un élément de liste.
    Remove { path: Vec<ConfigSeg> },
}

/// `POST /api/servers/{id}/config/check` : analyse (et éditions éventuelles) d'un texte.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConfigCheckRequest {
    pub path: String,
    pub text: String,
    #[serde(default)]
    pub edits: Vec<ConfigEdit>,
}

/// Erreur de l'analyseur, clé gérée modifiée, ou réglage réservé aux administrateurs modifié.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigError {
    /// Ligne et colonne (à partir de 1) ; 0 si inconnues.
    pub line: u32,
    pub col: u32,
    pub message: String,
    /// Clé gérée par le gestionnaire qui a changé (`server.properties`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_key: Option<String>,
    /// Réglage réservé aux administrateurs changé par un autre compte ([`admin_only`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_key: Option<String>,
    /// Valeur refusée quel que soit le compte (chemin qui sort du dossier du serveur…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsafe_key: Option<String>,
    /// Refus parce que les réglages du fichier ne peuvent pas être vérifiés : la construction en
    /// cause (avec `unsafe_key` : refusé pour tous ; avec `admin_key` `*` : pour les autres comptes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unverifiable: Option<Unverifiable>,
}

/// Construction qui empêche de vérifier les réglages d'un fichier : l'arbre tel que le jeu le
/// lit n'est pas représentable par des chemins. L'interface dit laquelle et quoi faire.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unverifiable {
    /// Texte que l'analyseur complet ne lit pas.
    Syntax,
    /// Section ou liste employée comme clé (`? [a, b] : x`).
    ComplexKey,
    /// Alias (`*nom`) d'une ancre (`&nom`) absente, ou dans la section qu'elle nomme.
    UnknownAlias,
    /// Plusieurs documents (`---`).
    ManyDocuments,
    /// Étiquette sur une section ou une liste (`!!omap`, `!!set`, `!perso`…).
    CollectionTag,
    /// Fusion `<<` d'autre chose qu'une section (ou une liste de sections).
    BadMerge,
    /// Trop imbriqué, ou trop grand une fois les alias dépliés.
    TooLarge,
    /// Le texte proposé se vérifie, mais pas la version actuelle sur le disque.
    OnDisk,
}

/// Nature d'une entrée de l'arbre.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Section,
    List,
    Value,
}

/// Entrée de l'arbre (liste à plat, dans l'ordre du fichier ; la profondeur donne l'imbrication).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConfigEntry {
    pub path: Vec<ConfigSeg>,
    pub kind: EntryKind,
    /// Valeur (entrées `Value`) ; `None` pour une valeur que le visuel ne sait pas éditer (texte
    /// sur plusieurs lignes, ancre, étiquette) : affichée telle quelle dans `raw`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ConfigValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Commentaire placé juste au-dessus de la clé dans le fichier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Liste de valeurs simples : éléments ajoutables et retirables.
    #[serde(default)]
    pub editable_list: bool,
    /// Ligne dans le fichier (à partir de 1).
    pub line: u32,
}

/// Réponse de la vérification.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ConfigCheck {
    /// Texte après les éditions (absent s'il n'y en avait pas).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ConfigError>,
    /// Arbre du texte (vide si invalide, format texte seulement, ou chemin en double).
    pub entries: Vec<ConfigEntry>,
    /// Chemin présent deux fois (le jeu lit la DERNIÈRE occurrence) : mode visuel refusé, le
    /// texte reste éditable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate: Option<String>,
    /// Réglages réservés aux administrateurs changés par rapport au disque (avertissement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive: Vec<String>,
    /// Texte valide dont les réglages ne peuvent pas être vérifiés (avertissement dès
    /// l'ouverture : seul un administrateur peut l'enregistrer tel quel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unverifiable: Option<Unverifiable>,
}

/// `POST /api/servers/{id}/config/save`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigSaveRequest {
    pub path: String,
    pub text: String,
    /// Empreinte du fichier à l'ouverture (`ConfigFile::hash`).
    pub base_hash: String,
}

/// Réponse de l'enregistrement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigSaved {
    pub hash: String,
    /// Le serveur tourne : les changements valent au prochain démarrage.
    pub restart_needed: bool,
    /// Le contenu était identique : rien n'a été écrit.
    pub unchanged: bool,
}

/// Version gardée dans l'historique (`GET /api/servers/{id}/config/history?path=…`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigVersion {
    pub id: i64,
    /// Instant Unix (s) de l'enregistrement qui a remplacé cette version.
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub size: u64,
}

/// Contenu d'une version (`GET /api/servers/{id}/config/history/{version}`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigVersionContent {
    pub id: i64,
    pub path: String,
    pub text: String,
}

/// Ligne d'un écart entre deux textes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiffLine {
    Same(String),
    Added(String),
    Removed(String),
}

/// Écart ligne à ligne (plus longue sous-suite commune, préfixe et suffixe communs retirés
/// d'abord ; au-delà de 4 millions de cases, la zone changée est rendue en bloc).
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..].iter().rev().zip(b[pre..].iter().rev()).take_while(|(x, y)| x == y).count();
    let (ma, mb) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut out: Vec<DiffLine> = a[..pre].iter().map(|l| DiffLine::Same((*l).into())).collect();
    if ma.len().saturating_mul(mb.len()) > 4_000_000 {
        out.extend(ma.iter().map(|l| DiffLine::Removed((*l).into())));
        out.extend(mb.iter().map(|l| DiffLine::Added((*l).into())));
    } else {
        // Table des longueurs de la plus longue sous-suite commune (suffixes).
        let w = mb.len() + 1;
        let mut t = vec![0u32; (ma.len() + 1) * w];
        for i in (0..ma.len()).rev() {
            for j in (0..mb.len()).rev() {
                t[i * w + j] =
                    if ma[i] == mb[j] { t[(i + 1) * w + j + 1] + 1 } else { t[(i + 1) * w + j].max(t[i * w + j + 1]) };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < ma.len() && j < mb.len() {
            if ma[i] == mb[j] {
                out.push(DiffLine::Same(ma[i].into()));
                i += 1;
                j += 1;
            } else if t[(i + 1) * w + j] >= t[i * w + j + 1] {
                out.push(DiffLine::Removed(ma[i].into()));
                i += 1;
            } else {
                out.push(DiffLine::Added(mb[j].into()));
                j += 1;
            }
        }
        out.extend(ma[i..].iter().map(|l| DiffLine::Removed((*l).into())));
        out.extend(mb[j..].iter().map(|l| DiffLine::Added((*l).into())));
    }
    out.extend(a[a.len() - suf..].iter().map(|l| DiffLine::Same((*l).into())));
    out
}

/// Texte saisi (la zone de saisie ne connaît que `\n`) remis dans les fins de ligne du fichier :
/// chaque ligne inchangée garde la sienne (`\r\n` ou `\n`, fichiers mixtes compris), une ligne
/// nouvelle prend celle qui domine dans le fichier.
pub fn merge_eol(old: &str, new_lf: &str) -> String {
    if !old.contains('\r') {
        return new_lf.to_string();
    }
    let crlf = old.matches("\r\n").count();
    let nl = if crlf * 2 >= old.matches('\n').count() { "\r\n" } else { "\n" };
    let ends: Vec<&str> = old
        .split_inclusive('\n')
        .map(|l| {
            if l.ends_with("\r\n") {
                "\r\n"
            } else if l.ends_with('\n') {
                "\n"
            } else {
                ""
            }
        })
        .collect();
    let old_lf = old.replace("\r\n", "\n");
    let total = new_lf.split_inclusive('\n').count();
    let mut out = String::with_capacity(new_lf.len() + new_lf.len() / 16);
    let (mut oi, mut done) = (0usize, 0usize);
    // Fins des lignes retirées juste avant : une ligne modifiée (retirée puis ajoutée) garde la
    // fin de celle qu'elle remplace.
    let mut replaced: std::collections::VecDeque<&str> = std::collections::VecDeque::new();
    let end_of = |i: usize| ends.get(i).copied().filter(|e| !e.is_empty()).unwrap_or(nl);
    for d in diff_lines(&old_lf, new_lf) {
        let (line, end) = match d {
            DiffLine::Removed(_) => {
                replaced.push_back(end_of(oi));
                oi += 1;
                continue;
            }
            DiffLine::Same(l) => {
                replaced.clear();
                let e = end_of(oi);
                oi += 1;
                (l, e)
            }
            DiffLine::Added(l) => (l, replaced.pop_front().unwrap_or(nl)),
        };
        out.push_str(&line);
        done += 1;
        if done < total || new_lf.ends_with('\n') {
            out.push_str(end);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_par_nom() {
        assert_eq!(ConfigFormat::from_name("server.properties"), Some(ConfigFormat::Properties));
        assert_eq!(ConfigFormat::from_name("config/paper-global.yml"), Some(ConfigFormat::Yaml));
        assert_eq!(ConfigFormat::from_name("a.JSON5"), Some(ConfigFormat::Json5));
        assert_eq!(ConfigFormat::from_name("a.cfg"), Some(ConfigFormat::Text));
        assert_eq!(ConfigFormat::from_name("server.jar"), None);
        assert_eq!(ConfigFormat::from_name("README"), None);
    }

    #[test]
    fn ecart_ligne_a_ligne() {
        let d = diff_lines("a\nb\nc\nd\n", "a\nB\nc\nd\ne\n");
        assert_eq!(
            d,
            vec![
                DiffLine::Same("a".into()),
                DiffLine::Removed("b".into()),
                DiffLine::Added("B".into()),
                DiffLine::Same("c".into()),
                DiffLine::Same("d".into()),
                DiffLine::Added("e".into()),
            ]
        );
        assert!(diff_lines("x\ny\n", "x\ny\n").iter().all(|l| matches!(l, DiffLine::Same(_))));
        assert_eq!(diff_lines("", "z"), vec![DiffLine::Added("z".into())]);
    }

    /// Saisie en texte : les fins de ligne du fichier survivent (CRLF de Windows, fichiers mixtes
    /// comme ceux de Paper) ; sans changement, le fichier d'origine à l'octet.
    #[test]
    fn fins_de_ligne_gardees() {
        let crlf = "a=1\r\nb=2\r\nc=3\r\n";
        let lf = crlf.replace("\r\n", "\n");
        assert_eq!(merge_eol(crlf, &lf), crlf);
        assert_eq!(merge_eol(crlf, "a=1\nb=9\nc=3\nd=4\n"), "a=1\r\nb=9\r\nc=3\r\nd=4\r\n");
        assert_eq!(merge_eol(crlf, "a=1\nc=3\n"), "a=1\r\nc=3\r\n");
        assert_eq!(merge_eol(crlf, "a=1\nb=2\nc=3"), "a=1\r\nb=2\r\nc=3", "sans fin finale");
        let mixed = "# en-tête\r\n#\r\nclé: 1\nautre: 2\n";
        assert_eq!(merge_eol(mixed, &mixed.replace("\r\n", "\n")), mixed);
        assert_eq!(merge_eol(mixed, "# en-tête\n#\nclé: 5\nautre: 2\n"), "# en-tête\r\n#\r\nclé: 5\nautre: 2\n");
        assert_eq!(merge_eol("x\ny\n", "x\nz\n"), "x\nz\n");
        assert_eq!(merge_eol(crlf, ""), "");
    }

    #[test]
    fn segments_et_valeurs_en_json() {
        let e =
            ConfigEdit::Set { path: vec![ConfigSeg::Key("a".into()), ConfigSeg::Index(2)], value: ConfigValue::Int(3) };
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(j, r#"{"op":"set","path":["a",2],"value":{"t":"int","v":3}}"#);
        assert_eq!(serde_json::from_str::<ConfigEdit>(&j).unwrap(), e);
    }
}
