//! Gestionnaire de fichiers d'un serveur : CONFINEMENT STRICT au dossier du serveur.
//!
//! Gardes, dans l'ordre, à chaque opération (et non une seule fois avant) :
//! 1. texte du chemin : segments séparés par `/`, chacun non vide, ni `.` ni `..`, sans `\`,
//!    `:`, `%`, caractère de contrôle ou interdit de Windows, sans espace ou point final (Windows
//!    les retire : deux noms pour un fichier), ni nom réservé (`CON`, `COM¹`…), ni nom court 8.3
//!    (`~` suivi d'un chiffre) ; premier segment différent de `.rcm` (dossier interne du
//!    gestionnaire, toute casse) ; 1 Kio au plus ; les règles comparent la forme sans casse
//!    ([`rule_rel`]) ;
//! 2. disque, AU MOMENT de l'opération (dans le même fil bloquant, juste avant) : chaque
//!    composant lu sans suivre les liens (`symlink_metadata`) ; lien symbolique, jonction ou
//!    autre point d'analyse Windows refusé, où qu'il soit (même s'il reste dans le dossier) ;
//!    forme canonique du parent sous la forme canonique de la racine ; nom réel (canonique) de
//!    chaque composant présent égal au nom demandé, casse à part ;
//! 3. écriture : temporaire dans le dossier cible, renommage ; le chemin est revérifié après.
//!
//! Les liens trouvés dans un dossier sont listés (`Link`), jamais suivis ni ouverts.

use rc_manager_shared::{FILE_LIST_MAX, FILE_PATH_MAX, FileEntry, FileKind, FileList, TRASH_DAYS, TrashItem};
use std::path::{Path, PathBuf};

/// Dossier interne du gestionnaire dans chaque dossier de serveur.
pub const INTERNAL: &str = ".rcm";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsErr {
    /// Chemin refusé par sa forme.
    Invalid,
    /// Absent, ou lien sur le trajet (même réponse : rien n'est révélé de ce qui est derrière).
    NotFound,
    Exists,
    /// Pas un fichier (ou pas un dossier) là où il en faut un.
    WrongKind,
    TooLarge,
    NotText,
    Io,
    /// Plus grand que toute la corbeille ([`TRASH_MAX_BYTES`]).
    TrashTooLarge,
    /// Corbeille pleine, et éviction non permise (compte ordinaire).
    TrashFull,
}

impl From<std::io::Error> for FsErr {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => FsErr::NotFound,
            std::io::ErrorKind::AlreadyExists => FsErr::Exists,
            _ => FsErr::Io,
        }
    }
}

/// Segment de chemin accepté (voir l'en-tête du module).
pub fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        // Point final refusé : couvre aussi `.` et `..`.
        && !s.ends_with(['.', ' '])
        && !s.chars().any(|c| c.is_control() || matches!(c, '\\' | '/' | ':' | '%' | '*' | '?' | '"' | '<' | '>' | '|'))
        && !crate::paths::is_windows_reserved(s)
        // Nom court 8.3 (`RCM~1`, `SERVER~1.PRO`) : alias d'un autre nom sur le disque.
        && !crate::paths::is_short_name(s)
}

/// Forme d'un chemin relatif pour les règles (fichiers gérés, listes, programmes, monde, gardes
/// des réglages) : sans casse, comme Windows lit les noms. Le chemin lui-même est confronté au
/// nom réel sur le disque par [`resolve`].
pub fn rule_rel(rel: &str) -> String {
    crate::paths::fold(rel)
}

/// Segments d'un chemin relatif (`""` : racine) ; `None` si la forme est refusée.
pub fn parse_rel(rel: &str) -> Option<Vec<&str>> {
    if rel.len() > FILE_PATH_MAX {
        return None;
    }
    if rel.is_empty() {
        return Some(Vec::new());
    }
    let segs: Vec<&str> = rel.split('/').collect();
    if !segs.iter().all(|s| segment_ok(s)) || crate::paths::fold(segs[0]) == INTERNAL {
        return None;
    }
    Some(segs)
}

/// Lien symbolique, jonction ou autre point d'analyse (Windows : attribut `REPARSE_POINT`).
pub fn is_link(m: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    m.file_type().is_symlink()
}

/// Résout un chemin AU MOMENT de l'opération. `must_exist = false` : le dernier composant peut
/// manquer (création), son parent doit exister et être un dossier.
pub fn resolve(root: &Path, rel: &str, must_exist: bool) -> Result<PathBuf, FsErr> {
    let segs = parse_rel(rel).ok_or(FsErr::Invalid)?;
    let rm = std::fs::symlink_metadata(root)?;
    if is_link(&rm) || !rm.is_dir() {
        return Err(FsErr::NotFound);
    }
    let mut p = root.to_path_buf();
    for (i, seg) in segs.iter().enumerate() {
        p.push(seg);
        let last = i + 1 == segs.len();
        match std::fs::symlink_metadata(&p) {
            Ok(m) if is_link(&m) => return Err(FsErr::NotFound),
            Ok(m) if !last && !m.is_dir() => return Err(FsErr::NotFound),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && last && !must_exist => {}
            Err(e) => return Err(e.into()),
        }
    }
    // Défense en profondeur : forme canonique du dossier parent sous celle de la racine.
    let canon_root = std::fs::canonicalize(root)?;
    let parent = if segs.is_empty() { p.clone() } else { p.parent().map(Path::to_path_buf).unwrap_or_default() };
    let canon_parent = std::fs::canonicalize(&parent)?;
    if !canon_parent.starts_with(&canon_root) {
        return Err(FsErr::NotFound);
    }
    // Nom RÉEL de chaque composant présent (forme canonique : nom long, vraie casse) : celui
    // demandé, casse à part. Les règles comparent le texte demandé : il doit être le vrai nom.
    let (real, named) = match std::fs::symlink_metadata(&p) {
        Ok(_) if !segs.is_empty() => (std::fs::canonicalize(&p)?, &segs[..]),
        _ => (canon_parent, &segs[..segs.len().saturating_sub(1)]),
    };
    if !crate::paths::real_names_match(&canon_root, &real, named) {
        return Err(FsErr::Invalid);
    }
    Ok(p)
}

/// Fichiers jamais éditables (binaires connus), téléchargeables seulement.
pub fn binary_name(name: &str) -> bool {
    const BIN: &[&str] = &[
        "jar", "zip", "gz", "tgz", "xz", "7z", "rar", "bz2", "zst", "dat", "dat_old", "mca", "mcr", "mcc", "nbt",
        "png", "jpg", "jpeg", "gif", "webp", "ico", "class", "exe", "dll", "so", "dylib", "db", "sqlite", "lock",
        "jks", "p12", "keystore", "bin", "pdf",
    ];
    ext(name).is_some_and(|e| BIN.contains(&e.as_str()))
}

fn ext(name: &str) -> Option<String> {
    name.rsplit_once('.').map(|(_, e)| crate::paths::fold(e))
}

/// Programmes et code (lancés par le serveur, Java ou le système) : créés, remplacés ou
/// renommés par les administrateurs seulement.
pub fn executable_name(name: &str) -> bool {
    const EXEC: &[&str] = &[
        "jar", "class", "sh", "bash", "bat", "cmd", "ps1", "psm1", "vbs", "exe", "com", "msi", "dll", "so", "dylib",
        "py", "js", "mjs", "pl", "rb", "command", "scr", "lnk", "url", "desktop", "service",
        // Scripts lus par des greffons et des mods : Groovy, Kotlin script, Lua, CraftTweaker
        // (ZenScript), Skript.
        "groovy", "kts", "lua", "zs", "sk",
    ];
    ext(name).is_some_and(|e| EXEC.contains(&e.as_str()))
}

/// Fichier qui porte des secrets (mots de passe, jetons, clés) : lectures tracées, signalé.
pub fn sensitive_name(rel: &str) -> bool {
    let name = rule_rel(rel.rsplit('/').next().unwrap_or(rel));
    matches!(name.as_str(), "server.properties" | "paper-global.yml" | ".env" | "velocity.toml" | "forwarding.secret")
        || ["jks", "p12", "pem", "key", "keystore", "pfx"].iter().any(|e| ext(&name).as_deref() == Some(*e))
        || ["secret", "token", "password", "credential"].iter().any(|w| name.contains(w))
}

/// Fichiers tenus par le gestionnaire : modifiables par leur écran seulement.
pub fn managed_rel(rel: &str) -> bool {
    rule_rel(rel) == "eula.txt"
}

fn modified(m: &std::fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64)
}

/// Contenu d'un dossier : dossiers d'abord, puis fichiers, par nom ; liens listés sans être
/// suivis ; `.rcm` caché à la racine.
pub fn list(root: &Path, rel: &str) -> Result<FileList, FsErr> {
    let p = resolve(root, rel, true)?;
    if !std::fs::symlink_metadata(&p)?.is_dir() {
        return Err(FsErr::WrongKind);
    }
    let mut entries = Vec::new();
    let mut truncated = false;
    for e in std::fs::read_dir(&p)?.flatten() {
        if entries.len() >= FILE_LIST_MAX {
            truncated = true;
            break;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if rel.is_empty() && name.eq_ignore_ascii_case(INTERNAL) {
            continue;
        }
        let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
        let kind = if is_link(&m) {
            FileKind::Link
        } else if m.is_dir() {
            FileKind::Dir
        } else {
            FileKind::File
        };
        let child = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let blocked = e.file_name().to_str().is_none() || !segment_ok(&name);
        entries.push(FileEntry {
            editable: kind == FileKind::File
                && !blocked
                && !binary_name(&name)
                && m.len() <= rc_manager_shared::FILE_EDIT_MAX,
            sensitive: kind == FileKind::File && sensitive_name(&child),
            managed: managed_rel(&child),
            size: if kind == FileKind::File { m.len() } else { 0 },
            modified: modified(&m),
            name,
            kind,
            blocked,
        });
    }
    entries.sort_by(|a, b| {
        (a.kind != FileKind::Dir, a.name.to_lowercase()).cmp(&(b.kind != FileKind::Dir, b.name.to_lowercase()))
    });
    Ok(FileList { path: rel.to_string(), entries, truncated, world: false })
}

/// Texte d'un fichier (UTF-8 sans octet nul, 1 Mio au plus).
pub fn read_text(root: &Path, rel: &str) -> Result<(Vec<u8>, String), FsErr> {
    let p = resolve(root, rel, true)?;
    if binary_name(rel) {
        return Err(FsErr::NotText);
    }
    read_text_at(&p)
}

/// Texte d'un fichier déjà résolu (ouvert sans suivre de lien), mêmes bornes que [`read_text`].
pub fn read_text_at(p: &Path) -> Result<(Vec<u8>, String), FsErr> {
    let f = open_file(p)?;
    let len = f.metadata()?.len();
    if len > rc_manager_shared::FILE_EDIT_MAX {
        return Err(FsErr::TooLarge);
    }
    let mut bytes = Vec::with_capacity(len as usize);
    use std::io::Read;
    f.take(rc_manager_shared::FILE_EDIT_MAX + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > rc_manager_shared::FILE_EDIT_MAX {
        return Err(FsErr::TooLarge);
    }
    if bytes.contains(&0) {
        return Err(FsErr::NotText);
    }
    let text = String::from_utf8(bytes.clone()).map_err(|_| FsErr::NotText)?;
    Ok((bytes, text))
}

/// Ouvre un fichier ordinaire SANS suivre de lien sur le dernier composant (Windows :
/// `FILE_FLAG_OPEN_REPARSE_POINT`, Unix : `O_NOFOLLOW`), puis vérifie la nature de ce qui est ouvert.
pub fn open_file(p: &Path) -> Result<std::fs::File, FsErr> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    open_nofollow(o, p)
}

/// Ouvre (crée au besoin) un fichier ordinaire en ajout, sans suivre de lien, comme [`open_file`].
pub fn open_append(p: &Path) -> Result<std::fs::File, FsErr> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    open_nofollow(o, p)
}

fn open_nofollow(mut o: std::fs::OpenOptions, p: &Path) -> Result<std::fs::File, FsErr> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NOFOLLOW: i32 = if cfg!(target_os = "linux") { 0o400000 } else { 0x100 };
        // Sans attente : une FIFO posée à la place du fichier bloquerait `open` jusqu'à ce qu'un
        // autre processus l'ouvre (le contrôle de nature qui suit la refuse) ; sans effet sur un
        // fichier ordinaire.
        const O_NONBLOCK: i32 = if cfg!(target_os = "linux") { 0o4000 } else { 0x4 };
        o.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    }
    let f = o.open(p)?;
    let m = f.metadata()?;
    if is_link(&m) || !m.is_file() {
        return Err(FsErr::WrongKind);
    }
    Ok(f)
}

/// Écrit un fichier texte : remplacé seulement si son empreinte est `base_hash` ; créé si
/// `base_hash` est vide et qu'il n'existe pas. Rend l'ancien contenu.
pub fn write_text(root: &Path, rel: &str, data: &[u8], base_hash: &str) -> Result<Vec<u8>, FsErr> {
    if rel.is_empty() {
        return Err(FsErr::Invalid);
    }
    let p = resolve(root, rel, false)?;
    let old = match std::fs::symlink_metadata(&p) {
        Ok(m) if !m.is_file() => return Err(FsErr::WrongKind),
        Ok(_) => {
            let (b, _) = read_any(&p)?;
            if base_hash.is_empty() || crate::configs::hash(&b) != base_hash {
                return Err(FsErr::Exists);
            }
            b
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !base_hash.is_empty() {
                return Err(FsErr::NotFound);
            }
            Vec::new()
        }
        Err(e) => return Err(e.into()),
    };
    crate::fsutil::write_atomic(&p, data)?;
    // Revérifié après coup : un lien glissé entre-temps sur le trajet fait échouer l'opération.
    resolve(root, rel, true)?;
    Ok(old)
}

fn read_any(p: &Path) -> Result<(Vec<u8>, u64), FsErr> {
    use std::io::Read;
    let f = open_file(p)?;
    let len = f.metadata()?.len();
    if len > rc_manager_shared::FILE_EDIT_MAX {
        return Err(FsErr::TooLarge);
    }
    let mut b = Vec::new();
    f.take(rc_manager_shared::FILE_EDIT_MAX + 1).read_to_end(&mut b)?;
    Ok((b, len))
}

/// Crée un dossier (son parent doit exister).
pub fn mkdir(root: &Path, rel: &str) -> Result<(), FsErr> {
    if rel.is_empty() {
        return Err(FsErr::Invalid);
    }
    let p = resolve(root, rel, false)?;
    std::fs::create_dir(&p)?;
    resolve(root, rel, true).map(|_| ())
}

/// Renomme ou déplace (destination absente, parent existant ; pas un dossier dans lui-même).
pub fn rename(root: &Path, from: &str, to: &str) -> Result<(), FsErr> {
    if from.is_empty() || to.is_empty() {
        return Err(FsErr::Invalid);
    }
    let lower = |s: &str| s.to_lowercase();
    if lower(to).starts_with(&format!("{}/", lower(from))) {
        return Err(FsErr::Invalid);
    }
    let src = resolve(root, from, true)?;
    let dst = resolve(root, to, false)?;
    move_no_replace(&src, &dst)?;
    resolve(root, to, true).map(|_| ())
}

/// Déplace `src` vers `dst` SANS jamais remplacer ce qui s'y trouve, même apparu après une
/// vérification : `std::fs::rename` remplace un fichier (et sous Windows un dossier vide, voire un
/// fichier par un dossier). La place est d'abord réservée de façon atomique (fichier créé en
/// `create_new`, ou dossier créé : échec si le nom existe), puis l'élément est renommé sur cette
/// réservation, qui lui appartient. Destination déjà présente : refus, sauf si c'est le même
/// élément (même nom à la casse près sous Windows : même forme canonique).
pub fn move_no_replace(src: &Path, dst: &Path) -> Result<(), FsErr> {
    let sm = std::fs::symlink_metadata(src)?;
    if std::fs::symlink_metadata(dst).is_ok() {
        let same = matches!((std::fs::canonicalize(src), std::fs::canonicalize(dst)), (Ok(a), Ok(b)) if a == b);
        if !same {
            return Err(FsErr::Exists);
        }
        std::fs::rename(src, dst)?;
        return Ok(());
    }
    if sm.is_dir() {
        std::fs::create_dir(dst)?;
    } else {
        std::fs::OpenOptions::new().write(true).create_new(true).open(dst)?;
    }
    if let Err(e) = std::fs::rename(src, dst) {
        let _ = if sm.is_dir() { std::fs::remove_dir(dst) } else { std::fs::remove_file(dst) };
        return Err(e.into());
    }
    Ok(())
}

/// Taille d'un fichier ou d'un dossier (liens non suivis, borné en nombre d'entrées).
pub fn size_of(p: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(m) = std::fs::symlink_metadata(&d) else { continue };
        if is_link(&m) {
            continue;
        }
        if m.is_file() {
            total += m.len();
            continue;
        }
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                seen += 1;
                if seen > 200_000 {
                    return total;
                }
                stack.push(e.path());
            }
        }
    }
    total
}

/// Sous-dossier du dossier interne (`.rcm/<sub>`, `.rcm` lui-même si `sub` est vide), créé au
/// besoin si `create` ; refusé (`NotFound`) si `.rcm` ou lui n'est pas un vrai dossier (lien,
/// jonction posés par un processus du serveur) : le gestionnaire n'y écrit ni n'y lit jamais au
/// travers d'un lien.
pub fn internal_dir(root: &Path, sub: &str, create: bool) -> Result<PathBuf, FsErr> {
    let mut p = root.to_path_buf();
    for seg in [INTERNAL, sub].into_iter().filter(|s| !s.is_empty()) {
        p.push(seg);
        if create
            && let Err(e) = std::fs::create_dir(&p)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(e.into());
        }
        let m = std::fs::symlink_metadata(&p)?;
        if is_link(&m) || !m.is_dir() {
            return Err(FsErr::NotFound);
        }
    }
    Ok(p)
}

fn trash_root(root: &Path) -> Result<PathBuf, FsErr> {
    internal_dir(root, "trash", false)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TrashMeta {
    path: String,
    kind: FileKind,
    size: u64,
    deleted: i64,
    user: Option<String>,
}

/// Corbeille d'un serveur : éléments et octets au plus (tous partent après [`TRASH_DAYS`] jours).
/// Un envoi qui remplace un fichier y range l'ancien : sans quota, des envois répétés
/// rempliraient le disque. Quotas atteints : voir [`trash`].
pub const TRASH_MAX_ITEMS: usize = rc_manager_shared::TRASH_MAX_ITEMS;
pub const TRASH_MAX_BYTES: u64 = rc_manager_shared::TRASH_MAX_BYTES;
/// Entrées du dossier de la corbeille examinées au plus (dossier rempli hors du gestionnaire).
const TRASH_SCAN_MAX: usize = 10_000;

/// Envoie un fichier ou un dossier dans la corbeille (`.rcm/trash/<id>/`, même volume :
/// simple renommage). Rend l'identifiant. Élément plus grand que toute la corbeille : refusé
/// (`TrashTooLarge`), jamais rangé pour être effacé aussitôt (ni la corbeille vidée pour lui).
/// Quotas atteints : si `evict` (administrateur, prévenu par la fenêtre de suppression), les
/// plus anciens partent ; sinon refus (`TrashFull`) : un compte ordinaire n'efface jamais rien
/// définitivement, même par éviction.
pub fn trash(root: &Path, rel: &str, user: &str, now: i64, evict: bool) -> Result<String, FsErr> {
    if rel.is_empty() {
        return Err(FsErr::Invalid);
    }
    let src = resolve(root, rel, true)?;
    let m = std::fs::symlink_metadata(&src)?;
    let kind = if m.is_dir() { FileKind::Dir } else { FileKind::File };
    let size = size_of(&src);
    trash_admit(root, now, size, evict)?;
    let id = format!("{now}-{}", crate::crypto::base32(&crate::crypto::random_bytes::<5>()).to_ascii_lowercase());
    let slot = internal_dir(root, "trash", true)?.join(&id);
    std::fs::create_dir_all(&slot)?;
    // Description d'abord (écriture atomique : complète ou absente), élément ensuite : un
    // plantage entre les deux laisse un emplacement sans élément, ignoré par la liste et effacé
    // au démarrage ; dans l'ordre inverse, il laisserait un élément sans chemin d'origine.
    let meta = TrashMeta { path: rel.to_string(), kind, size, deleted: now, user: Some(user.to_string()) };
    if let Err(e) = crate::fsutil::write_atomic(&slot.join("meta.json"), &serde_json::to_vec(&meta).unwrap_or_default())
    {
        let _ = std::fs::remove_dir_all(&slot);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&src, slot.join("item")) {
        let _ = std::fs::remove_dir_all(&slot);
        return Err(e.into());
    }
    Ok(id)
}

/// Place d'un élément de `size` octets dans la corbeille (voir [`trash`]).
fn trash_admit(root: &Path, now: i64, size: u64, evict: bool) -> Result<(), FsErr> {
    if size > TRASH_MAX_BYTES {
        return Err(FsErr::TrashTooLarge);
    }
    if !trash_prune(root, now, Some(size), evict) {
        return Err(FsErr::TrashFull);
    }
    Ok(())
}

fn trash_id_ok(id: &str) -> bool {
    (3..=40).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Éléments lisibles de la corbeille (identifiant, description), lecture bornée.
fn trash_entries(root: &Path) -> Vec<(String, TrashMeta)> {
    let Ok(rd) = trash_root(root).and_then(|t| Ok(std::fs::read_dir(t)?)) else { return Vec::new() };
    rd.flatten()
        .take(TRASH_SCAN_MAX)
        .filter_map(|e| {
            let id = e.file_name().to_str().filter(|id| trash_id_ok(id))?.to_string();
            // Emplacement sans élément (plantage pendant une mise à la corbeille ou une
            // restauration) : ni listé, ni compté dans les quotas.
            std::fs::symlink_metadata(e.path().join("item")).ok()?;
            let b = crate::fsutil::read_bounded(&e.path().join("meta.json"), 64 * 1024).ok()?;
            Some((id, serde_json::from_slice(&b).ok()?))
        })
        .collect()
}

/// Purge de la corbeille : éléments de plus de [`TRASH_DAYS`] jours ; puis, si `evict`, les plus
/// anciens tant que les quotas ne laissent pas la place d'un élément de `incoming` octets
/// (`None` : aucun). Rend vrai si cet élément tient (jamais d'éviction pour un élément qui ne
/// tiendrait pas, même seul).
pub fn trash_prune(root: &Path, now: i64, incoming: Option<u64>, evict: bool) -> bool {
    let (extra_n, extra_b) = incoming.map_or((0, 0), |b| (1, b));
    if extra_b > TRASH_MAX_BYTES {
        return false;
    }
    let Ok(tr) = trash_root(root) else { return true };
    let mut items = trash_entries(root);
    items.retain(|(id, meta)| {
        let keep = now - meta.deleted <= TRASH_DAYS * 86_400;
        if !keep {
            let _ = std::fs::remove_dir_all(tr.join(id));
        }
        keep
    });
    items.sort_by(|a, b| a.1.deleted.cmp(&b.1.deleted).then(a.0.cmp(&b.0)));
    let mut n = items.len();
    let mut total: u64 = items.iter().map(|(_, m)| m.size).sum();
    let fits =
        |n: usize, total: u64| n + extra_n <= TRASH_MAX_ITEMS && total.saturating_add(extra_b) <= TRASH_MAX_BYTES;
    if evict {
        for (id, meta) in &items {
            if fits(n, total) {
                break;
            }
            let _ = std::fs::remove_dir_all(tr.join(id));
            n -= 1;
            total = total.saturating_sub(meta.size);
        }
    }
    fits(n, total)
}

/// Éléments de la corbeille, les plus récents d'abord ([`TRASH_MAX_ITEMS`] au plus). Simple
/// lecture : rien n'est effacé ici (la purge se fait sous le verrou des enregistrements, par la
/// mise à la corbeille et l'entretien) ; les éléments expirés sont seulement masqués.
pub fn trash_list(root: &Path, now: i64) -> Vec<TrashItem> {
    let mut out: Vec<TrashItem> = trash_entries(root)
        .into_iter()
        .filter(|(_, meta)| now - meta.deleted <= TRASH_DAYS * 86_400)
        .map(|(id, meta)| TrashItem {
            id,
            path: meta.path,
            kind: meta.kind,
            size: meta.size,
            deleted: meta.deleted,
            user: meta.user,
        })
        .collect();
    out.sort_by(|a, b| b.deleted.cmp(&a.deleted).then(b.id.cmp(&a.id)));
    out.truncate(TRASH_MAX_ITEMS);
    out
}

/// Envois interrompus laissés par un plantage ou une coupure (`.rcm/tmp/upload-*.part`) :
/// effacés au démarrage (`older_than = None`), puis seulement plus vieux que `older_than` (un
/// envoi peut être en cours).
pub fn sweep_uploads(root: &Path, older_than: Option<std::time::Duration>) {
    let Ok(rd) = internal_dir(root, "tmp", false).and_then(|t| Ok(std::fs::read_dir(t)?)) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("upload-") && name.ends_with(".part")) {
            continue;
        }
        let Ok(m) = e.metadata() else { continue };
        let age = m.modified().ok().and_then(|t| t.elapsed().ok());
        if older_than.is_none_or(|limit| age.is_some_and(|a| a > limit)) && m.is_file() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Restes d'un plantage, effacés au démarrage (aucune opération n'est alors en cours) :
/// emplacements de la corbeille sans élément (plantage entre la description et le déplacement,
/// ou entre la restauration et l'effacement de l'emplacement), et temporaires d'écriture
/// atomique (`.rcm-XXXXXXXX.tmp`, posés à côté du fichier écrit) dans tout le dossier du serveur,
/// parcouru sans suivre de lien et borné. La réservation vide d'un déplacement sans
/// remplacement ([`move_no_replace`]) ne se distingue pas d'un fichier vide légitime : elle reste.
pub fn sweep_startup(root: &Path) {
    if let Ok(rd) = trash_root(root).and_then(|t| Ok(std::fs::read_dir(t)?)) {
        for e in rd.flatten().take(TRASH_SCAN_MAX) {
            let is_slot = e.file_name().to_str().is_some_and(trash_id_ok) && e.file_type().is_ok_and(|t| t.is_dir());
            if is_slot && std::fs::symlink_metadata(e.path().join("item")).is_err() {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > 200_000 {
                return;
            }
            let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
            if is_link(&m) {
                continue;
            }
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() && e.file_name().to_str().is_some_and(crate::fsutil::is_atomic_tmp) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Remet un élément à sa place (son dossier d'origine doit exister, la place être libre).
/// Rend le chemin restauré.
pub fn trash_restore(root: &Path, id: &str) -> Result<String, FsErr> {
    let (item, path) = trash_item(root, id)?;
    let dst = resolve(root, &path, false)?;
    move_no_replace(&item, &dst)?;
    let _ = std::fs::remove_dir_all(trash_root(root)?.join(id));
    Ok(path)
}

/// Élément de la corbeille (chemin sur le disque) et chemin d'origine relatif.
pub fn trash_item(root: &Path, id: &str) -> Result<(PathBuf, String), FsErr> {
    if !trash_id_ok(id) {
        return Err(FsErr::Invalid);
    }
    let slot = trash_root(root)?.join(id);
    let meta: TrashMeta = serde_json::from_slice(&crate::fsutil::read_bounded(&slot.join("meta.json"), 64 * 1024)?)
        .map_err(|_| FsErr::Io)?;
    Ok((slot.join("item"), meta.path))
}

/// Efface définitivement un fichier ou un dossier du serveur (sans suivre de lien : un lien sur
/// le trajet est refusé par [`resolve`], et `remove_dir_all` efface un lien du dossier sans le
/// suivre).
pub fn erase(root: &Path, rel: &str) -> Result<(), FsErr> {
    if rel.is_empty() {
        return Err(FsErr::Invalid);
    }
    let p = resolve(root, rel, true)?;
    let m = std::fs::symlink_metadata(&p)?;
    if is_link(&m) {
        return Err(FsErr::NotFound);
    }
    if m.is_dir() {
        std::fs::remove_dir_all(&p)?
    } else {
        std::fs::remove_file(&p)?
    }
    Ok(())
}

/// Supprime définitivement un élément de la corbeille (sans suivre de lien).
pub fn trash_purge(root: &Path, id: &str) -> Result<(), FsErr> {
    if !trash_id_ok(id) {
        return Err(FsErr::Invalid);
    }
    let slot = trash_root(root)?.join(id);
    std::fs::symlink_metadata(&slot)?;
    std::fs::remove_dir_all(&slot)?;
    Ok(())
}

/// `server.properties` d'un serveur, sans suivre de lien, 1 Mio au plus (UTF-8, sinon ISO-8859-1
/// comme le jeu) ; absent ou illisible : vide (valeurs par défaut du jeu).
pub fn server_properties(root: &Path) -> String {
    crate::fsutil::read_bounded(&root.join("server.properties"), rc_manager_shared::FILE_EDIT_MAX)
        .map(|b| match String::from_utf8(b) {
            Ok(s) => s,
            Err(e) => e.into_bytes().iter().map(|&b| b as char).collect(),
        })
        .unwrap_or_default()
}

/// Dossiers du monde (`level-name`, et `_nether`, `_the_end` des serveurs Bukkit), relatifs.
pub fn world_dirs(root: &Path) -> Vec<String> {
    let text = server_properties(root);
    let level = crate::props::get(&text, "level-name").filter(|l| !l.is_empty()).unwrap_or_else(|| "world".into());
    let level = level.replace('\\', "/").trim_matches('/').to_string();
    vec![level.clone(), format!("{level}_nether"), format!("{level}_the_end")]
}

/// `rel` est-il dans (ou est-il) un des dossiers donnés (comparaison sans casse) ?
pub fn under_any(rel: &str, dirs: &[String]) -> bool {
    let r = rule_rel(rel);
    dirs.iter().any(|d| {
        let d = rule_rel(d);
        r == d || r.starts_with(&format!("{d}/")) || d.starts_with(&format!("{r}/"))
    })
}

/// Écrit un dossier en zip dans `w`, en flux (sans lien, sans `.rcm` à la racine du serveur).
pub fn zip_dir<W: std::io::Write>(root: &Path, rel: &str, w: W) -> Result<(), FsErr> {
    use zip::write::SimpleFileOptions;
    let base = resolve(root, rel, true)?;
    if !std::fs::symlink_metadata(&base)?.is_dir() {
        return Err(FsErr::WrongKind);
    }
    let mut z = zip::ZipWriter::new_stream(w);
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(1))
        .large_file(true);
    let mut stack = vec![(base.clone(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut items: Vec<_> = std::fs::read_dir(&dir)?.flatten().collect();
        items.sort_by_key(|e| e.file_name());
        for e in items {
            let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
            if rel.is_empty() && prefix.is_empty() && name.eq_ignore_ascii_case(INTERNAL) {
                continue;
            }
            // Nom refusé par les règles (sortirait du dossier à l'extraction sous Windows : `a\b`,
            // `x.`, nom court…) : sauté, comme il est bloqué dans la liste.
            if !segment_ok(&name) {
                continue;
            }
            // Lu sans suivre : un lien, une jonction ou un autre point d'analyse est sauté.
            let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
            if is_link(&m) {
                continue;
            }
            let zname = format!("{prefix}{name}");
            if m.is_dir() {
                z.add_directory(format!("{zname}/"), opts).map_err(|_| FsErr::Io)?;
                stack.push((e.path(), format!("{zname}/")));
            } else if m.is_file() {
                let Ok(mut f) = open_file(&e.path()) else { continue };
                z.start_file(zname, opts).map_err(|_| FsErr::Io)?;
                std::io::copy(&mut f, &mut z).map_err(|_| FsErr::Io)?;
            }
        }
    }
    z.finish().map_err(|_| FsErr::Io)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rcm-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Lien symbolique de fichier (Windows : mode développeur ou droit requis ; `false` sinon).
    pub(crate) fn link_file(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        return std::os::unix::fs::symlink(target, link).is_ok();
        #[cfg(windows)]
        return std::os::windows::fs::symlink_file(target, link).is_ok();
    }

    pub(crate) fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        return std::os::unix::fs::symlink(target, link).is_ok();
        #[cfg(windows)]
        return std::os::windows::fs::symlink_dir(target, link).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|o| o.status.success());
    }

    /// Chemins hostiles : refusés par leur forme, avant le disque.
    #[test]
    fn chemins_hostiles_refuses() {
        for bad in [
            "..",
            "../x",
            "a/../../x",
            "a/..",
            "./a",
            "a/./b",
            "/etc/passwd",
            "\\windows",
            "C:/x",
            "C:x",
            "a\\..\\x",
            "%2e%2e/x",
            "%2E%2E%2Fx",
            "a/%2f/b",
            "a//b",
            "a/",
            "/",
            "CON",
            "a/nul.txt",
            "COM¹",
            "LPT³.log",
            "aux .txt",
            "a.",
            "a ",
            "a\0b",
            "a\nb",
            "a\u{7f}",
            "x:stream",
            "a*b",
            "a?b",
            "a|b",
            "a<b",
            ".rcm",
            ".RCM/trash",
            ".Rcm",
        ] {
            assert!(parse_rel(bad).is_none(), "{bad:?}");
        }
        assert!(parse_rel(&"a/".repeat(600)).is_none(), "trop long");
        assert_eq!(parse_rel("").unwrap(), Vec::<&str>::new());
        for ok in ["world", "plugins/x/config.yml", ".fabric/cache", "a.rcm", "sub/.rcm", "logs/latest.log", "é à"] {
            assert!(parse_rel(ok).is_some(), "{ok}");
        }
    }

    /// Windows : noms courts 8.3 et casse. Les fichiers existent réellement ; un nom court (alias
    /// d'un autre nom) est refusé avant le disque, et chaque composant présent doit porter son nom
    /// réel ; les règles (fichiers gérés, `.rcm`, monde, listes, réglages) voient la forme sans casse.
    #[cfg(windows)]
    #[test]
    fn noms_courts_et_casse_windows() {
        use crate::paths::real_names_match;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("rcm-noms-windows-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".rcm")).unwrap();
        std::fs::create_dir_all(root.join("world")).unwrap();
        std::fs::create_dir_all(root.join("plugins")).unwrap();
        std::fs::write(root.join(".rcm/console.jsonl"), "x").unwrap();
        std::fs::write(root.join("world/level.dat"), "x").unwrap();
        std::fs::write(root.join("server.properties"), "online-mode=true\nlevel-name=world\n").unwrap();
        std::fs::write(root.join("eula.txt"), "eula=true\n").unwrap();
        std::fs::write(root.join("spigot.yml"), "settings:\n  restart-script: ./start.sh\n").unwrap();
        std::fs::write(root.join("plugins/loader.jar"), "x").unwrap();
        // Noms courts : refusés par la forme (lecture, écriture, création), que le volume les crée
        // ou non (D: n'en crée pas par défaut).
        for rel in [
            "SERVER~1.PRO",
            "RCM~1/console.jsonl",
            "RCM~1",
            "EULA~1.TXT",
            "SPIGOT~1.YML",
            "WORLD~1/level.dat",
            "plugins/LOADER~1.JAR",
        ] {
            assert_eq!(resolve(&root, rel, true), Err(FsErr::Invalid), "{rel}");
            assert_eq!(resolve(&root, rel, false), Err(FsErr::Invalid), "{rel}");
            assert!(read_text(&root, rel).is_err(), "{rel}");
        }
        // Nom réel : un alias dont la forme canonique porte un autre nom ne passe pas.
        let canon_root = std::fs::canonicalize(&root).unwrap();
        let real = std::fs::canonicalize(root.join("server.properties")).unwrap();
        assert!(real_names_match(&canon_root, &real, &["server.properties"]));
        assert!(real_names_match(&canon_root, &real, &["Server.Properties"]), "casse à part");
        assert!(!real_names_match(&canon_root, &real, &["SERVER~1.PRO"]));
        assert!(!real_names_match(&canon_root, &real, &["eula.txt"]));
        if let Ok(short) = std::fs::canonicalize(root.join("SERVER~1.PRO")) {
            // Volume qui crée les noms courts : la forme canonique rend le vrai nom long.
            assert!(real_names_match(&canon_root, &short, &["server.properties"]));
            assert!(!real_names_match(&canon_root, &short, &["SERVER~1.PRO"]));
        }
        // Casse : le système ouvre le même fichier ; les règles le reconnaissent.
        assert!(resolve(&root, "Server.Properties", true).is_ok());
        assert_eq!(rule_rel("Server.Properties"), "server.properties");
        assert!(managed_rel("EULA.TXT") && managed_rel("Eula.txt"));
        assert!(resolve(&root, "EULA.TXT", true).is_ok(), "même fichier que eula.txt");
        for rel in [".RCM/console.jsonl", ".Rcm"] {
            assert!(parse_rel(rel).is_none(), "{rel}");
        }
        assert!(under_any("WORLD/level.dat", &world_dirs(&root)));
        assert!(executable_name("plugins/Loader.JAR"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Liens et jonctions refusés AU MOMENT de l'opération, qu'ils sortent du dossier ou non ;
    /// listés sans être suivis ; jamais suivis par le zip.
    #[test]
    fn liens_refuses_au_moment_de_l_operation() {
        let root = tmp("liens");
        let outside = tmp("liens-dehors");
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();
        std::fs::create_dir_all(root.join("world")).unwrap();
        std::fs::write(root.join("world/level.dat"), "x").unwrap();
        std::fs::write(root.join("a.txt"), "a").unwrap();
        assert!(read_text(&root, "a.txt").is_ok());
        // Lien vers l'extérieur.
        assert!(link_dir(&outside, &root.join("dehors")), "lien impossible à créer pour le test");
        assert!(root.join("dehors/secret.txt").exists(), "le lien mène bien dehors");
        for op in [
            read_text(&root, "dehors/secret.txt").map(|_| ()),
            write_text(&root, "dehors/new.txt", b"x", "").map(|_| ()),
            mkdir(&root, "dehors/d"),
            rename(&root, "a.txt", "dehors/a.txt"),
            rename(&root, "dehors/secret.txt", "b.txt"),
            trash(&root, "dehors/secret.txt", "u", 1, true).map(|_| ()),
            list(&root, "dehors").map(|_| ()),
        ] {
            assert_eq!(op, Err(FsErr::NotFound));
        }
        assert!(!outside.join("new.txt").exists() && !outside.join("d").exists() && !outside.join("a.txt").exists());
        assert_eq!(std::fs::read_to_string(outside.join("secret.txt")).unwrap(), "secret");
        // Le lien lui-même : listé comme lien, jamais suivi ; ni renommé, ni mis à la corbeille.
        let l = list(&root, "").unwrap();
        assert_eq!(l.entries.iter().find(|e| e.name == "dehors").unwrap().kind, FileKind::Link);
        assert_eq!(trash(&root, "dehors", "u", 1, true), Err(FsErr::NotFound));
        // Lien qui reste DANS le dossier (vers le monde) : refusé aussi.
        assert!(link_dir(&root.join("world"), &root.join("monde2")));
        assert_eq!(read_text(&root, "monde2/level.dat").map(|_| ()), Err(FsErr::NotFound));
        // Zip : le lien n'est pas suivi.
        let mut buf = Vec::new();
        zip_dir(&root, "", &mut buf).unwrap();
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(buf)).unwrap();
        let names: Vec<String> = (0..z.len()).map(|i| z.by_index(i).unwrap().name().unwrap().to_string()).collect();
        assert!(names.contains(&"a.txt".to_string()) && names.contains(&"world/level.dat".to_string()), "{names:?}");
        assert!(
            !names.iter().any(|n| n.contains("secret") || n.starts_with("dehors") || n.starts_with("monde2")),
            "{names:?}"
        );
        // Lien posé APRÈS une vérification réussie : l'opération suivante le voit.
        std::fs::create_dir_all(root.join("sub")).unwrap();
        assert!(resolve(&root, "sub/x.txt", false).is_ok());
        std::fs::remove_dir(root.join("sub")).unwrap();
        assert!(link_dir(&outside, &root.join("sub")));
        assert_eq!(write_text(&root, "sub/x.txt", b"x", "").map(|_| ()), Err(FsErr::NotFound));
        assert!(!outside.join("x.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Dossier interne `.rcm` : ni listé, ni lisible, ni modifiable, ni dans le zip.
    #[test]
    fn dossier_interne_invisible() {
        let root = tmp("interne");
        std::fs::create_dir_all(root.join(".rcm/tmp")).unwrap();
        std::fs::write(root.join(".rcm/console.jsonl"), "x").unwrap();
        std::fs::write(root.join("a.txt"), "a").unwrap();
        assert!(list(&root, "").unwrap().entries.iter().all(|e| !e.name.eq_ignore_ascii_case(".rcm")));
        for rel in [".rcm/console.jsonl", ".RCM/console.jsonl", ".rcm"] {
            assert_eq!(read_text(&root, rel).map(|_| ()), Err(FsErr::Invalid), "{rel}");
            assert_eq!(trash(&root, rel, "u", 1, true).map(|_| ()), Err(FsErr::Invalid));
            assert_eq!(rename(&root, "a.txt", rel), Err(FsErr::Invalid));
        }
        let mut buf = Vec::new();
        zip_dir(&root, "", &mut buf).unwrap();
        let z = zip::ZipArchive::new(std::io::Cursor::new(buf)).unwrap();
        assert!(z.file_names().all(|n| !n.unwrap().to_lowercase().starts_with(".rcm")));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Écriture, renommage, corbeille et restauration ; aucun temporaire restant.
    #[test]
    fn operations_et_corbeille() {
        let root = tmp("ops");
        assert_eq!(write_text(&root, "n.txt", b"un", "").unwrap(), b"");
        assert_eq!(write_text(&root, "n.txt", b"deux", ""), Err(FsErr::Exists), "existe : empreinte exigée");
        assert_eq!(write_text(&root, "n.txt", b"deux", "faux"), Err(FsErr::Exists));
        let h = crate::configs::hash(b"un");
        assert_eq!(write_text(&root, "n.txt", b"deux", &h).unwrap(), b"un");
        assert_eq!(write_text(&root, "absent.txt", b"x", &h), Err(FsErr::NotFound));
        assert_eq!(write_text(&root, "pas/de/parent.txt", b"x", ""), Err(FsErr::NotFound));
        mkdir(&root, "d").unwrap();
        assert_eq!(mkdir(&root, "d"), Err(FsErr::Exists));
        assert_eq!(rename(&root, "d", "d/e"), Err(FsErr::Invalid), "dossier dans lui-même");
        rename(&root, "n.txt", "d/m.txt").unwrap();
        assert_eq!(read_text(&root, "d/m.txt").unwrap().1, "deux");
        std::fs::write(root.join("o.txt"), "o").unwrap();
        assert_eq!(rename(&root, "o.txt", "d/m.txt"), Err(FsErr::Exists));
        let id = trash(&root, "d", "neo", 1000, true).unwrap();
        assert!(!root.join("d").exists());
        let items = trash_list(&root, 1000);
        assert_eq!((items.len(), items[0].path.as_str(), items[0].kind), (1, "d", FileKind::Dir));
        assert_eq!(items[0].size, 4);
        assert_eq!(trash_restore(&root, &id).unwrap(), "d");
        assert_eq!(read_text(&root, "d/m.txt").unwrap().1, "deux");
        assert!(trash_list(&root, 1000).is_empty());
        // Expiration après 30 jours ; identifiant hostile refusé.
        let id = trash(&root, "o.txt", "neo", 1000, true).unwrap();
        assert_eq!(trash_restore(&root, "../../x"), Err(FsErr::Invalid));
        assert_eq!(trash_purge(&root, "..\\x"), Err(FsErr::Invalid));
        let later = 1000 + TRASH_DAYS * 86_400 + 1;
        assert!(trash_list(&root, later).is_empty());
        assert!(root.join(".rcm/trash").join(&id).exists(), "la liste n'efface rien");
        assert!(trash_prune(&root, later, None, false));
        assert!(!root.join(".rcm/trash").join(&id).exists(), "expiré : effacé par l'entretien");
        // Binaire : pas éditable.
        std::fs::write(root.join("b.txt"), b"a\0b").unwrap();
        assert_eq!(read_text(&root, "b.txt").map(|_| ()), Err(FsErr::NotText));
        std::fs::write(root.join("s.jar"), b"PK").unwrap();
        assert_eq!(read_text(&root, "s.jar").map(|_| ()), Err(FsErr::NotText));
        let names: Vec<String> =
            std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Déplacement sans remplacement : ce qui occupe la destination (apparu après une vérification)
    /// n'est jamais remplacé, quelle que soit la nature des deux côtés ; même élément à la casse
    /// près (Windows) : renommé.
    #[test]
    fn deplacement_sans_remplacement() {
        let root = tmp("sans-remplacement");
        let p = |s: &str| root.join(s);
        std::fs::write(p("a.txt"), "a").unwrap();
        std::fs::write(p("b.txt"), "b").unwrap();
        std::fs::create_dir_all(p("d/sous")).unwrap();
        std::fs::create_dir(p("vide")).unwrap();
        for (src, dst) in [("a.txt", "b.txt"), ("d", "vide"), ("d", "b.txt"), ("a.txt", "vide")] {
            assert_eq!(move_no_replace(&p(src), &p(dst)), Err(FsErr::Exists), "{src} -> {dst}");
        }
        assert_eq!(std::fs::read_to_string(p("b.txt")).unwrap(), "b");
        assert!(p("d/sous").is_dir() && p("vide").is_dir() && p("a.txt").is_file());
        move_no_replace(&p("a.txt"), &p("c.txt")).unwrap();
        move_no_replace(&p("d"), &p("e")).unwrap();
        assert!(!p("a.txt").exists() && p("c.txt").is_file() && p("e/sous").is_dir() && !p("d").exists());
        // Restauration : la place prise entre-temps n'est pas écrasée, l'élément reste en corbeille.
        let id = trash(&root, "c.txt", "u", 1, true).unwrap();
        std::fs::write(p("c.txt"), "nouveau").unwrap();
        assert_eq!(trash_restore(&root, &id), Err(FsErr::Exists));
        assert_eq!(std::fs::read_to_string(p("c.txt")).unwrap(), "nouveau");
        assert_eq!(trash_list(&root, 1).len(), 1);
        #[cfg(windows)]
        {
            rename(&root, "e", "E").unwrap();
            let names: Vec<String> = std::fs::read_dir(&root)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(names.contains(&"E".to_string()), "{names:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Emplacement de corbeille décrit (taille annoncée, élément réduit à un dossier vide).
    fn described(root: &Path, id: &str, deleted: i64, size: u64) {
        let slot = root.join(".rcm/trash").join(id);
        std::fs::create_dir_all(slot.join("item")).unwrap();
        let meta = format!(r#"{{"path":"w{id}","kind":"dir","size":{size},"deleted":{deleted},"user":null}}"#);
        std::fs::write(slot.join("meta.json"), meta).unwrap();
    }

    /// Corbeille bornée en éléments et en octets : les plus anciens partent pour un administrateur
    /// seulement (un compte ordinaire est refusé, rien n'est effacé) ; liste plafonnée ; envois
    /// interrompus effacés (tous au démarrage, les vieux seulement ensuite).
    #[test]
    fn corbeille_bornee_et_entretien() {
        let root = tmp("quota");
        for i in 0..TRASH_MAX_ITEMS {
            std::fs::write(root.join("f.txt"), "x").unwrap();
            trash(&root, "f.txt", "u", 1000 + i as i64, false).unwrap();
        }
        std::fs::write(root.join("f.txt"), "x").unwrap();
        assert_eq!(trash(&root, "f.txt", "u", 1500, false), Err(FsErr::TrashFull), "compte ordinaire : refus");
        assert!(root.join("f.txt").exists());
        assert_eq!(std::fs::read_dir(root.join(".rcm/trash")).unwrap().count(), TRASH_MAX_ITEMS, "rien d'effacé");
        for i in 0..5 {
            std::fs::write(root.join("f.txt"), "x").unwrap();
            trash(&root, "f.txt", "u", 1600 + i, true).unwrap();
        }
        let items = trash_list(&root, 2000);
        assert_eq!(items.len(), TRASH_MAX_ITEMS);
        assert_eq!(items.last().unwrap().deleted, 1005, "les plus anciens sont partis");
        let on_disk = std::fs::read_dir(root.join(".rcm/trash")).unwrap().count();
        assert_eq!(on_disk, TRASH_MAX_ITEMS);
        // Octets : deux gros éléments décrits, un troisième arrive ; le plus ancien part.
        let root = tmp("quota-octets");
        described(&root, "1-a", 1, 7 << 30);
        described(&root, "2-b", 2, 7 << 30);
        assert!(!trash_prune(&root, 3, Some(4 << 30), false), "sans éviction : ne tient pas");
        assert!(root.join(".rcm/trash/1-a").exists());
        assert!(trash_prune(&root, 3, Some(4 << 30), true));
        assert!(!root.join(".rcm/trash/1-a").exists() && root.join(".rcm/trash/2-b").exists());
        // Envois interrompus.
        let t = root.join(".rcm/tmp");
        std::fs::create_dir_all(&t).unwrap();
        std::fs::write(t.join("upload-abc.part"), "x").unwrap();
        std::fs::write(t.join("autre.txt"), "x").unwrap();
        sweep_uploads(&root, Some(std::time::Duration::from_secs(3600)));
        assert!(t.join("upload-abc.part").exists(), "récent : peut être en cours");
        sweep_uploads(&root, None);
        assert!(!t.join("upload-abc.part").exists() && t.join("autre.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Élément plus grand que toute la corbeille : refusé, sans rien effacer d'autre ; un élément
    /// rangé n'est jamais effacé par la liste ni par l'entretien tant qu'il tient dans les quotas.
    #[test]
    fn corbeille_trop_gros_jamais_videe() {
        let root = tmp("trop-gros");
        described(&root, "1-a", 1, 1 << 30);
        assert_eq!(trash_admit(&root, 2, 17 << 30, true), Err(FsErr::TrashTooLarge));
        assert!(!trash_prune(&root, 2, Some(17 << 30), true));
        assert!(root.join(".rcm/trash/1-a").exists(), "rien d'effacé pour un entrant qui ne tient pas");
        // Élément de 15 Gio admis (un compte ordinaire, place libre) : il reste.
        assert_eq!(trash_admit(&root, 2, 15 << 30, false), Ok(()));
        described(&root, "2-b", 2, 15 << 30);
        assert_eq!(trash_list(&root, 3).len(), 2);
        assert!(trash_prune(&root, 3, None, true));
        assert!(root.join(".rcm/trash/1-a").exists() && root.join(".rcm/trash/2-b").exists());
        // Un 17 Gio décrit (posé hors du gestionnaire) : la liste le montre sans l'effacer.
        described(&root, "3-c", 3, 17 << 30);
        assert_eq!(trash_list(&root, 4).len(), 3);
        assert!(root.join(".rcm/trash/3-c").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Plantage entre la description et l'élément (ou au milieu d'une restauration) : emplacement
    /// sans élément ni listé, ni compté, effacé au démarrage ; temporaires d'écriture atomique
    /// effacés au démarrage (sans suivre de lien), le reste gardé.
    #[test]
    fn restes_d_un_plantage() {
        let root = tmp("plantage");
        let outside = tmp("plantage-dehors");
        described(&root, "1-a", 1, 15 << 30);
        std::fs::remove_dir(root.join(".rcm/trash/1-a/item")).unwrap();
        assert!(trash_list(&root, 2).is_empty(), "fantôme : pas listé");
        assert_eq!(trash_admit(&root, 2, 15 << 30, false), Ok(()), "fantôme : pas compté");
        std::fs::create_dir_all(root.join("plugins/Essentials")).unwrap();
        std::fs::write(root.join("plugins/Essentials/.rcm-ABCDE234.tmp"), "x").unwrap();
        std::fs::write(root.join(".rcm-ZZZZ2345.tmp"), "x").unwrap();
        std::fs::write(root.join(".rcm-notes.tmp"), "x").unwrap();
        std::fs::write(root.join("plugins/Essentials/config.yml"), "x").unwrap();
        std::fs::write(outside.join(".rcm-ABCDE234.tmp"), "x").unwrap();
        assert!(link_dir(&outside, &root.join("lien")));
        sweep_startup(&root);
        assert!(!root.join(".rcm/trash/1-a").exists());
        assert!(
            !root.join("plugins/Essentials/.rcm-ABCDE234.tmp").exists() && !root.join(".rcm-ZZZZ2345.tmp").exists()
        );
        assert!(root.join(".rcm-notes.tmp").exists() && root.join("plugins/Essentials/config.yml").exists());
        assert!(outside.join(".rcm-ABCDE234.tmp").exists(), "lien jamais suivi");
        let _ = std::fs::remove_dir(root.join("lien")).or_else(|_| std::fs::remove_file(root.join("lien")));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// FIFO posée à la place d'un fichier (Unix) : refusée sans bloquer (lecture et ajout).
    #[cfg(unix)]
    #[test]
    fn fifo_refusee_sans_bloquer() {
        let root = tmp("fifo");
        let p = root.join("server.properties");
        assert!(std::process::Command::new("mkfifo").arg(&p).status().is_ok_and(|s| s.success()));
        let (tx, rx) = std::sync::mpsc::channel();
        let r = root.clone();
        std::thread::spawn(move || {
            let read = crate::fsutil::read_bounded(&r.join("server.properties"), 1024).is_err();
            let props = server_properties(&r).is_empty();
            let append = open_append(&r.join("server.properties")).is_err();
            let _ = tx.send((read, props, append));
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("bloqué sur la FIFO");
        assert_eq!(got, (true, true, true));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `.rcm` remplacé par un lien (posé par un processus du serveur) : ni temporaires, ni
    /// corbeille au travers ; nom hostile jamais mis dans un zip ; scripts de greffons comptés
    /// comme programmes ; `server.properties` lu borné.
    #[test]
    fn interne_zip_programmes_et_monde() {
        let root = tmp("interne-lien");
        let outside = tmp("interne-lien-dehors");
        std::fs::write(root.join("a.txt"), "a").unwrap();
        assert!(link_dir(&outside, &root.join(".rcm")));
        assert_eq!(internal_dir(&root, "tmp", true), Err(FsErr::NotFound));
        assert!(trash(&root, "a.txt", "u", 1, true).is_err());
        assert!(root.join("a.txt").exists() && std::fs::read_dir(&outside).unwrap().next().is_none());
        assert!(trash_list(&root, 1).is_empty());
        std::fs::remove_dir(root.join(".rcm")).or_else(|_| std::fs::remove_file(root.join(".rcm"))).unwrap();
        assert!(internal_dir(&root, "tmp", true).is_ok_and(|p| p.is_dir()));
        // Zip : noms que les règles refusent (forme courte 8.3, alias d'un autre nom ; Windows :
        // point final, créé par la forme brute `\\?\` ; Unix : antislashs, chemin à l'extraction
        // sous Windows).
        #[cfg(windows)]
        let bad = [root.join("ab~1.txt"), std::fs::canonicalize(&root).unwrap().join("x.")];
        #[cfg(unix)]
        let bad = [root.join("ab~1.txt"), root.join("a\\..\\b")];
        for b in &bad {
            std::fs::write(b, "x").unwrap();
        }
        let mut buf = Vec::new();
        zip_dir(&root, "", &mut buf).unwrap();
        let z = zip::ZipArchive::new(std::io::Cursor::new(buf)).unwrap();
        let names: Vec<String> = z.file_names().map(|n| n.unwrap().into_owned()).collect();
        assert_eq!(names, ["a.txt"]);
        for b in &bad {
            let _ = std::fs::remove_file(b);
        }
        for p in ["scripts/a.zs", "plugins/Skript/scripts/b.sk", "kubejs/c.lua", "d.groovy", "e.kts"] {
            assert!(executable_name(p), "{p}");
        }
        // `server.properties` démesuré : non lu (monde par défaut), comme le reste des fichiers.
        let mut big = "#\n".repeat(600_000);
        big.push_str("level-name=ailleurs\n");
        std::fs::write(root.join("server.properties"), big).unwrap();
        assert_eq!(world_dirs(&root)[0], "world");
        std::fs::write(root.join("server.properties"), "level-name=ailleurs\n").unwrap();
        assert_eq!(world_dirs(&root)[0], "ailleurs");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn monde_et_noms() {
        let root = tmp("monde");
        std::fs::write(root.join("server.properties"), "level-name=mondes/survie\n").unwrap();
        let w = world_dirs(&root);
        assert_eq!(w, ["mondes/survie", "mondes/survie_nether", "mondes/survie_the_end"]);
        assert!(under_any("mondes/survie/region/r.0.0.mca", &w));
        assert!(under_any("Mondes/Survie", &w));
        assert!(under_any("mondes", &w), "parent du monde");
        assert!(!under_any("mondes/autre", &w));
        assert!(!under_any("plugins", &w));
        assert!(executable_name("x.JAR") && executable_name("start.sh") && !executable_name("a.yml"));
        assert!(sensitive_name("config/paper-global.yml") && sensitive_name("server.properties"));
        assert!(sensitive_name("plugins/x/api-token.txt") && !sensitive_name("logs/latest.log"));
        assert!(managed_rel("EULA.txt") && !managed_rel("sub/eula.txt"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
