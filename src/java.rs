//! Java : Temurin (JRE) téléchargé depuis l'API Adoptium selon la version demandée par le jeu
//! (`javaVersion.majorVersion` du manifeste Mojang : 25 pour 26.x, 21 pour 1.20.5 à 1.21.x, 17
//! pour 1.18 à 1.20.4, 16 pour 1.17 — servi par 17, Adoptium n'ayant pas de JRE 16 —, 8 avant),
//! installé dans `<données>/java/<majeure>`. Un Java déjà installé sur la machine reste
//! sélectionnable (détecté, ou chemin donné par un administrateur).
//!
//! Tout processus enfant (sonde `java -version`, serveurs) reçoit un environnement VIDÉ puis une
//! courte liste blanche ([`minimal_env`]) : jamais la clé ni un secret du gestionnaire.

use crate::download::{Checksum, DlError, Expect, Http};
use crate::paths::java_dir;
use rc_manager_shared::JavaInfo;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// Versions à support long d'Adoptium ; une version intermédiaire est servie par la suivante.
pub const LTS: [u32; 5] = [8, 11, 17, 21, 25];

/// Java à installer pour une version demandée par le jeu.
pub fn runtime_for(game_major: u32) -> u32 {
    if game_major <= 8 {
        return 8;
    }
    LTS.iter().copied().find(|&l| l >= game_major).unwrap_or(game_major)
}

pub fn exe_name() -> &'static str {
    if cfg!(windows) { "java.exe" } else { "java" }
}

/// Exécutable d'un Java géré, s'il est installé.
pub fn managed_exe(data: &Path, major: u32) -> Option<PathBuf> {
    let p = java_dir(data, major).join("bin").join(exe_name());
    p.is_file().then_some(p)
}

/// Variables transmises aux processus enfants, et elles seules (liste blanche). `tmp` : dossier
/// temporaire propre au serveur.
pub fn minimal_env(tmp: &Path) -> Vec<(OsString, OsString)> {
    let mut v: Vec<(OsString, OsString)> = Vec::new();
    let t = tmp.as_os_str().to_owned();
    v.push(("TMP".into(), t.clone()));
    v.push(("TEMP".into(), t.clone()));
    // Sans SystemRoot, Java ne peut pas initialiser le réseau sous Windows.
    #[cfg(windows)]
    for k in ["SystemRoot", "SystemDrive", "windir", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"] {
        if let Some(val) = std::env::var_os(k) {
            v.push((k.into(), val));
        }
    }
    #[cfg(unix)]
    {
        v.push(("TMPDIR".into(), t));
        v.push(("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()));
        v.push(("LANG".into(), "C.UTF-8".into()));
    }
    // Fuseau horaire (heures du journal du serveur), jamais un secret.
    if let Some(tz) = std::env::var_os("TZ") {
        v.push(("TZ".into(), tz));
    }
    v
}

/// Commande sans shell ni environnement hérité.
pub fn command(exe: &Path, dir: &Path, tmp: &Path) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(exe);
    c.current_dir(dir).env_clear().envs(minimal_env(tmp)).stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        // Pas de fenêtre de console, et un groupe de processus à part : un Ctrl+C dans la console
        // du gestionnaire ne tue pas les serveurs (c'est le gestionnaire qui les arrête proprement).
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        c.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }
    c
}

/// Lit `java -version` (sortie d'erreur) : (majeure, version complète).
pub fn parse_version_output(s: &str) -> Option<(u32, String)> {
    let line = s.lines().find(|l| l.contains("version \""))?;
    let v = line.split('"').nth(1)?.to_string();
    let major = if let Some(rest) = v.strip_prefix("1.") {
        rest.split(['.', '_']).next()?.parse().ok()?
    } else {
        v.split(['.', '+', '-']).next()?.parse().ok()?
    };
    Some((major, v))
}

/// Interroge un exécutable `java` (5 s au plus).
pub async fn probe(exe: &Path, tmp: &Path) -> Option<(u32, String)> {
    let dir = exe.parent()?;
    let mut c = command(exe, dir, tmp);
    c.arg("-version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(5), c.output()).await.ok()?.ok()?;
    parse_version_output(&String::from_utf8_lossy(&out.stderr))
}

/// Chemin donné par un administrateur : fichier existant nommé `java` (`java.exe`), qui répond.
pub async fn validate_custom(path: &str, tmp: &Path) -> Option<(PathBuf, u32)> {
    let p = std::fs::canonicalize(path.trim()).ok()?;
    let name = p.file_name()?.to_string_lossy().to_ascii_lowercase();
    if !p.is_file() || name != exe_name() {
        return None;
    }
    let (major, _) = probe(&p, tmp).await?;
    Some((p, major))
}

/// Java installés : gérés, puis ceux de la machine (JAVA_HOME, PATH, dossiers usuels).
pub async fn detect(data: &Path, tmp: &Path) -> Vec<JavaInfo> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(data.join("java")) {
        let mut dirs: Vec<_> = rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()).collect();
        dirs.sort_unstable_by(|a, b| b.cmp(a));
        for m in dirs {
            if let Some(exe) = managed_exe(data, m)
                && let Some((major, version)) = probe(&exe, tmp).await
            {
                seen.insert(exe.clone());
                out.push(JavaInfo { major, version, path: exe.to_string_lossy().into_owned(), managed: true });
            }
        }
    }
    for exe in system_candidates() {
        let Ok(c) = std::fs::canonicalize(&exe) else { continue };
        if !seen.insert(c.clone()) {
            continue;
        }
        if let Some((major, version)) = probe(&c, tmp).await {
            out.push(JavaInfo { major, version, path: c.to_string_lossy().into_owned(), managed: false });
        }
    }
    out
}

fn system_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = std::env::var_os("JAVA_HOME") {
        v.push(PathBuf::from(h).join("bin").join(exe_name()));
    }
    if let Some(p) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&p) {
            let e = d.join(exe_name());
            if e.is_file() {
                v.push(e);
            }
        }
    }
    let roots: &[&str] = if cfg!(windows) {
        &[
            r"C:\Program Files\Eclipse Adoptium",
            r"C:\Program Files\Java",
            r"C:\Program Files\Microsoft",
            r"C:\Program Files\Zulu",
            r"C:\Program Files\BellSoft",
            r"C:\Program Files\Amazon Corretto",
        ]
    } else {
        &["/usr/lib/jvm", "/opt/java"]
    };
    for r in roots {
        if let Ok(rd) = std::fs::read_dir(r) {
            for e in rd.flatten() {
                let exe = e.path().join("bin").join(exe_name());
                if exe.is_file() {
                    v.push(exe);
                }
            }
        }
    }
    v.truncate(32);
    v
}

#[derive(Deserialize)]
struct Asset {
    binary: Binary,
}
#[derive(Deserialize)]
struct Binary {
    package: Package,
}
#[derive(Deserialize)]
struct Package {
    name: String,
    link: String,
    checksum: String,
    size: u64,
}

/// Système et architecture au sens d'Adoptium.
pub fn adoptium_platform() -> (&'static str, &'static str) {
    let os = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "mac"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x64" };
    (os, arch)
}

static LOCKS: LazyLock<Mutex<HashMap<u32, Arc<tokio::sync::Mutex<()>>>>> = LazyLock::new(Default::default);

#[derive(Debug)]
pub enum JavaError {
    Download(DlError),
    Unavailable,
    Extract(String),
}

impl JavaError {
    pub fn code(&self) -> rc_manager_shared::ErrorCode {
        match self {
            JavaError::Download(e) => e.code(),
            _ => rc_manager_shared::ErrorCode::JavaNotFound,
        }
    }
}

impl std::fmt::Display for JavaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JavaError::Download(e) => write!(f, "{e}"),
            JavaError::Unavailable => f.write_str("aucun JRE Temurin pour cette version et cette plateforme"),
            JavaError::Extract(e) => write!(f, "extraction : {e}"),
        }
    }
}

/// Java géré `major` (déjà installé, sinon téléchargé, vérifié et extrait). Une seule
/// installation à la fois par version (deux serveurs qui démarrent ensemble attendent).
pub async fn ensure(
    http: &Http,
    data: &Path,
    major: u32,
    progress: &(dyn Fn(u64, Option<u64>) + Send + Sync),
) -> Result<PathBuf, JavaError> {
    if let Some(e) = managed_exe(data, major) {
        return Ok(e);
    }
    let lock = LOCKS.lock().unwrap_or_else(|p| p.into_inner()).entry(major).or_default().clone();
    let _g = lock.lock().await;
    if let Some(e) = managed_exe(data, major) {
        return Ok(e);
    }
    let (os, arch) = adoptium_platform();
    let url = format!(
        "https://api.adoptium.net/v3/assets/latest/{major}/hotspot?architecture={arch}&image_type=jre&os={os}&vendor=eclipse"
    );
    let assets: Vec<Asset> = http.json(&url).await.map_err(JavaError::Download)?;
    let pkg = assets.into_iter().next().ok_or(JavaError::Unavailable)?.binary.package;
    let checksum = Checksum::sha256(&pkg.checksum).ok_or(JavaError::Unavailable)?;
    // Nom de l'archive : seulement pour l'extension (jamais un chemin).
    let zip = pkg.name.ends_with(".zip");
    if !zip && !pkg.name.ends_with(".tar.gz") {
        return Err(JavaError::Unavailable);
    }
    let root = data.join("java");
    let archive = root.join(format!(".download-{major}{}", if zip { ".zip" } else { ".tar.gz" }));
    http.file(&pkg.link, &archive, Expect { checksum, size: Some(pkg.size) }, progress)
        .await
        .map_err(JavaError::Download)?;
    let target = java_dir(data, major);
    let archive2 = archive.clone();
    let res = tokio::task::spawn_blocking(move || extract_into(&archive2, &target, zip))
        .await
        .map_err(|e| JavaError::Extract(e.to_string()))?;
    let _ = std::fs::remove_file(&archive);
    res.map_err(JavaError::Extract)?;
    managed_exe(data, major).ok_or_else(|| JavaError::Extract("bin/java absent".into()))
}

/// Extrait l'archive dans un dossier temporaire voisin, puis renomme son dossier racine (celui qui
/// contient `bin/java`) en `target`. Chemins confinés (aucune entrée hors du dossier).
pub fn extract_into(archive: &Path, target: &Path, zip: bool) -> Result<(), String> {
    let parent = target.parent().ok_or("dossier")?;
    let tmp = parent.join(format!(".extract-{}", crate::crypto::base32(&crate::crypto::random_bytes::<5>())));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let res = (|| {
        if zip {
            unzip_confined(archive, &tmp)?;
        } else {
            let f = std::fs::File::open(archive).map_err(|e| e.to_string())?;
            let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
            for entry in ar.entries().map_err(|e| e.to_string())? {
                let mut entry = entry.map_err(|e| e.to_string())?;
                // `unpack_in` refuse toute entrée qui sortirait du dossier (`..`, chemin absolu).
                if !entry.unpack_in(&tmp).map_err(|e| e.to_string())? {
                    return Err("entrée hors du dossier refusée".into());
                }
            }
        }
        let top = find_java_root(&tmp).ok_or("bin/java introuvable dans l'archive")?;
        if target.exists() {
            return Ok(());
        }
        std::fs::rename(&top, target).map_err(|e| e.to_string())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// Extrait un zip en refusant toute entrée hors du dossier (`enclosed_name`).
pub fn unzip_confined(archive: &Path, dest: &Path) -> Result<(), String> {
    let f = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let mut z = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| e.to_string())?;
        let shown = e.name().map(|n| n.chars().take(120).collect::<String>()).unwrap_or_default();
        let rel = e.enclosed_name().ok_or_else(|| format!("entrée hors du dossier refusée : {shown}"))?;
        if !crate::paths::is_confined(&rel) {
            return Err(format!("entrée refusée : {shown}"));
        }
        let out = dest.join(&rel);
        if e.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(p) = out.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let mut f = std::fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut e, &mut f).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        if let Some(mode) = e.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode & 0o755));
        }
    }
    Ok(())
}

fn find_java_root(dir: &Path) -> Option<PathBuf> {
    if dir.join("bin").join(exe_name()).is_file() {
        return Some(dir.to_path_buf());
    }
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.join("bin").join(exe_name()).is_file() {
            return Some(p);
        }
        // macOS : <racine>/Contents/Home/bin/java.
        let home = p.join("Contents").join("Home");
        if home.join("bin").join(exe_name()).is_file() {
            return Some(home);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_de_java_selon_le_jeu() {
        // Valeurs lues dans les manifestes Mojang (20/10/2026) : 26.3 → 25, 1.21.11 → 21,
        // 1.20.4 → 17, 1.17 → 16, 1.16.5 → 8.
        assert_eq!(runtime_for(25), 25);
        assert_eq!(runtime_for(21), 21);
        assert_eq!(runtime_for(17), 17);
        assert_eq!(runtime_for(16), 17, "Adoptium n'a pas de JRE 16");
        assert_eq!(runtime_for(8), 8);
        assert_eq!(runtime_for(0), 8);
        assert_eq!(runtime_for(27), 27);
    }

    #[test]
    fn sortie_de_java_version() {
        let t = "openjdk version \"25.0.4.1\" 2026-08-18\nOpenJDK Runtime Environment Temurin-25.0.4.1+1";
        assert_eq!(parse_version_output(t), Some((25, "25.0.4.1".into())));
        assert_eq!(parse_version_output("java version \"1.8.0_402\""), Some((8, "1.8.0_402".into())));
        assert_eq!(parse_version_output("openjdk version \"21\" 2023-09-19"), Some((21, "21".into())));
        assert_eq!(parse_version_output("rien"), None);
    }

    /// Aucun secret du gestionnaire dans l'environnement des enfants : liste blanche seulement.
    #[test]
    fn environnement_minimal_sans_secret() {
        let env = minimal_env(Path::new("tmp"));
        let allowed = [
            "TMP",
            "TEMP",
            "TMPDIR",
            "PATH",
            "LANG",
            "TZ",
            "SystemRoot",
            "SystemDrive",
            "windir",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
        ];
        for (k, _) in &env {
            let k = k.to_string_lossy();
            assert!(allowed.contains(&k.as_ref()), "{k} hors liste blanche");
            assert!(!k.starts_with("RCM_"));
        }
    }

    /// Archive zip hostile (entrée `../`) : refusée, rien n'est écrit hors du dossier.
    #[test]
    fn zip_hostile_refuse() {
        use std::io::Write;
        let d = std::env::temp_dir().join(format!("rcm-zip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("out")).unwrap();
        let zp = d.join("a.zip");
        {
            let f = std::fs::File::create(&zp).unwrap();
            let mut w = zip::ZipWriter::new(f);
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("ok/bin/java.exe", o).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("../evil.txt", o).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        assert!(unzip_confined(&zp, &d.join("out")).is_err());
        assert!(!d.join("evil.txt").exists());
    }
}
