//! Logiciels serveur : versions proposées et installation depuis les API officielles.
//!
//! | Logiciel | Source | Somme vérifiée |
//! |---|---|---|
//! | Vanilla | manifeste Mojang `piston-meta` → `piston-data` | SHA-1 + taille du manifeste de version (lui-même vérifié par le SHA-1 du manifeste) |
//! | Paper, Folia | API PaperMC fill v3 | SHA-256 + taille |
//! | Purpur | API Purpur v2 | MD5 (seule somme publiée) |
//! | Fabric, Quilt | serveur Mojang + profil `meta` + bibliothèques Maven | sommes du profil, sinon fichier `.sha256` (`.sha1`) du dépôt |
//!
//! Java : `javaVersion.majorVersion` du manifeste Mojang (et le minimum de PaperMC s'il est plus
//! haut), servi par [`crate::java::runtime_for`].

use crate::download::{Checksum, DlError, Expect, Http};
use crate::paths::{maven_path, version_valid};
use rc_manager_shared::{GameVersion, Software};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MOJANG_MANIFEST: &str = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json";
/// Les listes de versions sont gardées 10 minutes.
const CACHE_TTL: Duration = Duration::from_secs(600);

/// Lancement d'un serveur installé (enregistré en base, JSON).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Launch {
    /// `java -jar <jar> nogui`.
    Jar { jar: String },
    /// Fabric, Quilt : `java -D<prop>=server.jar -cp <bibliothèques> <classe> nogui`.
    Knot { main_class: String, classpath: Vec<String>, game_jar_prop: String },
}

impl Launch {
    /// Arguments après les options de la JVM. Chemins relatifs au dossier du serveur, déjà
    /// validés à l'installation.
    pub fn args(&self) -> Vec<String> {
        match self {
            Launch::Jar { jar } => vec!["-jar".into(), jar.clone(), "nogui".into()],
            Launch::Knot { main_class, classpath, game_jar_prop } => {
                let sep = if cfg!(windows) { ";" } else { ":" };
                vec![
                    format!("-D{game_jar_prop}=server.jar"),
                    "-cp".into(),
                    classpath.join(sep),
                    main_class.clone(),
                    "nogui".into(),
                ]
            }
        }
    }
}

#[derive(Deserialize, Clone)]
struct Manifest {
    versions: Vec<ManifestEntry>,
}
#[derive(Deserialize, Clone)]
struct ManifestEntry {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    url: String,
    sha1: String,
}
#[derive(Deserialize)]
struct VersionJson {
    downloads: Option<VersionDownloads>,
    #[serde(rename = "javaVersion")]
    java_version: Option<JavaVersion>,
    #[serde(rename = "assetIndex")]
    asset_index: Option<AssetIndexRef>,
}
#[derive(Deserialize)]
struct VersionDownloads {
    server: Option<FileRef>,
}
#[derive(Deserialize)]
struct FileRef {
    sha1: String,
    size: u64,
    url: String,
}
#[derive(Deserialize)]
struct JavaVersion {
    #[serde(rename = "majorVersion")]
    major: u32,
}
#[derive(Deserialize)]
pub struct AssetIndexRef {
    pub sha1: String,
    pub url: String,
}

/// Catalogue des versions, avec cache.
pub struct Catalog {
    pub http: Http,
    manifest: Mutex<Option<(Instant, Arc<Manifest>)>>,
    lists: Mutex<HashMap<Software, CachedList>>,
}

/// Liste de versions et instant de sa lecture.
type CachedList = (Instant, Arc<Vec<GameVersion>>);

/// Résultat d'une installation.
#[derive(Debug, Clone)]
pub struct Installed {
    pub launch: Launch,
    pub java_major: u32,
    /// Construction ou version du chargeur (Paper, Purpur, Fabric, Quilt).
    pub build: Option<String>,
}

/// Erreur d'installation.
#[derive(Debug)]
pub enum InstallError {
    UnknownVersion,
    Download(DlError),
    Io(String),
}

impl From<DlError> for InstallError {
    fn from(e: DlError) -> Self {
        InstallError::Download(e)
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::UnknownVersion => f.write_str("version inconnue"),
            InstallError::Download(e) => write!(f, "{e}"),
            InstallError::Io(e) => write!(f, "disque : {e}"),
        }
    }
}

impl InstallError {
    pub fn code(&self) -> rc_manager_shared::ErrorCode {
        match self {
            InstallError::UnknownVersion => rc_manager_shared::ErrorCode::InvalidVersion,
            InstallError::Download(e) => e.code(),
            InstallError::Io(_) => rc_manager_shared::ErrorCode::Internal,
        }
    }
}

/// Étapes signalées pendant l'installation : (étape, octets reçus, total).
pub type Progress<'a> = dyn Fn(rc_manager_shared::OpStep, u64, Option<u64>) + Send + Sync + 'a;

impl Catalog {
    pub fn new(http: Http) -> Catalog {
        Catalog { http, manifest: Mutex::new(None), lists: Mutex::new(HashMap::new()) }
    }

    async fn manifest(&self) -> Result<Arc<Manifest>, DlError> {
        if let Some((t, m)) = self.manifest.lock().unwrap_or_else(|p| p.into_inner()).as_ref()
            && t.elapsed() < CACHE_TTL
        {
            return Ok(m.clone());
        }
        let m: Arc<Manifest> = Arc::new(self.http.json(MOJANG_MANIFEST).await?);
        *self.manifest.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), m.clone()));
        Ok(m)
    }

    /// Manifeste d'une version Mojang, vérifié par le SHA-1 du manifeste général.
    async fn version_json(&self, version: &str) -> Result<VersionJson, InstallError> {
        let m = self.manifest().await?;
        let e = m.versions.iter().find(|v| v.id == version).ok_or(InstallError::UnknownVersion)?;
        let bytes = self.http.bytes(&e.url, crate::download::MAX_JSON).await?;
        let want = Checksum::sha1(&e.sha1).ok_or(InstallError::UnknownVersion)?;
        let got = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &bytes);
        if Checksum::Sha1(got.as_ref().to_vec()) != want {
            return Err(InstallError::Download(DlError::Checksum));
        }
        serde_json::from_slice(&bytes).map_err(|e| InstallError::Download(DlError::Parse(e.to_string())))
    }

    /// Index des ressources d'une version (fichiers de langue).
    pub async fn asset_index(&self, version: &str) -> Result<AssetIndexRef, InstallError> {
        self.version_json(version).await?.asset_index.ok_or(InstallError::UnknownVersion)
    }

    /// Versions proposées pour un logiciel (les plus récentes d'abord).
    pub async fn versions(&self, sw: Software) -> Result<Arc<Vec<GameVersion>>, DlError> {
        if let Some((t, l)) = self.lists.lock().unwrap_or_else(|p| p.into_inner()).get(&sw)
            && t.elapsed() < CACHE_TTL
        {
            return Ok(l.clone());
        }
        let list = match sw {
            Software::Vanilla => {
                let m = self.manifest().await?;
                m.versions
                    .iter()
                    .filter(|v| v.kind == "release")
                    .map(|v| GameVersion { id: v.id.clone(), stable: true })
                    .collect()
            }
            Software::Paper | Software::Folia => {
                #[derive(Deserialize)]
                struct P {
                    versions: serde_json::Map<String, serde_json::Value>,
                }
                let p: P = self.http.json(&format!("https://fill.papermc.io/v3/projects/{}", sw.code())).await?;
                // Groupes déjà du plus récent au plus ancien (ordre du JSON gardé par serde_json ?
                // non garanti : on trie par numéro de version).
                let mut ids: Vec<String> = p
                    .versions
                    .values()
                    .filter_map(|v| v.as_array())
                    .flatten()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                sort_versions_desc(&mut ids);
                ids.into_iter().map(|id| GameVersion { stable: !id.contains('-'), id }).collect()
            }
            Software::Purpur => {
                #[derive(Deserialize)]
                struct P {
                    versions: Vec<String>,
                }
                let p: P = self.http.json("https://api.purpurmc.org/v2/purpur").await?;
                let mut ids = p.versions;
                sort_versions_desc(&mut ids);
                ids.into_iter().map(|id| GameVersion { stable: true, id }).collect()
            }
            Software::Fabric | Software::Quilt => {
                #[derive(Deserialize)]
                struct G {
                    version: String,
                    stable: bool,
                }
                let url = if sw == Software::Fabric {
                    "https://meta.fabricmc.net/v2/versions/game"
                } else {
                    "https://meta.quiltmc.org/v3/versions/game"
                };
                let g: Vec<G> = self.http.json(url).await?;
                g.into_iter().filter(|v| v.stable).map(|v| GameVersion { id: v.version, stable: true }).collect()
            }
        };
        let list: Vec<GameVersion> = list;
        let list: Vec<GameVersion> = list.into_iter().filter(|v| version_valid(&v.id)).collect();
        let arc = Arc::new(list);
        self.lists.lock().unwrap_or_else(|p| p.into_inner()).insert(sw, (Instant::now(), arc.clone()));
        Ok(arc)
    }

    /// Liste de versions posée d'avance (tests sans réseau).
    pub fn preload(&self, sw: Software, list: Vec<GameVersion>) {
        self.lists.lock().unwrap_or_else(|p| p.into_inner()).insert(sw, (Instant::now(), Arc::new(list)));
    }

    /// Version de Java demandée par le jeu (manifeste Mojang).
    pub async fn java_major(&self, version: &str) -> Result<u32, InstallError> {
        Ok(self.version_json(version).await?.java_version.map_or(8, |j| j.major))
    }

    /// Télécharge et vérifie tout ce qu'il faut dans `dir` (dossier du serveur).
    pub async fn install(
        &self,
        sw: Software,
        version: &str,
        dir: &Path,
        progress: &Progress<'_>,
    ) -> Result<Installed, InstallError> {
        use rc_manager_shared::OpStep;
        if !version_valid(version) {
            return Err(InstallError::UnknownVersion);
        }
        progress(OpStep::Resolve, 0, None);
        let vj = self.version_json(version).await?;
        let mut java_major = vj.java_version.as_ref().map_or(8, |j| j.major);
        let server_jar = dir.join("server.jar");
        let dl_progress = |step: OpStep| move |d: u64, t: Option<u64>| progress(step, d, t);
        let vanilla = |vj: &VersionJson| -> Result<(String, Expect), InstallError> {
            let s = vj.downloads.as_ref().and_then(|d| d.server.as_ref()).ok_or(InstallError::UnknownVersion)?;
            let sum = Checksum::sha1(&s.sha1).ok_or(InstallError::UnknownVersion)?;
            Ok((s.url.clone(), Expect { checksum: sum, size: Some(s.size) }))
        };
        let (launch, build) = match sw {
            Software::Vanilla => {
                let (url, exp) = vanilla(&vj)?;
                self.http.file(&url, &server_jar, exp, &dl_progress(OpStep::DownloadServer)).await?;
                (Launch::Jar { jar: "server.jar".into() }, None)
            }
            Software::Paper | Software::Folia => {
                #[derive(Deserialize)]
                struct Build {
                    id: u64,
                    downloads: HashMap<String, Dl>,
                }
                #[derive(Deserialize)]
                struct Dl {
                    checksums: HashMap<String, String>,
                    size: u64,
                    url: String,
                }
                #[derive(Deserialize)]
                struct V {
                    version: VInner,
                }
                #[derive(Deserialize)]
                struct VInner {
                    java: Option<VJava>,
                }
                #[derive(Deserialize)]
                struct VJava {
                    version: VJavaV,
                }
                #[derive(Deserialize)]
                struct VJavaV {
                    minimum: u32,
                }
                let base = format!("https://fill.papermc.io/v3/projects/{}/versions/{version}", sw.code());
                if let Ok(v) = self.http.json::<V>(&base).await
                    && let Some(j) = v.version.java
                {
                    java_major = java_major.max(j.version.minimum);
                }
                let b: Build = self.http.json(&format!("{base}/builds/latest")).await.map_err(|e| match e {
                    DlError::Status(404) => InstallError::UnknownVersion,
                    e => e.into(),
                })?;
                let d = b.downloads.get("server:default").ok_or(InstallError::UnknownVersion)?;
                let sum =
                    d.checksums.get("sha256").and_then(|s| Checksum::sha256(s)).ok_or(InstallError::UnknownVersion)?;
                self.http
                    .file(
                        &d.url,
                        &server_jar,
                        Expect { checksum: sum, size: Some(d.size) },
                        &dl_progress(OpStep::DownloadServer),
                    )
                    .await?;
                (Launch::Jar { jar: "server.jar".into() }, Some(b.id.to_string()))
            }
            Software::Purpur => {
                #[derive(Deserialize)]
                struct B {
                    build: String,
                    md5: String,
                }
                let b: B =
                    self.http.json(&format!("https://api.purpurmc.org/v2/purpur/{version}/latest")).await.map_err(
                        |e| match e {
                            DlError::Status(404) => InstallError::UnknownVersion,
                            e => e.into(),
                        },
                    )?;
                if !b.build.bytes().all(|c| c.is_ascii_digit()) || b.build.is_empty() || b.build.len() > 12 {
                    return Err(InstallError::UnknownVersion);
                }
                let sum = Checksum::md5(&b.md5).ok_or(InstallError::UnknownVersion)?;
                let url = format!("https://api.purpurmc.org/v2/purpur/{version}/{}/download", b.build);
                self.http
                    .file(&url, &server_jar, Expect { checksum: sum, size: None }, &dl_progress(OpStep::DownloadServer))
                    .await?;
                (Launch::Jar { jar: "server.jar".into() }, Some(b.build))
            }
            Software::Fabric | Software::Quilt => {
                let (url, exp) = vanilla(&vj)?;
                self.http.file(&url, &server_jar, exp, &dl_progress(OpStep::DownloadServer)).await?;
                let fabric = sw == Software::Fabric;
                let loader = self.latest_loader(fabric).await?;
                let profile_url = if fabric {
                    format!("https://meta.fabricmc.net/v2/versions/loader/{version}/{loader}/server/json")
                } else {
                    format!("https://meta.quiltmc.org/v3/versions/loader/{version}/{loader}/server/json")
                };
                let profile: Profile = self.http.json(&profile_url).await.map_err(|e| match e {
                    DlError::Status(400 | 404) => InstallError::UnknownVersion,
                    e => e.into(),
                })?;
                let mut classpath = Vec::new();
                let n = profile.libraries.len() as u64;
                for (i, lib) in profile.libraries.iter().enumerate() {
                    progress(OpStep::DownloadLibraries, i as u64, Some(n));
                    let rel = maven_path(&lib.name).ok_or(InstallError::UnknownVersion)?;
                    let url = format!("{}{}", lib.url.trim_end_matches('/'), maven_url_path(&rel));
                    let dest = dir.join("libraries").join(&rel);
                    let checksum = match lib.checksum() {
                        Some(c) => c,
                        None => self.maven_sidecar(&url).await?,
                    };
                    if !file_matches(&dest, &checksum) {
                        self.http.file(&url, &dest, Expect { checksum, size: lib.size }, &|_, _| {}).await?;
                    }
                    let rel_str = Path::new("libraries").join(&rel).to_string_lossy().replace('\\', "/");
                    classpath.push(rel_str);
                }
                progress(OpStep::DownloadLibraries, n, Some(n));
                if !valid_class_name(&profile.main_class) {
                    return Err(InstallError::UnknownVersion);
                }
                let prop = if fabric { "fabric.gameJarPath" } else { "loader.gameJarPath" };
                (Launch::Knot { main_class: profile.main_class, classpath, game_jar_prop: prop.into() }, Some(loader))
            }
        };
        Ok(Installed { launch, java_major, build })
    }

    async fn latest_loader(&self, fabric: bool) -> Result<String, InstallError> {
        #[derive(Deserialize)]
        struct L {
            version: String,
            #[serde(default)]
            stable: Option<bool>,
        }
        let url = if fabric {
            "https://meta.fabricmc.net/v2/versions/loader"
        } else {
            "https://meta.quiltmc.org/v3/versions/loader"
        };
        let list: Vec<L> = self.http.json(url).await?;
        // Fabric : drapeau `stable` ; Quilt : pas de drapeau, une version sans suffixe (-beta) est stable.
        let pick = list
            .iter()
            .find(|l| l.stable.unwrap_or_else(|| !l.version.contains('-')))
            .or_else(|| list.first())
            .ok_or(InstallError::UnknownVersion)?;
        if !version_valid(&pick.version) {
            return Err(InstallError::UnknownVersion);
        }
        Ok(pick.version.clone())
    }

    /// Somme publiée à côté de l'artefact dans le dépôt Maven (`.sha256`, sinon `.sha1`).
    async fn maven_sidecar(&self, url: &str) -> Result<Checksum, InstallError> {
        if let Ok(t) = self.http.text(&format!("{url}.sha256"), 1024).await
            && let Some(c) = t.split_whitespace().next().and_then(Checksum::sha256)
        {
            return Ok(c);
        }
        let t = self.http.text(&format!("{url}.sha1"), 1024).await?;
        t.split_whitespace().next().and_then(Checksum::sha1).ok_or(InstallError::Download(DlError::Checksum))
    }
}

#[derive(Deserialize)]
struct Profile {
    #[serde(rename = "mainClass")]
    main_class: String,
    libraries: Vec<Library>,
}

#[derive(Deserialize)]
struct Library {
    name: String,
    url: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    sha1: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

impl Library {
    fn checksum(&self) -> Option<Checksum> {
        self.sha256.as_deref().and_then(Checksum::sha256).or_else(|| self.sha1.as_deref().and_then(Checksum::sha1))
    }
}

/// Chemin d'URL d'un artefact (séparateurs `/`), à partir d'un chemin déjà validé.
fn maven_url_path(rel: &Path) -> String {
    let mut s = String::new();
    for c in rel.components() {
        s.push('/');
        s.push_str(&c.as_os_str().to_string_lossy());
    }
    s
}

/// Nom de classe Java plausible (`net.fabricmc.loader.impl.launch.knot.KnotServer`).
fn valid_class_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$'))
}

/// Fichier déjà présent avec la bonne somme (reprise d'une installation interrompue).
fn file_matches(path: &Path, c: &Checksum) -> bool {
    let Ok(bytes) = crate::fsutil::read_bounded(path, crate::download::MAX_FILE) else { return false };
    let got = match c {
        Checksum::Sha1(_) => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &bytes).as_ref().to_vec(),
        Checksum::Sha256(_) => ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref().to_vec(),
        Checksum::Sha512(_) => ring::digest::digest(&ring::digest::SHA512, &bytes).as_ref().to_vec(),
        Checksum::Md5(_) => return false,
    };
    let want = match c {
        Checksum::Sha1(v) | Checksum::Sha256(v) | Checksum::Sha512(v) | Checksum::Md5(v) => v,
    };
    crate::crypto::ct_eq(&got, want)
}

/// Tri décroissant de versions `a.b.c[-suffixe]` (numérique par segment ; une version sans
/// suffixe passe avant ses pré-versions).
pub fn sort_versions_desc(v: &mut [String]) {
    fn key(s: &str) -> (Vec<u64>, bool, String) {
        let (base, suffix) = match s.split_once('-') {
            Some((b, x)) => (b, x.to_string()),
            None => (s, String::new()),
        };
        let nums = base.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect();
        (nums, suffix.is_empty(), suffix)
    }
    v.sort_by_key(|s| std::cmp::Reverse(key(s)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tri_des_versions() {
        let mut v: Vec<String> = ["1.21.9", "1.21.11", "26.3-rc-3", "26.3", "1.21.10", "26.1.2", "1.8"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        sort_versions_desc(&mut v);
        assert_eq!(v, ["26.3", "26.3-rc-3", "26.1.2", "1.21.11", "1.21.10", "1.21.9", "1.8"]);
    }

    #[test]
    fn arguments_de_lancement() {
        let j = Launch::Jar { jar: "server.jar".into() };
        assert_eq!(j.args(), ["-jar", "server.jar", "nogui"]);
        let k = Launch::Knot {
            main_class: "net.fabricmc.loader.impl.launch.knot.KnotServer".into(),
            classpath: vec!["libraries/a.jar".into(), "libraries/b.jar".into()],
            game_jar_prop: "fabric.gameJarPath".into(),
        };
        let a = k.args();
        assert_eq!(a[0], "-Dfabric.gameJarPath=server.jar");
        assert!(a[2].contains("libraries/a.jar") && a[2].contains("libraries/b.jar"));
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(serde_json::from_str::<Launch>(&json).unwrap(), k);
        assert!(valid_class_name("net.fabricmc.loader.impl.launch.knot.KnotServer"));
        assert!(!valid_class_name("a;b"));
        assert!(!valid_class_name("a..b"));
        assert_eq!(maven_url_path(&maven_path("a.b:c:1").unwrap()), "/a/b/c/1/c-1.jar");
    }
}
