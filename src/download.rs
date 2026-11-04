//! Téléchargements depuis les sources officielles seulement : HTTPS, hôtes d'une liste fermée (y
//! compris à chaque redirection), délais (connexion, inactivité, total), taille bornée (annoncée
//! ET lue), réponses lues jusqu'au bout avant analyse, somme de contrôle vérifiée au fil de
//! l'eau, fichier écrit à côté (`.part`) puis renommé, jamais laissé à moitié.

use ring::digest;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Hôtes autorisés (comparaison exacte du nom, port 443 seulement).
pub const ALLOWED_HOSTS: &[&str] = &[
    // Mojang : manifeste des versions, serveurs, ressources (fichiers de langue).
    "piston-meta.mojang.com",
    "piston-data.mojang.com",
    "launchermeta.mojang.com",
    "launcher.mojang.com",
    "resources.download.minecraft.net",
    // PaperMC (Paper, Folia) : API fill v3 et ses fichiers.
    "fill.papermc.io",
    "fill-data.papermc.io",
    // Purpur.
    "api.purpurmc.org",
    // Fabric et Quilt : métadonnées et dépôts Maven.
    "meta.fabricmc.net",
    "maven.fabricmc.net",
    "meta.quiltmc.org",
    "maven.quiltmc.org",
    // Java Temurin : API Adoptium, archives publiées sur GitHub (et leur redirection).
    "api.adoptium.net",
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    // Profils des joueurs (pseudo → UUID officiel), onglet « Joueurs ».
    "api.mojang.com",
];

/// Taille maximale d'une réponse JSON ou texte.
pub const MAX_JSON: u64 = 16 * 1024 * 1024;
/// Taille maximale d'un fichier téléchargé (jar, archive de Java).
pub const MAX_FILE: u64 = 512 * 1024 * 1024;
/// Délai de connexion, d'inactivité (entre deux morceaux) et total d'une requête courte.
const CONNECT: Duration = Duration::from_secs(15);
const IDLE: Duration = Duration::from_secs(60);
const SHORT_TOTAL: Duration = Duration::from_secs(60);
/// Délai total d'un gros fichier (≈ 100 Mo à 150 kio/s).
const FILE_TOTAL: Duration = Duration::from_secs(20 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlError {
    /// Adresse refusée (schéma, hôte, port, identifiants).
    Host(String),
    Status(u16),
    TooLarge,
    /// Taille différente de celle annoncée.
    Size {
        expected: u64,
        got: u64,
    },
    Checksum,
    Timeout,
    Network(String),
    Parse(String),
    Io(String),
}

impl std::fmt::Display for DlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlError::Host(u) => write!(f, "adresse refusée : {u}"),
            DlError::Status(s) => write!(f, "réponse HTTP {s}"),
            DlError::TooLarge => f.write_str("réponse trop grande"),
            DlError::Size { expected, got } => write!(f, "taille {got} au lieu de {expected}"),
            DlError::Checksum => f.write_str("somme de contrôle différente"),
            DlError::Timeout => f.write_str("délai dépassé"),
            DlError::Network(e) => write!(f, "réseau : {e}"),
            DlError::Parse(e) => write!(f, "réponse illisible : {e}"),
            DlError::Io(e) => write!(f, "disque : {e}"),
        }
    }
}

impl DlError {
    pub fn code(&self) -> rc_manager_shared::ErrorCode {
        match self {
            DlError::Checksum | DlError::Size { .. } => rc_manager_shared::ErrorCode::ChecksumMismatch,
            _ => rc_manager_shared::ErrorCode::DownloadFailed,
        }
    }
}

/// Adresse autorisée ? HTTPS, hôte de la liste (nom exact), port par défaut, sans identifiants.
pub fn url_allowed(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && matches!(url.domain(), Some(h) if ALLOWED_HOSTS.contains(&h))
}

fn check(url: &str) -> Result<reqwest::Url, DlError> {
    let u = reqwest::Url::parse(url).map_err(|_| DlError::Host(url.chars().take(120).collect()))?;
    if url_allowed(&u) { Ok(u) } else { Err(DlError::Host(url.chars().take(120).collect())) }
}

/// Somme de contrôle attendue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
    Sha1(Vec<u8>),
    Sha256(Vec<u8>),
    Sha512(Vec<u8>),
    /// Purpur ne publie que du MD5 (intégrité seulement ; l'authenticité vient du HTTPS).
    Md5(Vec<u8>),
}

impl Checksum {
    fn hex(s: &str, len: usize) -> Option<Vec<u8>> {
        let s = s.trim();
        if s.len() != len * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        (0..len).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
    }
    pub fn sha1(s: &str) -> Option<Checksum> {
        Self::hex(s, 20).map(Checksum::Sha1)
    }
    pub fn sha256(s: &str) -> Option<Checksum> {
        Self::hex(s, 32).map(Checksum::Sha256)
    }
    pub fn sha512(s: &str) -> Option<Checksum> {
        Self::hex(s, 64).map(Checksum::Sha512)
    }
    pub fn md5(s: &str) -> Option<Checksum> {
        Self::hex(s, 16).map(Checksum::Md5)
    }
    fn hasher(&self) -> Hasher {
        match self {
            Checksum::Sha1(_) => Hasher::Ring(digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)),
            Checksum::Sha256(_) => Hasher::Ring(digest::Context::new(&digest::SHA256)),
            Checksum::Sha512(_) => Hasher::Ring(digest::Context::new(&digest::SHA512)),
            Checksum::Md5(_) => Hasher::Md5(<md5::Md5 as md5::Digest>::new()),
        }
    }
    fn expected(&self) -> &[u8] {
        match self {
            Checksum::Sha1(v) | Checksum::Sha256(v) | Checksum::Sha512(v) | Checksum::Md5(v) => v,
        }
    }
}

enum Hasher {
    Ring(digest::Context),
    Md5(md5::Md5),
}

impl Hasher {
    fn update(&mut self, b: &[u8]) {
        match self {
            Hasher::Ring(c) => c.update(b),
            Hasher::Md5(m) => md5::Digest::update(m, b),
        }
    }
    fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Ring(c) => c.finish().as_ref().to_vec(),
            Hasher::Md5(m) => md5::Digest::finalize(m).to_vec(),
        }
    }
}

/// Ce qu'on attend d'un fichier.
#[derive(Debug, Clone)]
pub struct Expect {
    pub checksum: Checksum,
    /// Taille annoncée par la source (vérifiée), sinon seulement bornée par [`MAX_FILE`].
    pub size: Option<u64>,
}

/// Fichier en cours d'écriture : somme calculée au fil de l'eau, taille bornée, supprimé s'il
/// n'est pas mené au bout (`Drop`).
pub struct Sink {
    file: Option<std::fs::File>,
    part: PathBuf,
    dest: PathBuf,
    hasher: Option<Hasher>,
    expect: Expect,
    written: u64,
    max: u64,
}

impl Sink {
    pub fn create(dest: &Path, expect: Expect) -> Result<Sink, DlError> {
        let dir = dest.parent().ok_or_else(|| DlError::Io("dossier".into()))?;
        std::fs::create_dir_all(dir).map_err(|e| DlError::Io(e.to_string()))?;
        let name = dest.file_name().ok_or_else(|| DlError::Io("nom".into()))?.to_string_lossy();
        let part = dir.join(format!(".{name}.{}.part", crate::crypto::base32(&crate::crypto::random_bytes::<5>())));
        let file = std::fs::File::create(&part).map_err(|e| DlError::Io(e.to_string()))?;
        let max = expect.size.unwrap_or(MAX_FILE).min(MAX_FILE);
        Ok(Sink {
            file: Some(file),
            part,
            dest: dest.to_path_buf(),
            hasher: Some(expect.checksum.hasher()),
            expect,
            written: 0,
            max,
        })
    }

    pub fn push(&mut self, b: &[u8]) -> Result<(), DlError> {
        use std::io::Write;
        self.written += b.len() as u64;
        if self.written > self.max {
            return Err(match self.expect.size {
                Some(expected) => DlError::Size { expected, got: self.written },
                None => DlError::TooLarge,
            });
        }
        if let Some(h) = self.hasher.as_mut() {
            h.update(b);
        }
        self.file
            .as_mut()
            .ok_or_else(|| DlError::Io("fermé".into()))?
            .write_all(b)
            .map_err(|e| DlError::Io(e.to_string()))
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Vérifie taille et somme, puis fsync, renomme, fsync du dossier.
    pub fn finish(mut self) -> Result<(), DlError> {
        if let Some(expected) = self.expect.size
            && self.written != expected
        {
            return Err(DlError::Size { expected, got: self.written });
        }
        let got = self.hasher.take().map(Hasher::finish).unwrap_or_default();
        if !crate::crypto::ct_eq(&got, self.expect.checksum.expected()) {
            return Err(DlError::Checksum);
        }
        let f = self.file.take().ok_or_else(|| DlError::Io("fermé".into()))?;
        f.sync_all().map_err(|e| DlError::Io(e.to_string()))?;
        drop(f);
        std::fs::rename(&self.part, &self.dest).map_err(|e| DlError::Io(e.to_string()))?;
        crate::fsutil::sync_dir(self.dest.parent().unwrap_or_else(|| Path::new(".")));
        Ok(())
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        drop(self.file.take());
        if self.part.exists() {
            let _ = std::fs::remove_file(&self.part);
        }
    }
}

/// Client HTTP des téléchargements (un seul, partagé).
#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
}

impl Http {
    pub fn new() -> Http {
        // rustls sur ring (rien de natif à compiler) ; le fournisseur se pose une fois.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let policy = reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("trop de redirections")
            } else if url_allowed(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("redirection vers un hôte non autorisé")
            }
        });
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(policy)
            .connect_timeout(CONNECT)
            .read_timeout(IDLE)
            .user_agent(concat!("rustcraft-manager/", env!("CARGO_PKG_VERSION"), " (+https://github.com/neotoxicfr)"))
            .no_proxy()
            .build()
            .expect("client HTTP");
        Http { client }
    }

    async fn send(&self, url: &str) -> Result<reqwest::Response, DlError> {
        let u = check(url)?;
        let res = self.client.get(u).send().await.map_err(net)?;
        if !url_allowed(res.url()) {
            return Err(DlError::Host(res.url().to_string()));
        }
        if !res.status().is_success() {
            return Err(DlError::Status(res.status().as_u16()));
        }
        Ok(res)
    }

    /// Corps entier (borné), lu jusqu'au bout avant toute analyse.
    pub async fn bytes(&self, url: &str, max: u64) -> Result<Vec<u8>, DlError> {
        let fut = async {
            let mut res = self.send(url).await?;
            if res.content_length().is_some_and(|n| n > max) {
                return Err(DlError::TooLarge);
            }
            let mut out = Vec::new();
            while let Some(chunk) = res.chunk().await.map_err(net)? {
                if out.len() as u64 + chunk.len() as u64 > max {
                    return Err(DlError::TooLarge);
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        };
        tokio::time::timeout(SHORT_TOTAL, fut).await.map_err(|_| DlError::Timeout)?
    }

    /// JSON (borné à [`MAX_JSON`]).
    pub async fn json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, DlError> {
        let b = self.bytes(url, MAX_JSON).await?;
        serde_json::from_slice(&b).map_err(|e| DlError::Parse(e.to_string()))
    }

    /// Texte court (fichier de somme d'un dépôt Maven).
    pub async fn text(&self, url: &str, max: u64) -> Result<String, DlError> {
        let b = self.bytes(url, max).await?;
        String::from_utf8(b).map_err(|e| DlError::Parse(e.to_string()))
    }

    /// Télécharge vers `dest` (remplacé seulement si tout est vérifié). `progress` reçoit
    /// (octets reçus, total annoncé).
    pub async fn file(
        &self,
        url: &str,
        dest: &Path,
        expect: Expect,
        progress: &(dyn Fn(u64, Option<u64>) + Send + Sync),
    ) -> Result<(), DlError> {
        let total = expect.size;
        let fut = async {
            let mut res = self.send(url).await?;
            let announced = res.content_length();
            if let (Some(a), Some(e)) = (announced, expect.size)
                && a != e
            {
                return Err(DlError::Size { expected: e, got: a });
            }
            if announced.is_some_and(|a| a > MAX_FILE) {
                return Err(DlError::TooLarge);
            }
            let total = total.or(announced);
            let mut sink = Sink::create(dest, expect)?;
            let mut last = 0u64;
            while let Some(chunk) = res.chunk().await.map_err(net)? {
                sink.push(&chunk)?;
                // Progression toutes les 256 kio au plus (pas une notification par paquet).
                if sink.written() - last >= 256 * 1024 {
                    last = sink.written();
                    progress(last, total);
                }
            }
            progress(sink.written(), total);
            tokio::task::spawn_blocking(move || sink.finish()).await.map_err(|e| DlError::Io(e.to_string()))?
        };
        tokio::time::timeout(FILE_TOTAL, fut).await.map_err(|_| DlError::Timeout)?
    }
}

impl Default for Http {
    fn default() -> Self {
        Self::new()
    }
}

fn net(e: reqwest::Error) -> DlError {
    if e.is_timeout() {
        DlError::Timeout
    } else {
        // Sans l'adresse complète (pas de jeton signé de GitHub dans les journaux).
        DlError::Network(e.without_url().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(u: &str) -> bool {
        reqwest::Url::parse(u).map(|u| url_allowed(&u)).unwrap_or(false)
    }

    /// Adresses hostiles refusées : autre schéma, hôte voisin ou suffixé, port, identifiants,
    /// adresse IP, hôte en majuscules normalisé par l'analyseur (accepté car identique).
    #[test]
    fn hotes_hostiles_refuses() {
        assert!(allowed("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"));
        assert!(allowed("https://PISTON-DATA.mojang.com/v1/objects/x/server.jar"));
        for bad in [
            "http://piston-meta.mojang.com/x",
            "https://piston-meta.mojang.com.evil.example/x",
            "https://evil.example/piston-meta.mojang.com",
            "https://mojang.com/x",
            "https://x.piston-meta.mojang.com/x",
            "https://piston-meta.mojang.com:8443/x",
            "https://user:pw@piston-meta.mojang.com/x",
            "https://user@piston-meta.mojang.com/x",
            "https://93.184.216.34/x",
            "https://[::1]/x",
            "file:///etc/passwd",
            "ftp://maven.fabricmc.net/x",
            "https://evil.example\\@piston-meta.mojang.com/x",
            "https://piston-meta.mojang.com%2eevil.example/x",
        ] {
            assert!(!allowed(bad), "{bad}");
        }
        assert!(matches!(check("pas une adresse"), Err(DlError::Host(_))));
    }

    #[test]
    fn sommes_lues_en_hexadecimal() {
        assert!(Checksum::sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709").is_some());
        assert!(Checksum::sha1("da39a3ee5e6b4b0d3255bfef95601890afd8070").is_none());
        assert!(Checksum::sha256(&"g".repeat(64)).is_none());
        assert!(Checksum::md5("d41d8cd98f00b204e9800998ecf8427e").is_some());
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rcm-dl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn leftovers(d: &Path) -> Vec<String> {
        std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()
    }

    /// Somme et taille vérifiées ; un échec ne laisse ni le fichier ni le temporaire.
    #[test]
    fn somme_taille_et_aucun_reste() {
        let d = tmp("sink");
        let dest = d.join("server.jar");
        // SHA-1 de « abc ».
        let sha1 = Checksum::sha1("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        let mut s = Sink::create(&dest, Expect { checksum: sha1.clone(), size: Some(3) }).unwrap();
        s.push(b"ab").unwrap();
        s.push(b"c").unwrap();
        s.finish().unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        assert_eq!(leftovers(&d), vec!["server.jar"]);
        std::fs::remove_file(&dest).unwrap();

        // Contenu altéré : somme refusée, rien ne reste.
        let mut s = Sink::create(&dest, Expect { checksum: sha1.clone(), size: Some(3) }).unwrap();
        s.push(b"abd").unwrap();
        assert_eq!(s.finish(), Err(DlError::Checksum));
        assert!(leftovers(&d).is_empty(), "{:?}", leftovers(&d));

        // Plus long qu'annoncé : arrêt dès le dépassement.
        let mut s = Sink::create(&dest, Expect { checksum: sha1.clone(), size: Some(3) }).unwrap();
        assert!(matches!(s.push(b"abcd"), Err(DlError::Size { .. })));
        drop(s);
        // Plus court qu'annoncé.
        let mut s = Sink::create(&dest, Expect { checksum: sha1, size: Some(4) }).unwrap();
        s.push(b"abc").unwrap();
        assert!(matches!(s.finish(), Err(DlError::Size { .. })));
        assert!(leftovers(&d).is_empty(), "{:?}", leftovers(&d));

        // Autres algorithmes : SHA-256, SHA-512, MD5 de « abc ».
        for c in [
            Checksum::sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap(),
            Checksum::sha512(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            )
            .unwrap(),
            Checksum::md5("900150983cd24fb0d6963f7d28e17f72").unwrap(),
        ] {
            let mut s = Sink::create(&dest, Expect { checksum: c, size: None }).unwrap();
            s.push(b"abc").unwrap();
            s.finish().unwrap();
            std::fs::remove_file(&dest).unwrap();
        }
    }
}
