//! Configuration : valeurs par défaut < fichier TOML < variables d'environnement < arguments.
//!
//! Fichier : `--config <chemin>`, sinon `RCM_CONFIG`, sinon `<dossier de données>/manager.toml`
//! s'il existe. Le dossier de données vient de `--data-dir`, `RCM_DATA_DIR`, puis du fichier,
//! puis du défaut (`%LOCALAPPDATA%\rustcraft-manager` sous Windows, `/data` ailleurs).
//!
//! Échec fermé : toute valeur invalide ou hors bornes arrête le démarrage avec un message qui
//! nomme la variable (ou la clé du fichier) ; booléens stricts (`true`/`false`) ; aucune valeur
//! ramenée en silence dans les bornes. Les secrets (`RCM_ENCRYPTION_KEY`) se lisent par
//! [`crate::env::secret`] (`_FILE` prioritaire) et jamais depuis le fichier TOML.

use crate::crypto::MasterKey;
use crate::env::{Env, secret};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

/// Port d'écoute par défaut.
pub const DEFAULT_PORT: u16 = 8580;

/// Variables secrètes retirées de l'environnement du processus après lecture.
pub const SECRET_ENV: &[&str] = &["RCM_ENCRYPTION_KEY", "RCM_CLOUDFLARE_TOKEN"];

/// Jeton d'API Cloudflare (limité à Zone:DNS:Edit sur la zone) : jamais affiché, ni par `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(String);

impl ApiToken {
    /// Caractères visibles sans espace (il part dans un en-tête), 20 à 200 ; l'erreur ne recopie
    /// jamais la valeur.
    pub fn parse(s: &str) -> Result<ApiToken, String> {
        if !(20..=200).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("jeton invalide (20 à 200 caractères visibles, sans espace)".into());
        }
        Ok(ApiToken(s.to_string()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiToken(masqué)")
    }
}

/// Automatisation Cloudflare : jeton (secret Docker) et identifiant de la zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cloudflare {
    pub token: ApiToken,
    pub zone_id: String,
}

/// Aiguilleur : écouteur TCP public qui route par le nom de la poignée de main.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Router {
    pub listen: IpAddr,
    pub port: u16,
    /// Connexions simultanées, au plus.
    pub max_connections: usize,
    /// Connexions simultanées par adresse (IPv6 : par /64).
    pub max_per_ip: usize,
}

/// Bloc d'adresses `IP/longueur` (ou une IP seule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, l)) => (ip.parse::<IpAddr>().ok()?, Some(l.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = len.unwrap_or(max);
        (len <= max).then_some(Cidr { net: ip, len })
    }

    /// Longueur du préfixe (32 ou 128 pour une adresse seule).
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn is_ipv4(&self) -> bool {
        self.net.is_ipv4()
    }

    /// L'adresse est-elle dans le bloc ? Une IPv4 vue en IPv6 (`::ffff:a.b.c.d`, socket double
    /// pile) est comparée comme IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len) };
                (u32::from(n) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.len == 0 { 0 } else { u128::MAX << (128 - self.len) };
                (u128::from(n) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

/// IPv4 vue en IPv6 (`::ffff:a.b.c.d`) ramenée en IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Un mandataire de confiance : réseau (IP ou CIDR) ou nom d'hôte résolu périodiquement (voir
/// [`crate::proxies`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxySpec {
    Net(Cidr),
    Host(String),
}

impl ProxySpec {
    pub fn parse(s: &str) -> Option<ProxySpec> {
        if let Some(c) = Cidr::parse(s) {
            return Some(ProxySpec::Net(c));
        }
        hostname_valid(s).then(|| ProxySpec::Host(s.to_ascii_lowercase()))
    }
}

/// Nom d'hôte DNS (`traefik`, `proxy.lan`) : étiquettes de 1 à 63 caractères `a-z 0-9 -`, sans
/// tiret au bord ; pas uniquement des chiffres (une IP mal écrite n'est pas un nom).
fn hostname_valid(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    labels.iter().all(|l| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    }) && !labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Attribut `Secure` du cookie de session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieSecure {
    /// Posé quand la requête est arrivée en HTTPS (vu par `X-Forwarded-Proto` derrière un
    /// mandataire de confiance, voir `trusted_proxies`).
    Auto,
    Always,
    Never,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: IpAddr,
    pub port: u16,
    pub data_dir: PathBuf,
    pub cookie_secure: CookieSecure,
    /// Mandataires inverses de confiance (IP, CIDR ou nom d'hôte ; vide par défaut). Seulement
    /// quand la connexion vient de l'un d'eux, `X-Forwarded-For` (adresse du client : limite de
    /// tentatives, audit), `X-Forwarded-Proto` (cookie `Secure`, HSTS) et `X-Forwarded-Host`
    /// (contrôle d'origine) sont lus ; sinon ces en-têtes sont ignorés.
    pub trusted_proxies: Vec<ProxySpec>,
    /// Session fermée après cette durée sans requête.
    pub session_idle: Duration,
    /// Durée de vie maximale d'une session, même active.
    pub session_max: Duration,
    /// Échecs de connexion tolérés par (adresse, compte) dans la fenêtre.
    pub login_max_failures: u32,
    pub login_window: Duration,
    /// Fils du moteur asynchrone (0 = nombre de cœurs logiques).
    pub threads: usize,
    /// Connexions TCP ouvertes en même temps, au plus (au-delà : fermées à l'acceptation).
    pub max_connections: usize,
    /// Connexions TCP simultanées par adresse (hors mandataires de confiance).
    pub max_connections_per_ip: usize,
    /// Délai pour recevoir les en-têtes d'une requête (compte aussi l'attente entre deux requêtes
    /// d'une connexion gardée ouverte).
    pub header_read_timeout: Duration,
    /// Délai total d'une requête (corps compris) avant la réponse.
    pub request_timeout: Duration,
    /// WebSocket fermé après cette durée sans rien recevoir (le serveur envoie un ping toutes les
    /// 30 s : un client vivant répond).
    pub ws_idle_timeout: Duration,
    /// WebSocket ouverts en même temps par session, au plus.
    pub ws_per_session: usize,
    /// Attente maximale d'une place de hachage Argon2 (au-delà : 503 + Retry-After).
    pub hash_wait: Duration,
    /// Requêtes d'authentification en cours en même temps par adresse (IPv6 : par /64).
    pub auth_inflight_per_ip: u32,
    /// Lignes du journal d'audit gardées ce nombre de jours.
    pub audit_retention_days: u32,
    /// Serveurs au plus.
    pub max_servers: usize,
    /// Mémoire (Mio) de tous les serveurs ensemble, au plus (0 : pas de borne).
    pub max_memory_mb: u64,
    /// Installations (téléchargements) simultanées, au plus.
    pub max_installs: usize,
    /// Taille maximale d'un fichier envoyé par le gestionnaire de fichiers (Mio).
    pub upload_max_mb: u64,
    /// Lancé dans l'image Docker (`RCM_CONTAINER=true`) : la clé de chiffrement doit être
    /// fournie (secret Docker), jamais générée dans le volume à côté de la base.
    pub container: bool,
    /// Clé de chiffrement des champs sensibles (`RCM_ENCRYPTION_KEY` ou `_FILE`). `None` : lue
    /// (ou créée au premier lancement hors conteneur) dans `<données>/manager.key`.
    pub encryption_key: Option<MasterKey>,
    /// Adresse publique (`RCM_PUBLIC_URL`, ex. `https://manager.example.org`) : origine et
    /// identifiant de domaine (RP ID) des passkeys, fixes. Sans elle, passkeys désactivées.
    pub public_url: Option<PublicUrl>,
    /// Durée de vie d'un défi de passkey (à usage unique, gardé côté serveur).
    pub passkey_challenge_ttl: Duration,
    /// Zone DNS des noms publics (`RCM_DNS_ZONE`, ex. `example.com`).
    pub dns_zone: Option<String>,
    /// Automatisation Cloudflare (`RCM_CLOUDFLARE_TOKEN_FILE` seulement).
    pub cloudflare: Option<Cloudflare>,
    /// IP publiques fixées (sinon détectées si `public_ip_detect`).
    pub public_ipv4: Option<std::net::Ipv4Addr>,
    pub public_ipv6: Option<std::net::Ipv6Addr>,
    pub public_ip_detect: bool,
    /// Aiguilleur (`None` : coupé).
    pub router: Option<Router>,
}

impl Config {
    /// Valeurs par défaut pour un dossier de données donné (tests, outils).
    pub fn with_data_dir(data_dir: PathBuf) -> Self {
        Config {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            data_dir,
            cookie_secure: CookieSecure::Auto,
            trusted_proxies: Vec::new(),
            session_idle: Duration::from_secs(60 * 60),
            session_max: Duration::from_secs(12 * 60 * 60),
            login_max_failures: 5,
            login_window: Duration::from_secs(15 * 60),
            threads: 0,
            max_connections: 512,
            max_connections_per_ip: 64,
            header_read_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            ws_idle_timeout: Duration::from_secs(90),
            ws_per_session: 4,
            hash_wait: Duration::from_secs(5),
            auth_inflight_per_ip: 4,
            audit_retention_days: 90,
            max_servers: 32,
            max_memory_mb: 0,
            max_installs: 2,
            upload_max_mb: 1024,
            container: false,
            encryption_key: None,
            public_url: None,
            passkey_challenge_ttl: Duration::from_secs(5 * 60),
            dns_zone: None,
            cloudflare: None,
            public_ipv4: None,
            public_ipv6: None,
            public_ip_detect: true,
            router: None,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("manager.db")
    }

    /// Fichier de la clé de chiffrement générée hors conteneur.
    pub fn key_path(&self) -> PathBuf {
        self.data_dir.join("manager.key")
    }
}

/// Dossier de données par défaut de la plateforme.
pub fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        match std::env::var_os("LOCALAPPDATA") {
            Some(d) => PathBuf::from(d).join("rustcraft-manager"),
            None => PathBuf::from("rustcraft-manager"),
        }
    } else {
        PathBuf::from("/data")
    }
}

/// Contenu du fichier TOML (toutes les clés facultatives, clé inconnue = erreur). Les nombres sont
/// lus en `i64` pour que la borne (et non le type) nomme l'erreur.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<String>,
    port: Option<i64>,
    data_dir: Option<PathBuf>,
    cookie_secure: Option<String>,
    trusted_proxies: Option<Vec<String>>,
    session_idle_minutes: Option<i64>,
    session_max_hours: Option<i64>,
    login_max_failures: Option<i64>,
    login_window_minutes: Option<i64>,
    threads: Option<i64>,
    max_connections: Option<i64>,
    max_connections_per_ip: Option<i64>,
    audit_retention_days: Option<i64>,
    max_servers: Option<i64>,
    max_memory_mb: Option<i64>,
    max_installs: Option<i64>,
    upload_max_mb: Option<i64>,
    public_url: Option<String>,
    dns_zone: Option<String>,
    cloudflare_zone_id: Option<String>,
    public_ipv4: Option<String>,
    public_ipv6: Option<String>,
    public_ip_detect: Option<bool>,
    router_port: Option<i64>,
    router_listen: Option<String>,
    router_max_connections: Option<i64>,
    router_max_per_ip: Option<i64>,
}

/// Arguments de la ligne de commande.
#[derive(Default, Debug)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub port: Option<String>,
    pub help: bool,
    pub version: bool,
    /// Interroge `/api/health` de l'instance configurée et sort (0 = en bonne santé).
    pub healthcheck: bool,
}

pub const HELP: &str = "\
Rustcraft Manager : gestionnaire web de serveurs Minecraft.

Usage : rustcraft-manager [options]

  --config <fichier>    fichier TOML (défaut : <données>/manager.toml s'il existe)
  --data-dir <dossier>  dossier de données (base, clé, réglages)
  --listen <adresse>    adresse d'écoute (défaut 127.0.0.1)
  --port <port>         port d'écoute (défaut 8580)
  --healthcheck         interroge /api/health de l'instance configurée (0 = en bonne santé)
  -h, --help            cette aide
  -V, --version         version

Variables : RCM_CONFIG, RCM_DATA_DIR, RCM_LISTEN, RCM_PORT, RCM_COOKIE_SECURE (auto|always|never),
RCM_TRUSTED_PROXIES (IP, CIDR ou noms d'hôte séparés par des virgules), RCM_SESSION_IDLE_MINUTES,
RCM_SESSION_MAX_HOURS, RCM_LOGIN_MAX_FAILURES, RCM_LOGIN_WINDOW_MINUTES, RCM_THREADS,
RCM_MAX_CONNECTIONS, RCM_AUDIT_RETENTION_DAYS, RCM_CONTAINER (true|false),
RCM_ENCRYPTION_KEY ou RCM_ENCRYPTION_KEY_FILE (32 octets en base64 ou hexadécimal),
RCM_PUBLIC_URL (https://<nom> : passkeys), RCM_LOG (error|warn|info|debug).
Adresses des serveurs : RCM_DNS_ZONE, RCM_CLOUDFLARE_TOKEN_FILE (secret seulement) et
RCM_CLOUDFLARE_ZONE_ID, RCM_PUBLIC_IPV4, RCM_PUBLIC_IPV6, RCM_PUBLIC_IP_DETECT (true|false),
RCM_ROUTER_PORT (aiguilleur, 0 = coupé), RCM_ROUTER_LISTEN, RCM_ROUTER_MAX_CONNECTIONS,
RCM_ROUTER_MAX_PER_IP.
";

pub fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args::default();
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} : valeur manquante"));
        match arg.as_str() {
            "--config" => a.config = Some(PathBuf::from(val("--config")?)),
            "--data-dir" => a.data_dir = Some(PathBuf::from(val("--data-dir")?)),
            "--listen" => a.listen = Some(val("--listen")?),
            "--port" => a.port = Some(val("--port")?),
            "-h" | "--help" => a.help = true,
            "-V" | "--version" => a.version = true,
            "--healthcheck" => a.healthcheck = true,
            other => return Err(format!("argument inconnu : {other}")),
        }
    }
    Ok(a)
}

/// Booléen strict : `true` ou `false` seulement (`on`, `yes`, `1` refusés : une faute de frappe ne
/// doit pas changer un réglage de sécurité en silence).
pub fn parse_bool(name: &str, v: &str) -> Result<bool, String> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{name} : true ou false attendu (lu : {v})")),
    }
}

/// Entier dans `[min, max]`, l'erreur nomme la source et les bornes.
fn bounded(name: &str, v: &str, min: i64, max: i64) -> Result<i64, String> {
    let n: i64 = v.trim().parse().map_err(|_| format!("{name} : nombre entier attendu (lu : {v})"))?;
    if !(min..=max).contains(&n) {
        return Err(format!("{name} : hors bornes, de {min} à {max} (lu : {n})"));
    }
    Ok(n)
}

/// Valeur d'un réglage numérique : variable d'environnement, sinon clé du fichier ; bornée.
fn number(env: &dyn Env, var: &str, file: Option<i64>, key: &str, min: i64, max: i64) -> Result<Option<i64>, String> {
    if let Some(v) = env.var(var)? {
        return bounded(var, &v, min, max).map(Some);
    }
    match file {
        Some(n) => bounded(&format!("{key} (fichier)"), &n.to_string(), min, max).map(Some),
        None => Ok(None),
    }
}

/// Assemble la configuration.
pub fn load(args: &Args, env: &dyn Env) -> Result<Config, String> {
    let data_dir_override = match &args.data_dir {
        Some(d) => Some(d.clone()),
        None => env.var("RCM_DATA_DIR")?.map(PathBuf::from),
    };
    let base_dir = data_dir_override.clone().unwrap_or_else(default_data_dir);
    let config_override = match &args.config {
        Some(p) => Some(p.clone()),
        None => env.var("RCM_CONFIG")?.map(PathBuf::from),
    };
    let (file_path, explicit) = match config_override {
        Some(p) => (p, true),
        None => (base_dir.join("manager.toml"), false),
    };
    let file: FileConfig = match std::fs::read_to_string(&file_path) {
        Ok(s) => toml::from_str(&s).map_err(|e| format!("{} : {e}", file_path.display()))?,
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => FileConfig::default(),
        Err(e) => return Err(format!("{} : {e}", file_path.display())),
    };

    let data_dir = data_dir_override.or(file.data_dir).unwrap_or(base_dir);
    // Chemin absolu : les serveurs tournent dans leur propre dossier, un chemin relatif passé à
    // Java (`-Djava.io.tmpdir=…`) y créerait une copie de l'arborescence (vu le 20/10 avec
    // `--data-dir target/essais/data` : `servers/2/target/essais/data`).
    let data_dir = std::path::absolute(&data_dir).map_err(|e| format!("{} : {e}", data_dir.display()))?;
    let mut c = Config::with_data_dir(data_dir);

    // Ordre : fichier, puis environnement, puis arguments (le dernier gagne).
    let listen = match &args.listen {
        Some(l) => Some(("--listen", l.clone())),
        None => match env.var("RCM_LISTEN")? {
            Some(l) => Some(("RCM_LISTEN", l)),
            None => file.listen.map(|l| ("listen (fichier)", l)),
        },
    };
    if let Some((name, l)) = listen {
        c.listen = l.trim().parse().map_err(|_| format!("{name} : adresse IP attendue (lu : {l})"))?;
    }
    let port = match &args.port {
        Some(p) => Some(bounded("--port", p, 1, 65535)?),
        None => number(env, "RCM_PORT", file.port, "port", 1, 65535)?,
    };
    if let Some(p) = port {
        c.port = p as u16;
    }
    let cookie = match env.var("RCM_COOKIE_SECURE")? {
        Some(s) => Some(("RCM_COOKIE_SECURE", s)),
        None => file.cookie_secure.map(|s| ("cookie_secure (fichier)", s)),
    };
    if let Some((name, s)) = cookie {
        c.cookie_secure = match s.trim() {
            "auto" => CookieSecure::Auto,
            "always" => CookieSecure::Always,
            "never" => CookieSecure::Never,
            _ => return Err(format!("{name} : auto, always ou never (lu : {s})")),
        };
    }
    let proxies = match env.var("RCM_TRUSTED_PROXIES")? {
        Some(s) => Some(("RCM_TRUSTED_PROXIES", s.split(',').map(str::to_string).collect::<Vec<_>>())),
        None => file.trusted_proxies.map(|l| ("trusted_proxies (fichier)", l)),
    };
    if let Some((name, list)) = proxies {
        c.trusted_proxies = list
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| ProxySpec::parse(s).ok_or_else(|| format!("{name} : IP, CIDR ou nom d'hôte invalide ({s})")))
            .collect::<Result<_, _>>()?;
    }
    if let Some(m) =
        number(env, "RCM_SESSION_IDLE_MINUTES", file.session_idle_minutes, "session_idle_minutes", 1, 60 * 24 * 30)?
    {
        c.session_idle = Duration::from_secs(m as u64 * 60);
    }
    if let Some(h) = number(env, "RCM_SESSION_MAX_HOURS", file.session_max_hours, "session_max_hours", 1, 24 * 90)? {
        c.session_max = Duration::from_secs(h as u64 * 3600);
    }
    if let Some(n) = number(env, "RCM_LOGIN_MAX_FAILURES", file.login_max_failures, "login_max_failures", 1, 1000)? {
        c.login_max_failures = n as u32;
    }
    if let Some(m) =
        number(env, "RCM_LOGIN_WINDOW_MINUTES", file.login_window_minutes, "login_window_minutes", 1, 24 * 60)?
    {
        c.login_window = Duration::from_secs(m as u64 * 60);
    }
    if let Some(t) = number(env, "RCM_THREADS", file.threads, "threads", 0, 4096)? {
        c.threads = t as usize;
    }
    if let Some(n) = number(env, "RCM_MAX_CONNECTIONS", file.max_connections, "max_connections", 16, 65536)? {
        c.max_connections = n as usize;
    }
    if let Some(n) =
        number(env, "RCM_MAX_CONNECTIONS_PER_IP", file.max_connections_per_ip, "max_connections_per_ip", 1, 65536)?
    {
        c.max_connections_per_ip = n as usize;
    }
    if let Some(d) =
        number(env, "RCM_AUDIT_RETENTION_DAYS", file.audit_retention_days, "audit_retention_days", 1, 3650)?
    {
        c.audit_retention_days = d as u32;
    }
    if let Some(n) = number(env, "RCM_MAX_SERVERS", file.max_servers, "max_servers", 1, 1000)? {
        c.max_servers = n as usize;
    }
    if let Some(n) = number(env, "RCM_MAX_MEMORY_MB", file.max_memory_mb, "max_memory_mb", 0, 1_048_576)? {
        c.max_memory_mb = n as u64;
    }
    if let Some(n) = number(env, "RCM_MAX_INSTALLS", file.max_installs, "max_installs", 1, 16)? {
        c.max_installs = n as usize;
    }
    if let Some(n) = number(env, "RCM_UPLOAD_MAX_MB", file.upload_max_mb, "upload_max_mb", 1, 65_536)? {
        c.upload_max_mb = n as u64;
    }
    if let Some(v) = env.var("RCM_CONTAINER")? {
        c.container = parse_bool("RCM_CONTAINER", &v)?;
    }
    if let Some(k) = secret(env, "RCM_ENCRYPTION_KEY")? {
        c.encryption_key = Some(MasterKey::parse(&k).map_err(|e| format!("RCM_ENCRYPTION_KEY : {e}"))?);
    }
    let public = match env.var("RCM_PUBLIC_URL")? {
        Some(u) => Some(("RCM_PUBLIC_URL", u)),
        None => file.public_url.map(|u| ("public_url (fichier)", u)),
    };
    if let Some((name, u)) = public {
        c.public_url = Some(PublicUrl::parse(&u).map_err(|e| format!("{name} : {e} (lu : {u})"))?);
    }
    let net = NetworkFile {
        dns_zone: file.dns_zone,
        cloudflare_zone_id: file.cloudflare_zone_id,
        public_ipv4: file.public_ipv4,
        public_ipv6: file.public_ipv6,
        public_ip_detect: file.public_ip_detect,
        router_port: file.router_port,
        router_listen: file.router_listen,
        router_max_connections: file.router_max_connections,
        router_max_per_ip: file.router_max_per_ip,
    };
    load_network(env, &mut c, net)?;
    Ok(c)
}

/// Texte d'un réglage : variable d'environnement, sinon clé du fichier ; rend la source nommée.
fn text(env: &dyn Env, var: &'static str, file: Option<String>, key: &str) -> Result<Option<(String, String)>, String> {
    Ok(match env.var(var)? {
        Some(v) => Some((var.to_string(), v)),
        None => file.map(|v| (format!("{key} (fichier)"), v)),
    })
}

/// IP publique fixée : bonne famille, adresse joignable d'Internet (ni privée, ni locale, ni
/// réservée), sinon refus nommé.
fn public_ip(name: &str, v: &str, v6: bool) -> Result<IpAddr, String> {
    let ip: IpAddr = v.trim().parse().map_err(|_| format!("{name} : adresse IP attendue (lu : {v})"))?;
    if ip.is_ipv6() != v6 {
        return Err(format!("{name} : adresse {} attendue (lu : {v})", if v6 { "IPv6" } else { "IPv4" }));
    }
    if !crate::network::ip_is_public(ip) {
        return Err(format!("{name} : adresse non publique (lu : {v})"));
    }
    Ok(ip)
}

/// Clés du fichier propres aux adresses des serveurs.
struct NetworkFile {
    dns_zone: Option<String>,
    cloudflare_zone_id: Option<String>,
    public_ipv4: Option<String>,
    public_ipv6: Option<String>,
    public_ip_detect: Option<bool>,
    router_port: Option<i64>,
    router_listen: Option<String>,
    router_max_connections: Option<i64>,
    router_max_per_ip: Option<i64>,
}

/// Adresses des serveurs : zone, Cloudflare, IP publiques, aiguilleur.
fn load_network(env: &dyn Env, c: &mut Config, file: NetworkFile) -> Result<(), String> {
    if let Some((name, z)) = text(env, "RCM_DNS_ZONE", file.dns_zone.clone(), "dns_zone")? {
        let z = rc_manager_shared::normalize_hostname(&z);
        if !rc_manager_shared::hostname_valid(&z) {
            return Err(format!("{name} : nom de zone attendu, ex. example.org (lu : {z})"));
        }
        c.dns_zone = Some(z);
    }
    // Le jeton ne vient QUE d'un fichier (secret Docker) : une variable en clair se lirait dans
    // `docker inspect` et l'environnement des processus.
    if env.var("RCM_CLOUDFLARE_TOKEN")?.is_some() {
        return Err(
            "RCM_CLOUDFLARE_TOKEN : refusée, fournir le jeton par RCM_CLOUDFLARE_TOKEN_FILE (secret Docker)".into()
        );
    }
    let zone_id = text(env, "RCM_CLOUDFLARE_ZONE_ID", file.cloudflare_zone_id.clone(), "cloudflare_zone_id")?;
    match (secret(env, "RCM_CLOUDFLARE_TOKEN")?, zone_id) {
        (Some(t), Some((name, z))) => {
            let token = ApiToken::parse(&t).map_err(|e| format!("RCM_CLOUDFLARE_TOKEN_FILE : {e}"))?;
            let z = z.trim().to_ascii_lowercase();
            if z.len() != 32 || !z.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("{name} : 32 chiffres hexadécimaux attendus (lu : {z})"));
            }
            if c.dns_zone.is_none() {
                return Err("RCM_DNS_ZONE : exigée avec RCM_CLOUDFLARE_TOKEN_FILE (nom de la zone)".into());
            }
            c.cloudflare = Some(Cloudflare { token, zone_id: z });
        }
        (Some(_), None) => {
            return Err("RCM_CLOUDFLARE_ZONE_ID : exigée avec RCM_CLOUDFLARE_TOKEN_FILE".into());
        }
        (None, Some((name, _))) => return Err(format!("{name} : sans RCM_CLOUDFLARE_TOKEN_FILE, inutile")),
        (None, None) => {}
    }
    if let Some((name, v)) = text(env, "RCM_PUBLIC_IPV4", file.public_ipv4.clone(), "public_ipv4")?
        && let IpAddr::V4(ip) = public_ip(&name, &v, false)?
    {
        c.public_ipv4 = Some(ip);
    }
    if let Some((name, v)) = text(env, "RCM_PUBLIC_IPV6", file.public_ipv6.clone(), "public_ipv6")?
        && let IpAddr::V6(ip) = public_ip(&name, &v, true)?
    {
        c.public_ipv6 = Some(ip);
    }
    match env.var("RCM_PUBLIC_IP_DETECT")? {
        Some(v) => c.public_ip_detect = parse_bool("RCM_PUBLIC_IP_DETECT", &v)?,
        None => c.public_ip_detect = file.public_ip_detect.unwrap_or(true),
    }
    let port = number(env, "RCM_ROUTER_PORT", file.router_port, "router_port", 0, 65535)?.unwrap_or(0);
    if port != 0 && port < 1024 {
        return Err(format!("RCM_ROUTER_PORT : 0 (coupé) ou de 1024 à 65535 (lu : {port})"));
    }
    if port != 0 {
        let mut r = Router {
            listen: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: port as u16,
            max_connections: 1024,
            max_per_ip: 8,
        };
        if let Some((name, l)) = text(env, "RCM_ROUTER_LISTEN", file.router_listen.clone(), "router_listen")? {
            r.listen = l.trim().parse().map_err(|_| format!("{name} : adresse IP attendue (lu : {l})"))?;
        }
        if let Some(n) =
            number(env, "RCM_ROUTER_MAX_CONNECTIONS", file.router_max_connections, "router_max_connections", 16, 65536)?
        {
            r.max_connections = n as usize;
        }
        if let Some(n) = number(env, "RCM_ROUTER_MAX_PER_IP", file.router_max_per_ip, "router_max_per_ip", 1, 1024)? {
            r.max_per_ip = n as usize;
        }
        if r.port == c.port && (r.listen == c.listen || r.listen.is_unspecified() || c.listen.is_unspecified()) {
            return Err(format!("RCM_ROUTER_PORT : même port que l'interface ({port})"));
        }
        c.router = Some(r);
    }
    Ok(())
}

/// Adresse publique du gestionnaire : origine exacte (`https://hôte[:port]`) et identifiant de
/// domaine des passkeys (l'hôte). HTTPS exigé, sauf `http://localhost` (essais locaux) ; pas de
/// chemin, de requête ni de fragment ; pas d'adresse IP (refusée comme RP ID par WebAuthn).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicUrl {
    pub origin: String,
    pub rp_id: String,
}

impl PublicUrl {
    pub fn parse(s: &str) -> Result<PublicUrl, String> {
        let s = s.trim().trim_end_matches('/');
        let (scheme, rest) = s.split_once("://").ok_or("adresse https://<nom> attendue")?;
        let scheme = scheme.to_ascii_lowercase();
        if rest.contains(['/', '?', '#', '@']) {
            return Err("ni chemin, ni requête, ni identifiant : https://<nom>[:port] seulement".into());
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => {
                let n: u16 = p.parse().map_err(|_| "port invalide")?;
                (h.to_ascii_lowercase(), Some(n))
            }
            None => (rest.to_ascii_lowercase(), None),
        };
        if !hostname_valid(&host) {
            return Err("nom d'hôte attendu (une adresse IP ne peut pas porter de passkeys)".into());
        }
        match scheme.as_str() {
            "https" => {}
            "http" if host == "localhost" => {}
            _ => return Err("https exigé (http seulement pour localhost)".into()),
        }
        let origin = match port {
            Some(p) => format!("{scheme}://{host}:{p}"),
            None => format!("{scheme}://{host}"),
        };
        Ok(PublicUrl { origin, rp_id: host })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rcm-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn args_in(d: &std::path::Path) -> Args {
        Args { data_dir: Some(d.to_path_buf()), ..Default::default() }
    }

    #[test]
    fn defauts_locaux() {
        let d = tmp("defauts");
        let c = load(&args_in(&d), &MapEnv::default()).unwrap();
        assert_eq!(c.listen, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(c.port, DEFAULT_PORT);
        assert_eq!(c.data_dir, d);
        assert_eq!(c.cookie_secure, CookieSecure::Auto);
        // Dossier relatif : rendu absolu (les serveurs tournent ailleurs).
        let rel =
            load(&Args { data_dir: Some("rel/donnees".into()), ..Default::default() }, &MapEnv::default()).unwrap();
        assert!(rel.data_dir.is_absolute(), "{}", rel.data_dir.display());
        assert!(rel.data_dir.ends_with("rel/donnees"));
        assert!(c.trusted_proxies.is_empty());
        assert!(!c.container);
        assert!(c.encryption_key.is_none());
    }

    #[test]
    fn cidr() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("::1")));
        let one = Cidr::parse("192.168.1.5").unwrap();
        assert!(one.contains(ip("192.168.1.5")) && !one.contains(ip("192.168.1.6")));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));
        // IPv4 vue en IPv6 (socket double pile) reconnue.
        assert!(c.contains(ip("::ffff:10.0.0.1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("bidon").is_none());
        let env = MapEnv::new(&[("RCM_TRUSTED_PROXIES", "172.20.0.0/24, 127.0.0.1, traefik")]);
        let p = load(&args_in(&tmp("cidr")), &env).unwrap().trusted_proxies;
        assert_eq!(p.len(), 3);
        assert_eq!(p[2], ProxySpec::Host("traefik".into()));
    }

    #[test]
    fn noms_de_mandataires() {
        for ok in ["traefik", "proxy.lan", "rp-1.example.org", "Traefik"] {
            assert!(matches!(ProxySpec::parse(ok), Some(ProxySpec::Host(_))), "{ok}");
        }
        for bad in ["", "-x", "x-", "a..b", "999.1.1.1", "a_b", "évier", &"a".repeat(64)] {
            assert!(ProxySpec::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(ProxySpec::parse("Traefik"), Some(ProxySpec::Host("traefik".into())));
    }

    #[test]
    fn priorites_fichier_env_arguments() {
        let d = tmp("prio");
        std::fs::write(
            d.join("manager.toml"),
            "listen = \"0.0.0.0\"\nport = 9000\nsession_idle_minutes = 5\ncookie_secure = \"always\"\n",
        )
        .unwrap();
        let env = MapEnv::new(&[("RCM_PORT", "9100"), ("RCM_SESSION_MAX_HOURS", "2")]);
        let args = Args { data_dir: Some(d.clone()), listen: Some("::1".into()), ..Default::default() };
        let c = load(&args, &env).unwrap();
        assert_eq!(c.listen, "::1".parse::<IpAddr>().unwrap()); // argument > fichier
        assert_eq!(c.port, 9100); // environnement > fichier
        assert_eq!(c.session_idle, Duration::from_secs(300)); // fichier
        assert_eq!(c.session_max, Duration::from_secs(7200));
        assert_eq!(c.cookie_secure, CookieSecure::Always);
    }

    #[test]
    fn erreurs_explicites() {
        let d = tmp("err");
        std::fs::write(d.join("manager.toml"), "inconnue = 1\n").unwrap();
        assert!(load(&args_in(&d), &MapEnv::default()).is_err(), "clé inconnue refusée");
        let args = Args { config: Some(d.join("absent.toml")), ..Default::default() };
        assert!(load(&args, &MapEnv::default()).is_err(), "fichier explicite absent refusé");
        assert!(parse_args(["--port".to_string()].into_iter()).is_err());
        assert!(parse_args(["--bizarre".to_string()].into_iter()).is_err());
    }

    /// Mineur 5 : chaque secret lu par `secret(env, "…")` est retiré de l'environnement après
    /// lecture (liste `SECRET_ENV`, appliquée par `main`).
    #[test]
    fn chaque_secret_retire_de_l_environnement() {
        let src = include_str!("config.rs");
        let read: Vec<&str> = src
            .match_indices("secret(env, \"")
            .map(|(i, m)| {
                let rest = &src[i + m.len()..];
                &rest[..rest.find('"').unwrap()]
            })
            .filter(|n| n.starts_with("RCM_"))
            .collect();
        assert!(!read.is_empty());
        for name in read {
            assert!(SECRET_ENV.contains(&name), "{name} lu mais jamais retiré de l'environnement");
        }
        assert!(include_str!("main.rs").contains("scrub_secret_env();"));
    }

    /// Échec fermé : hors bornes, booléens lâches et alias ambigus refusés, la variable nommée
    /// (avant : valeurs ramenées en silence dans les bornes, `true` accepté pour `always`).
    #[test]
    fn adresse_publique_des_passkeys() {
        let p = PublicUrl::parse("https://Manager.Example.com/").unwrap();
        assert_eq!(p, PublicUrl { origin: "https://manager.example.com".into(), rp_id: "manager.example.com".into() });
        assert_eq!(PublicUrl::parse("https://nas.lan:8443").unwrap().origin, "https://nas.lan:8443");
        assert_eq!(PublicUrl::parse("http://localhost:8580").unwrap().rp_id, "localhost");
        for bad in [
            "http://manager.example.com",
            "https://192.168.1.2",
            "https://manager.example.com/chemin",
            "https://manager.example.com?x=1",
            "https://u@manager.example.com",
            "manager.example.com",
            "ftp://manager.example.com",
            "https://h:99999",
        ] {
            assert!(PublicUrl::parse(bad).is_err(), "{bad}");
        }
        let d = tmp("public");
        let e = load(&args_in(&d), &MapEnv::new(&[("RCM_PUBLIC_URL", "http://exemple.org")])).unwrap_err();
        assert!(e.starts_with("RCM_PUBLIC_URL"), "{e}");
        let c = load(&args_in(&d), &MapEnv::new(&[("RCM_PUBLIC_URL", "https://exemple.org")])).unwrap();
        assert_eq!(c.public_url.unwrap().rp_id, "exemple.org");
        assert!(load(&args_in(&d), &MapEnv::default()).unwrap().public_url.is_none());
    }

    #[test]
    fn echec_ferme_et_variable_nommee() {
        let d = tmp("ferme");
        let err = |vars: &[(&str, &str)]| load(&args_in(&d), &MapEnv::new(vars)).unwrap_err();
        for (var, val) in [
            ("RCM_SESSION_IDLE_MINUTES", "0"),
            ("RCM_SESSION_IDLE_MINUTES", "999999"),
            ("RCM_SESSION_MAX_HOURS", "0"),
            ("RCM_LOGIN_MAX_FAILURES", "0"),
            ("RCM_LOGIN_WINDOW_MINUTES", "100000"),
            ("RCM_THREADS", "-1"),
            ("RCM_THREADS", "124832"),
            ("RCM_PORT", "0"),
            ("RCM_PORT", "70000"),
            ("RCM_MAX_CONNECTIONS", "1"),
            ("RCM_AUDIT_RETENTION_DAYS", "0"),
            ("RCM_CONTAINER", "on"),
            ("RCM_CONTAINER", "1"),
            ("RCM_COOKIE_SECURE", "true"),
            ("RCM_LISTEN", "partout"),
            ("RCM_TRUSTED_PROXIES", "10.0.0.0/40"),
        ] {
            let e = err(&[(var, val)]);
            assert!(e.starts_with(var), "{var}={val} : {e}");
        }
        // Le fichier aussi : la clé est nommée.
        std::fs::write(d.join("manager.toml"), "session_idle_minutes = 0\n").unwrap();
        let e = load(&args_in(&d), &MapEnv::default()).unwrap_err();
        assert!(e.starts_with("session_idle_minutes"), "{e}");
        std::fs::remove_file(d.join("manager.toml")).unwrap();
        // Clé de chiffrement invalide : refus, valeur jamais recopiée.
        let e = err(&[("RCM_ENCRYPTION_KEY", "trop-courte-secrete")]);
        assert!(e.starts_with("RCM_ENCRYPTION_KEY") && !e.contains("trop-courte-secrete"), "{e}");
        let ok =
            load(&args_in(&d), &MapEnv::new(&[("RCM_CONTAINER", "true"), ("RCM_ENCRYPTION_KEY", &"ab".repeat(32))]))
                .unwrap();
        assert!(ok.container && ok.encryption_key.is_some());
    }

    /// Jeton Cloudflare par fichier SEULEMENT, jamais recopié dans une erreur ni par `Debug` ;
    /// zone et identifiant exigés avec lui ; IP fixées publiques et de la bonne famille ;
    /// aiguilleur coupé par défaut, borné.
    #[test]
    fn adresses_cloudflare_et_aiguilleur() {
        let d = tmp("reseau");
        let tok = "cf-jeton-secret-0123456789abcdef0123";
        let zid = "0123456789abcdef0123456789abcdef";
        let load_env =
            |vars: &[(&str, &str)]| load(&args_in(&d), &MapEnv::new(vars).file("/run/secrets/cf", &format!("{tok}\n")));
        let c = load_env(&[]).unwrap();
        assert!(c.cloudflare.is_none() && c.router.is_none() && c.dns_zone.is_none() && c.public_ip_detect);
        let ok = load_env(&[
            ("RCM_CLOUDFLARE_TOKEN_FILE", "/run/secrets/cf"),
            ("RCM_CLOUDFLARE_ZONE_ID", zid),
            ("RCM_DNS_ZONE", "Example.com."),
        ])
        .unwrap();
        let cf = ok.cloudflare.clone().unwrap();
        assert_eq!(cf.token.expose(), tok);
        assert_eq!(ok.dns_zone.as_deref(), Some("example.com"));
        assert!(!format!("{ok:?}").contains(tok), "jeton visible par Debug");
        // Variable en clair : refusée, même avec le fichier ; valeur jamais citée.
        for vars in [
            vec![("RCM_CLOUDFLARE_TOKEN", tok)],
            vec![("RCM_CLOUDFLARE_TOKEN", tok), ("RCM_CLOUDFLARE_TOKEN_FILE", "/run/secrets/cf")],
        ] {
            let e = load_env(&vars).unwrap_err();
            assert!(e.starts_with("RCM_CLOUDFLARE_TOKEN") && !e.contains(tok), "{e}");
        }
        for (vars, var) in [
            (vec![("RCM_CLOUDFLARE_TOKEN_FILE", "/run/secrets/cf"), ("RCM_DNS_ZONE", "a.b")], "RCM_CLOUDFLARE_ZONE_ID"),
            (vec![("RCM_CLOUDFLARE_TOKEN_FILE", "/run/secrets/cf"), ("RCM_CLOUDFLARE_ZONE_ID", zid)], "RCM_DNS_ZONE"),
            (vec![("RCM_CLOUDFLARE_ZONE_ID", zid)], "RCM_CLOUDFLARE_ZONE_ID"),
            (
                vec![
                    ("RCM_CLOUDFLARE_TOKEN_FILE", "/run/secrets/cf"),
                    ("RCM_CLOUDFLARE_ZONE_ID", "zone"),
                    ("RCM_DNS_ZONE", "a.b"),
                ],
                "RCM_CLOUDFLARE_ZONE_ID",
            ),
            (vec![("RCM_CLOUDFLARE_TOKEN_FILE", "/absent")], "RCM_CLOUDFLARE_TOKEN_FILE"),
            (vec![("RCM_DNS_ZONE", "*.example.com")], "RCM_DNS_ZONE"),
            (vec![("RCM_PUBLIC_IPV4", "192.168.1.2")], "RCM_PUBLIC_IPV4"),
            (vec![("RCM_PUBLIC_IPV4", "2a01:e0a::1")], "RCM_PUBLIC_IPV4"),
            (vec![("RCM_PUBLIC_IPV6", "fd00::1")], "RCM_PUBLIC_IPV6"),
            (vec![("RCM_PUBLIC_IP_DETECT", "yes")], "RCM_PUBLIC_IP_DETECT"),
            (vec![("RCM_ROUTER_PORT", "80")], "RCM_ROUTER_PORT"),
            (vec![("RCM_ROUTER_PORT", "8580")], "RCM_ROUTER_PORT"),
            (vec![("RCM_ROUTER_PORT", "25565"), ("RCM_ROUTER_MAX_PER_IP", "0")], "RCM_ROUTER_MAX_PER_IP"),
            (vec![("RCM_ROUTER_PORT", "25565"), ("RCM_ROUTER_LISTEN", "partout")], "RCM_ROUTER_LISTEN"),
        ] {
            let e = load_env(&vars).unwrap_err();
            assert!(e.starts_with(var) && !e.contains(tok), "{vars:?} : {e}");
        }
        // Jeton au format douteux (espace, saut de ligne au milieu) : refusé sans être recopié.
        let bad = MapEnv::new(&[
            ("RCM_CLOUDFLARE_TOKEN_FILE", "/f"),
            ("RCM_CLOUDFLARE_ZONE_ID", zid),
            ("RCM_DNS_ZONE", "a.b"),
        ])
        .file("/f", "abc def ghi jkl mno pqr stu");
        let e = load(&args_in(&d), &bad).unwrap_err();
        assert!(e.starts_with("RCM_CLOUDFLARE_TOKEN_FILE") && !e.contains("abc"), "{e}");
        let c = load_env(&[
            ("RCM_PUBLIC_IPV4", "198.51.99.4"),
            ("RCM_PUBLIC_IPV6", "2a01:e0a::4"),
            ("RCM_PUBLIC_IP_DETECT", "false"),
            ("RCM_ROUTER_PORT", "25565"),
        ])
        .unwrap();
        assert_eq!(c.public_ipv4.unwrap().to_string(), "198.51.99.4");
        assert_eq!(c.public_ipv6.unwrap().to_string(), "2a01:e0a::4");
        assert!(!c.public_ip_detect);
        let r = c.router.unwrap();
        assert_eq!(
            (r.port, r.listen, r.max_per_ip, r.max_connections),
            (25565, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8, 1024)
        );
    }
}
