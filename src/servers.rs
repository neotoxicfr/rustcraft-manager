//! Serveurs pilotés : état en mémoire, opérations longues (une seule par serveur, objet versionné
//! poussé aux abonnés par `watch`), processus Java natifs supervisés.
//!
//! - lancement SANS shell, arguments passés un par un, environnement vidé puis liste blanche
//!   ([`crate::java::command`]) ; `-Xmx` pour la mémoire ; sous Windows, un objet Job « tuer à la
//!   fermeture » par serveur : si le gestionnaire meurt, le système ferme le Job et le serveur
//!   avec (aucun orphelin) ;
//! - arrêt propre : `stop` sur l'entrée standard, attente bornée, puis arrêt forcé ;
//! - plantage repéré (sortie non demandée et code non nul), redémarrage automatique optionnel
//!   (au plus 3 plantages en 10 minutes, sinon abandon et alerte) ;
//! - panne silencieuse : processus vivant mais port de jeu jamais ouvert → alerte ;
//! - état voulu (`desired_running`) en base : repris au redémarrage du gestionnaire ; à l'arrêt du
//!   gestionnaire, `save-all` puis `stop` de chaque serveur (l'état voulu reste) ;
//! - mesures (CPU, mémoire, joueurs, ticks) échantillonnées seulement quand quelqu'un regarde.

use crate::console::History;
use crate::db::{Db, now, write_tx};
use crate::download::Http;
use crate::error::AppError;
use crate::minecraft::{Catalog, Launch};
use crate::paths::{ServerId, server_dir};
use rc_manager_shared::*;
use rusqlite::{OptionalExtension, params};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::{Notify, broadcast, mpsc, watch};

/// Attente d'un arrêt propre avant l'arrêt forcé.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(90);
/// Délai au-delà duquel un port jamais ouvert est signalé (premier lancement : génération du monde).
pub const STARTUP_ALERT: Duration = Duration::from_secs(300);
/// Plantages tolérés dans la fenêtre avant d'abandonner le redémarrage automatique.
pub const CRASH_LIMIT: usize = 3;
pub const CRASH_WINDOW: Duration = Duration::from_secs(600);
/// Attente avant un redémarrage automatique.
pub const RESTART_DELAY: Duration = Duration::from_secs(10);
/// Bornes des ressources (configuration : `max_servers`, `max_memory_mb`, `max_installs`).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_servers: usize,
    /// Mémoire de tous les serveurs ensemble, en Mio (0 : pas de borne).
    pub max_memory_mb: u64,
    pub max_installs: usize,
    /// Port tenu par le gestionnaire lui-même (aiguilleur) : jamais donné à un serveur.
    pub reserved_port: Option<u16>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_servers: 32, max_memory_mb: 0, max_installs: 2, reserved_port: None }
    }
}

/// Délais du pilotage (réglables pour les tests).
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub stop_timeout: Duration,
    pub startup_alert: Duration,
    pub restart_delay: Duration,
    /// Processeur et mémoire, tant que quelqu'un regarde.
    pub sample_every: Duration,
    /// Joueurs et ticks par l'entrée standard (`list`, `tick query`, `mspt`, `tps`).
    pub probe_every: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Timings {
            stop_timeout: STOP_TIMEOUT,
            startup_alert: STARTUP_ALERT,
            restart_delay: RESTART_DELAY,
            sample_every: Duration::from_secs(2),
            probe_every: Duration::from_secs(10),
        }
    }
}

/// Ports RCON attribués automatiquement.
pub const RCON_PORTS: std::ops::RangeInclusive<u16> = 25575..=25775;
/// Ligne de sortie la plus longue lue d'un coup (au-delà : coupée).
const READ_LINE_MAX: usize = 64 * 1024;

/// Configuration d'un serveur (copie de sa ligne en base, mot de passe RCON déchiffré).
#[derive(Clone, Debug)]
pub struct Row {
    pub id: ServerId,
    pub name: String,
    pub software: Software,
    pub version: String,
    pub build: Option<String>,
    pub memory_mb: u32,
    pub port: u16,
    pub rcon_port: u16,
    pub rcon_password: String,
    pub java_major: u32,
    pub java_path: Option<String>,
    pub launch: Option<Launch>,
    pub auto_restart: bool,
    pub desired_running: bool,
    pub eula: bool,
}

#[derive(Debug)]
struct Rt {
    state: ServerState,
    op: Option<OperationInfo>,
    alert: Option<ServerAlert>,
    error: Option<ErrorCode>,
    refusal: Option<rc_manager_shared::LaunchRefusal>,
    started_at: Option<i64>,
    players: Vec<PlayerInfo>,
    max_players: u32,
    stop_requested: bool,
    crashes: VecDeque<Instant>,
    /// Fenêtre où les réponses aux mesures (`list`, ticks) sont lues et retirées de la console.
    probe_until: Option<Instant>,
    tps: Option<f32>,
    mspt: Option<f32>,
}

struct Proc {
    stdin: tokio::process::ChildStdin,
    pid: u32,
    kill: Arc<Notify>,
    #[cfg(windows)]
    _job: Option<win32job::Job>,
}

/// Ce qu'un abonné (WebSocket) reçoit d'un serveur suivi.
#[derive(Clone, Debug)]
pub enum ServerEvent {
    Line(Arc<ConsoleLine>),
    Players(Arc<Vec<PlayerInfo>>),
    Stats(ServerStats),
}

pub struct Server {
    pub id: ServerId,
    pub dir: PathBuf,
    row: Mutex<Row>,
    rt: Mutex<Rt>,
    proc: tokio::sync::Mutex<Option<Proc>>,
    history: Mutex<History>,
    pub events: broadcast::Sender<ServerEvent>,
    watchers: AtomicUsize,
    sampling: AtomicBool,
    /// Génération : augmentée par un arrêt ou une suppression (annule une relance en attente).
    generation: AtomicU64,
    /// Compteur de sorties du processus (attente d'un arrêt).
    exits: watch::Sender<u64>,
}

pub struct Manager {
    pub data: PathBuf,
    pub db: Db,
    pub catalog: Catalog,
    pub languages: crate::lang::Languages,
    servers: RwLock<BTreeMap<ServerId, Arc<Server>>>,
    /// Version de la liste : augmentée à chaque changement d'un serveur.
    pub changed: watch::Sender<u64>,
    next_op: AtomicU64,
    shutting_down: AtomicBool,
    /// Création en cours (ports et noms vérifiés puis réservés en une fois).
    create_lock: tokio::sync::Mutex<()>,
    timings: Mutex<Timings>,
    limits: Mutex<Limits>,
    installs: tokio::sync::Semaphore,
}

/// Opération en cours : rendue (et l'état publié) en sortant de portée.
pub struct OpGuard {
    srv: Arc<Server>,
    mgr: Arc<Manager>,
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.srv.rt.lock().unwrap_or_else(|p| p.into_inner()).op = None;
        self.mgr.bump();
    }
}

impl OpGuard {
    pub fn step(&self, step: OpStep, done: Option<u64>, total: Option<u64>) {
        {
            let mut rt = self.srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(op) = rt.op.as_mut() {
                op.step = step;
                op.done = done;
                op.total = total;
            }
        }
        self.mgr.bump();
    }
}

/// Le suivi d'un serveur par un abonné ; rendu en sortant de portée.
pub struct WatchGuard {
    srv: Arc<Server>,
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        self.srv.watchers.fetch_sub(1, Ordering::AcqRel);
    }
}

fn row_from(r: &rusqlite::Row<'_>, keys: &crate::crypto::Keys) -> rusqlite::Result<Option<Row>> {
    let id: i64 = r.get("id")?;
    let Some(sid) = ServerId::from_db(id) else { return Ok(None) };
    let sw: String = r.get("software")?;
    let Some(software) = Software::from_code(&sw) else { return Ok(None) };
    let enc: String = r.get("rcon_password_enc")?;
    let Ok(pw) = keys.decrypt(&crate::crypto::aad("servers", "rcon_password", id), &enc) else {
        tracing::error!("serveur {id} : mot de passe RCON indéchiffrable");
        return Ok(None);
    };
    let launch: Option<String> = r.get("launch")?;
    Ok(Some(Row {
        id: sid,
        name: r.get("name")?,
        software,
        version: r.get("game_version")?,
        build: r.get("build")?,
        memory_mb: r.get("memory_mb")?,
        port: r.get::<_, i64>("port")? as u16,
        rcon_port: r.get::<_, i64>("rcon_port")? as u16,
        rcon_password: String::from_utf8_lossy(&pw).into_owned(),
        java_major: r.get("java_major")?,
        java_path: r.get("java_path")?,
        launch: launch.and_then(|l| serde_json::from_str(&l).ok()),
        auto_restart: r.get("auto_restart")?,
        desired_running: r.get("desired_running")?,
        eula: r.get::<_, Option<i64>>("eula_accepted_at")?.is_some(),
    }))
}

/// Port libre sur la machine (toutes les interfaces et la boucle locale).
pub fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Fenêtre où les réponses aux mesures sont attendues (et retirées de la console).
pub const PROBE_WINDOW: Duration = Duration::from_millis(1500);

/// Réponse reconnue à une commande de mesure.
#[derive(Debug, PartialEq)]
pub enum Probe {
    List {
        max: u32,
        names: Vec<String>,
    },
    Mspt(f32),
    Tps(f32),
    /// Autre ligne de la même réponse (« The game is running normally »…).
    Other,
}

/// Ligne de réponse à `list`, `tick query` (vanilla 1.20.3+), `mspt` ou `tps` (Paper) ?
pub fn probe_response(raw: &str) -> Option<Probe> {
    let text = crate::rcon::strip_colors(&crate::console::clean(raw));
    let msg = match text.find("]: ") {
        Some(i) if text.starts_with('[') => &text[i + 3..],
        _ => text.as_str(),
    };
    let msg = msg.strip_prefix("System chat: ").unwrap_or(msg).trim();
    if msg.starts_with("There are ") && msg.contains("players online") {
        let (_, max, names) = crate::rcon::parse_list(msg)?;
        return Some(Probe::List { max, names });
    }
    if msg.starts_with("Average time per tick: ") {
        return crate::rcon::parse_mspt(msg).map(Probe::Mspt);
    }
    if msg.starts_with("TPS from last") {
        return crate::rcon::parse_tps(msg).map(Probe::Tps);
    }
    if let Some(rest) = msg.strip_prefix('◴') {
        let avg = rest.trim().split('/').next()?.trim();
        return avg.parse().ok().map(Probe::Mspt);
    }
    const OTHER: [&str; 6] = [
        "The game is running normally",
        "The game is frozen",
        "The game is sprinting",
        "Target tick rate: ",
        "Percentiles: ",
        "Server tick times",
    ];
    OTHER.iter().any(|p| msg.starts_with(p)).then_some(Probe::Other)
}

/// Lit une ligne (jusqu'à `\n`) d'au plus `max` octets ; au-delà, le reste de la ligne est sauté.
async fn read_line_bounded<R: AsyncBufRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, max: usize) -> std::io::Result<bool> {
    buf.clear();
    let mut overflow = false;
    loop {
        let avail = r.fill_buf().await?;
        if avail.is_empty() {
            return Ok(!buf.is_empty() || overflow);
        }
        let (take, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        if !overflow {
            let room = max.saturating_sub(buf.len());
            buf.extend_from_slice(&avail[..take.min(room)]);
            if take > room {
                overflow = true;
            }
        }
        r.consume(take);
        if done {
            return Ok(true);
        }
    }
}

/// Serveurs supprimés gardés ce nombre de jours dans la corbeille.
pub const TRASH_DAYS: u64 = 30;

/// Au démarrage : extractions et téléchargements de Java interrompus (un plantage pendant
/// l'installation les laisse), serveurs de la corbeille plus vieux que [`TRASH_DAYS`] ; dans chaque
/// serveur, envois interrompus et corbeille du gestionnaire de fichiers ([`sweep_servers`]).
pub fn cleanup(data: &Path, now: std::time::SystemTime) {
    sweep_servers(data, now, None);
    if let Ok(rd) = std::fs::read_dir(data.join("java")) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(".extract-") {
                let _ = std::fs::remove_dir_all(e.path());
            } else if n.starts_with(".download-") || (n.starts_with('.') && n.ends_with(".part")) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let keep = Duration::from_secs(TRASH_DAYS * 86_400);
    if let Ok(rd) = std::fs::read_dir(data.join("trash")) {
        for e in rd.flatten() {
            let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| now.duration_since(t).ok());
            if old.is_some_and(|age| age > keep) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

/// Entretien des dossiers de serveurs (démarrage, puis toutes les heures) : corbeille du
/// gestionnaire de fichiers purgée (durée et quotas), envois interrompus effacés (tous au
/// démarrage, `uploads_older_than` ensuite : un envoi peut être en cours) ; au démarrage
/// seulement (`uploads_older_than = None`), restes d'un plantage ([`crate::files::sweep_startup`]).
pub fn sweep_servers(data: &Path, now: std::time::SystemTime, uploads_older_than: Option<Duration>) {
    let secs = now.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let Ok(rd) = std::fs::read_dir(data.join("servers")) else { return };
    for e in rd.flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            crate::files::sweep_uploads(&e.path(), uploads_older_than);
            if uploads_older_than.is_none() {
                crate::files::sweep_startup(&e.path());
            }
            crate::files::trash_prune(&e.path(), secs, None, true);
        }
    }
}

/// Entretien périodique : [`sweep_servers`] toutes les heures, tant que le gestionnaire vit.
fn spawn_sweeper(data: PathBuf, alive: std::sync::Weak<Manager>) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
    rt.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        tick.tick().await;
        loop {
            tick.tick().await;
            if alive.strong_count() == 0 {
                break;
            }
            let data = data.clone();
            let day = Some(Duration::from_secs(86_400));
            // Sous le verrou des enregistrements (tenu par le fil) : jamais en même temps qu'une
            // mise à la corbeille, une restauration ou un effacement.
            let lock = crate::configs_api::SAVE_LOCK.lock().await;
            let _ = tokio::task::spawn_blocking(move || {
                let _lock = lock;
                sweep_servers(&data, std::time::SystemTime::now(), day)
            })
            .await;
        }
    });
}

/// EULA : `eula.txt` écrit SEULEMENT après l'acceptation d'un utilisateur (enregistrée en base
/// avec son compte et l'instant). Aucun autre chemin du code n'écrit ce fichier.
fn write_eula_accepted_by_user(dir: &Path) -> std::io::Result<()> {
    let text = "# EULA de Mojang (https://aka.ms/MinecraftEULA) acceptée dans Rustcraft Manager par un utilisateur.\neula=true\n";
    crate::fsutil::write_atomic(&dir.join("eula.txt"), text.as_bytes()).map(|_| ())
}

/// `level-name` ou `settings.restart-script` (Spigot et dérivés) qui sortent du dossier du
/// serveur, posés hors du gestionnaire : lancement refusé. Fichier présent mais illisible pour le
/// gestionnaire (trop grand, pas du texte, arbre non représentable) : refusé aussi, rien ne
/// pouvant être vérifié ; absent : rien à vérifier. Rend le fichier et la cause (affichés sur la
/// carte du serveur).
pub fn launch_refusal(dir: &Path) -> Option<rc_manager_shared::LaunchRefusal> {
    use rc_manager_shared::{ConfigFormat, LaunchCause, LaunchRefusal};
    [("server.properties", ConfigFormat::Properties), ("spigot.yml", ConfigFormat::Yaml)].into_iter().find_map(
        |(rel, f)| {
            let p = dir.join(rel);
            if std::fs::symlink_metadata(&p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
                return None;
            }
            let (cause, key) = match crate::configs::read(&p, f) {
                Ok((_, t)) => {
                    let key = crate::configs::unsafe_value(f, rel, &t)?;
                    match crate::configs::unverifiable(f, &t) {
                        Some(u) => (LaunchCause::Unverifiable(u), None),
                        None => (LaunchCause::UnsafeValue, Some(key)),
                    }
                }
                Err(_) => (LaunchCause::Unreadable, None),
            };
            Some(LaunchRefusal { file: rel.to_string(), cause, key })
        },
    )
}

pub fn launch_paths_unsafe(dir: &Path) -> bool {
    launch_refusal(dir).is_some()
}

impl Server {
    fn new(row: Row, data: &Path) -> Arc<Server> {
        let dir = server_dir(data, row.id);
        let state = if row.launch.is_some() { ServerState::Stopped } else { ServerState::NotInstalled };
        let max_players = crate::props::get(&crate::files::server_properties(&dir), "max-players")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        Arc::new(Server {
            id: row.id,
            history: Mutex::new(History::open(&dir)),
            dir,
            row: Mutex::new(row),
            rt: Mutex::new(Rt {
                state,
                op: None,
                alert: None,
                error: None,
                refusal: None,
                started_at: None,
                players: Vec::new(),
                max_players,
                stop_requested: false,
                crashes: VecDeque::new(),
                probe_until: None,
                tps: None,
                mspt: None,
            }),
            proc: tokio::sync::Mutex::new(None),
            events: broadcast::channel(512).0,
            watchers: AtomicUsize::new(0),
            sampling: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            exits: watch::channel(0).0,
        })
    }

    /// Adresse locale du jeu : `server-ip` si elle est posée (et précise), sinon la boucle
    /// locale ; port du serveur. Vérification « en marche » et aiguilleur.
    pub fn local_game_addr(&self) -> std::net::SocketAddr {
        let ip: std::net::IpAddr = crate::props::get(&crate::files::server_properties(&self.dir), "server-ip")
            .and_then(|v| v.parse().ok())
            .filter(|ip: &std::net::IpAddr| !ip.is_unspecified())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        std::net::SocketAddr::new(ip, self.row().port)
    }

    pub fn row(&self) -> Row {
        self.row.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn state(&self) -> ServerState {
        self.rt.lock().unwrap_or_else(|p| p.into_inner()).state
    }

    pub fn info(&self) -> ServerInfo {
        let row = self.row();
        let rt = self.rt.lock().unwrap_or_else(|p| p.into_inner());
        ServerInfo {
            id: row.id.get(),
            name: row.name,
            software: row.software,
            version: row.version,
            state: rt.state,
            port: row.port,
            memory_mb: row.memory_mb,
            auto_restart: row.auto_restart,
            java: row.java_path.map_or(JavaChoice::Managed, |path| JavaChoice::Path { path }),
            java_major: row.java_major,
            eula: row.eula,
            started_at: rt.started_at,
            op: rt.op.clone(),
            alert: rt.alert,
            error: rt.error,
            refusal: rt.refusal.clone().filter(|_| rt.error == Some(ErrorCode::LaunchRefused)),
            players: rt.players.len() as u32,
            max_players: rt.max_players,
        }
    }

    pub fn players(&self) -> Vec<PlayerInfo> {
        self.rt.lock().unwrap_or_else(|p| p.into_inner()).players.clone()
    }

    pub fn history(&self, n: usize, before: Option<u64>) -> Vec<ConsoleLine> {
        self.history.lock().unwrap_or_else(|p| p.into_inner()).tail(n, before)
    }

    /// Ajoute une ligne à la console (historique, abonnés) et applique ses effets.
    fn line(&self, source: LineSource, text: &str, event: Option<ConsoleEvent>) -> Arc<ConsoleLine> {
        let line = Arc::new(self.history.lock().unwrap_or_else(|p| p.into_inner()).push(source, text, event));
        let _ = self.events.send(ServerEvent::Line(line.clone()));
        line
    }

    fn note(&self, what: ManagerNote) {
        let text = match what {
            ManagerNote::Starting => "[Rustcraft Manager] démarrage",
            ManagerNote::Stopped => "[Rustcraft Manager] arrêté",
            ManagerNote::Crashed => "[Rustcraft Manager] arrêt inattendu",
            ManagerNote::Killed => "[Rustcraft Manager] arrêt forcé",
            ManagerNote::AutoRestart => "[Rustcraft Manager] redémarrage automatique",
            ManagerNote::PortNeverOpened => "[Rustcraft Manager] port de jeu toujours fermé",
        };
        self.line(LineSource::Manager, text, Some(ConsoleEvent::Manager { what }));
    }

    fn publish_players(&self) {
        let p = Arc::new(self.players());
        let _ = self.events.send(ServerEvent::Players(p));
    }

    pub async fn pid(&self) -> Option<u32> {
        self.proc.lock().await.as_ref().map(|p| p.pid)
    }

    /// Écrit une ligne sur l'entrée standard du serveur.
    pub async fn send_stdin(&self, cmd: &str) -> Result<(), AppError> {
        let mut g = self.proc.lock().await;
        let p = g.as_mut().ok_or_else(|| AppError::conflict(ErrorCode::NotRunning))?;
        let mut b = cmd.as_bytes().to_vec();
        b.push(b'\n');
        p.stdin.write_all(&b).await.map_err(|_| AppError::conflict(ErrorCode::NotRunning))?;
        p.stdin.flush().await.map_err(|_| AppError::conflict(ErrorCode::NotRunning))
    }
}

/// Commande acceptée : non vide, bornée, sans caractère de contrôle (une seule ligne).
/// Arguments de la JVM placés avant ceux du logiciel (`-jar …`, classe principale).
pub fn jvm_args(memory_mb: u32, tmp: &Path, linux: bool) -> Vec<String> {
    let mut a = vec![
        format!("-Xmx{memory_mb}M"),
        // Java ignore TMPDIR sous Linux : dossier temporaire du serveur donné explicitement.
        format!("-Djava.io.tmpdir={}", tmp.display()),
        "-Djava.awt.headless=true".into(),
        "-Dfile.encoding=UTF-8".into(),
        "-Dstdout.encoding=UTF-8".into(),
        "-Dstderr.encoding=UTF-8".into(),
    ];
    if linux {
        // OSHI (bibliothèque de Paper et de ses dérivés) tente de charger libudev, absente de
        // l'image distroless : avertissement « Did not find udev library » à chaque démarrage.
        // Réglage prévu par OSHI (oshi.properties ; ses propriétés système `oshi.*` priment) :
        // replis sysfs, aucune tentative de chargement. Aucun serveur n'a besoin de udev.
        a.push("-Doshi.os.linux.allowudev=false".into());
    }
    a
}

/// Processeur d'un processus en % de la machine (0 à 100) à partir de la mesure par cœur
/// (somme des cœurs, jusqu'à 100 × cœurs) ; `cores` : cœurs disponibles pour le gestionnaire
/// (quota cgroup et affinité compris).
pub fn cpu_machine_percent(per_core: f32, cores: f32) -> f32 {
    if !per_core.is_finite() || !cores.is_finite() {
        return 0.0;
    }
    let cores = if cores > 0.0 { cores } else { 1.0 };
    (per_core / cores).clamp(0.0, 100.0)
}

/// Quota cgroup v2 (`cpu.max` : `150000 100000` → 1,5 cœur ; `max …` : aucun).
pub fn parse_cpu_max(s: &str) -> Option<f32> {
    let mut it = s.split_whitespace();
    let (q, p) = (it.next()?, it.next().unwrap_or("100000"));
    let (q, p) = (q.parse::<f64>().ok()?, p.parse::<f64>().ok()?);
    (q > 0.0 && p > 0.0).then(|| (q / p) as f32)
}

/// Quota cgroup v1 (`cpu.cfs_quota_us`, `cpu.cfs_period_us` ; `-1` : aucun).
pub fn parse_cfs(quota: &str, period: &str) -> Option<f32> {
    let (q, p) = (quota.trim().parse::<f64>().ok()?, period.trim().parse::<f64>().ok()?);
    (q > 0.0 && p > 0.0).then(|| (q / p) as f32)
}

fn cgroup_quota() -> Option<f32> {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    read("/sys/fs/cgroup/cpu.max").and_then(|s| parse_cpu_max(&s)).or_else(|| {
        parse_cfs(&read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")?, &read("/sys/fs/cgroup/cpu/cpu.cfs_period_us")?)
    })
}

/// Cœurs disponibles pour le gestionnaire, fractionnaires : quota cgroup v1/v2 lu tel quel (1,5
/// et non 2 comme l'arrondi de la bibliothèque standard), borné par l'affinité. Relu toutes les
/// 30 s (un quota changé à chaud est suivi).
pub fn available_cores() -> f32 {
    static CACHE: std::sync::Mutex<Option<(std::time::Instant, f32)>> = std::sync::Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((t, v)) = *c
        && t.elapsed() < std::time::Duration::from_secs(30)
    {
        return v;
    }
    let affinity = std::thread::available_parallelism().map_or(1, |n| n.get()) as f32;
    let v = cgroup_quota().map_or(affinity, |q| q.min(affinity)).max(0.01);
    *c = Some((std::time::Instant::now(), v));
    v
}

pub fn command_ok(cmd: &str) -> bool {
    let c = cmd.trim();
    !c.is_empty() && c.len() <= COMMAND_MAX && !c.chars().any(char::is_control)
}

impl Manager {
    /// Charge les serveurs de la base.
    pub fn load(db: Db, data: PathBuf, http: Http, limits: Limits) -> Arc<Manager> {
        let rows: Vec<Row> = db.with(|c| {
            let keys = db.keys();
            let mut s = match c.prepare("SELECT * FROM servers ORDER BY id") {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("serveurs : {e}");
                    return Vec::new();
                }
            };
            s.query_map([], |r| row_from(r, keys))
                .map(|it| it.filter_map(|r| r.ok().flatten()).collect())
                .unwrap_or_default()
        });
        cleanup(&data, std::time::SystemTime::now());
        let map = rows.into_iter().map(|r| (r.id, Server::new(r, &data))).collect();
        let sweep_dir = data.clone();
        let mgr = Arc::new(Manager {
            data,
            db,
            catalog: Catalog::new(http),
            languages: Default::default(),
            servers: RwLock::new(map),
            changed: watch::channel(0).0,
            next_op: AtomicU64::new(1),
            shutting_down: AtomicBool::new(false),
            create_lock: tokio::sync::Mutex::new(()),
            timings: Mutex::new(Timings::default()),
            installs: tokio::sync::Semaphore::new(limits.max_installs.max(1)),
            limits: Mutex::new(limits),
        });
        spawn_sweeper(sweep_dir, Arc::downgrade(&mgr));
        mgr
    }

    pub fn limits(&self) -> Limits {
        *self.limits.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Bornes (tests).
    pub fn set_limits(&self, l: Limits) {
        *self.limits.lock().unwrap_or_else(|p| p.into_inner()) = l;
    }

    /// Mémoire totale des serveurs (`except` compté avec `mb` au lieu de sa valeur) sous la borne.
    fn check_memory(&self, mb: u32, except: Option<ServerId>) -> Result<(), AppError> {
        let max = self.limits().max_memory_mb;
        let others: u64 = self.all().iter().filter(|s| Some(s.id) != except).map(|s| s.row().memory_mb as u64).sum();
        if max > 0 && others + mb as u64 > max {
            return Err(AppError::conflict(ErrorCode::LimitReached));
        }
        Ok(())
    }

    pub fn timings(&self) -> Timings {
        *self.timings.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Délais du pilotage (tests : arrêts et redémarrages en quelques secondes).
    pub fn set_timings(&self, t: Timings) {
        *self.timings.lock().unwrap_or_else(|p| p.into_inner()) = t;
    }

    pub fn bump(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn list(&self) -> Vec<ServerInfo> {
        self.servers.read().unwrap_or_else(|p| p.into_inner()).values().map(|s| s.info()).collect()
    }

    pub fn get(&self, id: ServerId) -> Option<Arc<Server>> {
        self.servers.read().unwrap_or_else(|p| p.into_inner()).get(&id).cloned()
    }

    fn all(&self) -> Vec<Arc<Server>> {
        self.servers.read().unwrap_or_else(|p| p.into_inner()).values().cloned().collect()
    }

    /// Dossier temporaire des processus enfants (sonde de Java).
    pub fn tmp(&self) -> PathBuf {
        self.data.join("tmp")
    }

    /// Commence une opération (409 si une autre est en cours sur ce serveur).
    pub fn begin(self: &Arc<Self>, srv: &Arc<Server>, kind: OpKind) -> Result<OpGuard, AppError> {
        let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
        if rt.op.is_some() {
            return Err(AppError::conflict(ErrorCode::OperationInProgress));
        }
        let id = self.next_op.fetch_add(1, Ordering::Relaxed);
        rt.op = Some(OperationInfo { id, kind, step: OpStep::Resolve, done: None, total: None });
        drop(rt);
        self.bump();
        Ok(OpGuard { srv: srv.clone(), mgr: self.clone() })
    }

    /// Port pris par un autre serveur du gestionnaire (jeu ou RCON) ?
    fn port_taken(&self, port: u16, except: Option<ServerId>) -> bool {
        if self.limits().reserved_port == Some(port) {
            return true;
        }
        self.all().iter().filter(|s| Some(s.id) != except).any(|s| {
            let r = s.row();
            r.port == port || r.rcon_port == port
        })
    }

    fn pick_rcon_port(&self, game_port: u16) -> Option<u16> {
        RCON_PORTS.clone().find(|&p| p != game_port && !self.port_taken(p, None) && port_free(p))
    }

    /// Création : validations, ligne en base (mot de passe RCON chiffré), dossier, EULA si
    /// l'utilisateur l'a cochée, puis installation en tâche de fond.
    pub async fn create(
        self: &Arc<Self>,
        req: CreateServerRequest,
        user_id: i64,
        is_admin: bool,
    ) -> Result<ServerInfo, AppError> {
        let name = req.name.trim().to_string();
        if !server_name_valid(&name) {
            return Err(AppError::unprocessable(ErrorCode::InvalidName));
        }
        if !(MEMORY_MIN_MB..=MEMORY_MAX_MB).contains(&req.memory_mb) {
            return Err(AppError::unprocessable(ErrorCode::InvalidMemory));
        }
        if req.port < PORT_MIN {
            return Err(AppError::unprocessable(ErrorCode::InvalidPort));
        }
        if !crate::paths::version_valid(&req.version) {
            return Err(AppError::unprocessable(ErrorCode::InvalidVersion));
        }
        let java_path = self.check_java_choice(&req.java, is_admin).await?;
        let versions = self.catalog.versions(req.software).await.map_err(|e| {
            tracing::warn!("versions de {} : {e}", req.software.code());
            AppError::new(axum::http::StatusCode::BAD_GATEWAY, e.code())
        })?;
        if !versions.iter().any(|v| v.id == req.version) {
            return Err(AppError::unprocessable(ErrorCode::InvalidVersion));
        }
        let _g = self.create_lock.lock().await;
        if self.all().len() >= self.limits().max_servers {
            return Err(AppError::conflict(ErrorCode::LimitReached));
        }
        self.check_memory(req.memory_mb, None)?;
        if self.port_taken(req.port, None) || !port_free(req.port) {
            return Err(AppError::conflict(ErrorCode::PortInUse));
        }
        let rcon_port = self.pick_rcon_port(req.port).ok_or_else(|| AppError::conflict(ErrorCode::PortInUse))?;
        let password = crate::rcon::new_password();
        let (sw, ver, mem, port, eula) = (req.software, req.version.clone(), req.memory_mb, req.port, req.accept_eula);
        let pw2 = password.clone();
        let name2 = name.clone();
        let jp = java_path.clone();
        let id = self
            .db
            .call(move |c, keys| {
                let tx = write_tx(c)?;
                tx.execute(
                    "INSERT INTO servers (name, software, game_version, memory_mb, port, rcon_port, rcon_password_enc,
                      java_major, java_path, auto_restart, desired_running, eula_accepted_at, eula_accepted_by, created_at, created_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', 0, ?7, 0, 0, ?8, ?9, ?10, ?11)",
                    params![
                        name2,
                        sw.code(),
                        ver,
                        mem,
                        port,
                        rcon_port,
                        jp,
                        eula.then(now),
                        eula.then_some(user_id),
                        now(),
                        user_id
                    ],
                )?;
                let id = tx.last_insert_rowid();
                let enc = keys.encrypt(&crate::crypto::aad("servers", "rcon_password", id), pw2.as_bytes());
                tx.execute("UPDATE servers SET rcon_password_enc = ?1 WHERE id = ?2", params![enc, id])?;
                tx.commit()?;
                Ok(id)
            })
            .await?;
        let sid = ServerId::from_db(id).ok_or_else(AppError::internal)?;
        let row = Row {
            id: sid,
            name,
            software: sw,
            version: req.version,
            build: None,
            memory_mb: mem,
            port,
            rcon_port,
            rcon_password: password,
            java_major: 0,
            java_path,
            launch: None,
            auto_restart: false,
            desired_running: false,
            eula,
        };
        let srv = Server::new(row, &self.data);
        // Dossier et fichiers : un échec efface la ligne et le dossier (création tout ou rien).
        let files = (|| {
            std::fs::create_dir_all(&srv.dir)?;
            if eula {
                write_eula_accepted_by_user(&srv.dir)?;
            }
            self.write_properties(&srv, true)
        })();
        if let Err(e) = files {
            tracing::error!("{} : {e}", srv.dir.display());
            let _ = std::fs::remove_dir_all(&srv.dir);
            let _ = self
                .db
                .call(move |c, _| {
                    c.execute("DELETE FROM servers WHERE id = ?1", [id])?;
                    Ok(())
                })
                .await;
            return Err(AppError::internal());
        }
        self.servers.write().unwrap_or_else(|p| p.into_inner()).insert(sid, srv.clone());
        drop(_g);
        let guard = self.begin(&srv, OpKind::Install)?;
        let mgr = self.clone();
        let s2 = srv.clone();
        tokio::spawn(async move { mgr.install(s2, guard).await });
        Ok(srv.info())
    }

    async fn check_java_choice(&self, j: &JavaChoice, is_admin: bool) -> Result<Option<String>, AppError> {
        match j {
            JavaChoice::Managed => Ok(None),
            JavaChoice::Path { path } => {
                // Un chemin d'exécutable : administrateurs seulement.
                if !is_admin {
                    return Err(AppError::new(axum::http::StatusCode::FORBIDDEN, ErrorCode::Forbidden));
                }
                let (p, _) = crate::java::validate_custom(path, &self.tmp())
                    .await
                    .ok_or_else(|| AppError::unprocessable(ErrorCode::JavaNotFound))?;
                Ok(Some(p.to_string_lossy().into_owned()))
            }
        }
    }

    /// Clés de `server.properties` tenues par le gestionnaire (ports, RCON). `first` : valeurs
    /// initiales d'un serveur neuf en plus.
    fn write_properties(&self, srv: &Server, first: bool) -> std::io::Result<()> {
        let r = srv.row();
        // RCON coupé et sans mot de passe : le jeu l'ouvrirait sur `server-ip`, donc sur toutes les
        // interfaces par défaut (lu dans RconThread de la 26.3) ; mesures par l'entrée standard.
        let mut u: Vec<(&str, String)> = vec![
            ("server-port", r.port.to_string()),
            // Requête GameSpy4 (UDP) sur le port du jeu : deux serveurs ne se disputent jamais
            // le 25565 par défaut si l'un l'active.
            ("query.port", r.port.to_string()),
            ("enable-rcon", "false".into()),
            ("rcon.password", String::new()),
            // Serveur de gestion JSON-RPC (26.x) : pilotage complet du serveur ; coupé (une
            // adresse `0.0.0.0` l'ouvrirait au réseau). Clé ignorée par les versions plus anciennes.
            ("management-server-enabled", "false".into()),
        ];
        if first {
            u.push(("motd", crate::props::escape_value(&r.name)));
        }
        crate::props::patch_file(&srv.dir.join("server.properties"), &u)
    }

    async fn install(self: Arc<Self>, srv: Arc<Server>, guard: OpGuard) {
        // Installations simultanées bornées (téléchargements de dizaines de Mo chacune).
        let _permit = self.installs.acquire().await;
        let row = srv.row();
        srv.rt.lock().unwrap_or_else(|p| p.into_inner()).error = None;
        let progress = |step: OpStep, d: u64, t: Option<u64>| guard.step(step, Some(d), t);
        match self.catalog.install(row.software, &row.version, &srv.dir, &progress).await {
            Ok(inst) => {
                let launch = serde_json::to_string(&inst.launch).unwrap_or_default();
                let (id, major, build) = (row.id.get(), inst.java_major, inst.build.clone());
                let r = self
                    .db
                    .call(move |c, _| {
                        c.execute(
                            "UPDATE servers SET launch = ?1, java_major = ?2, build = ?3 WHERE id = ?4",
                            params![launch, major, build, id],
                        )?;
                        Ok(())
                    })
                    .await;
                if r.is_ok() {
                    {
                        let mut rw = srv.row.lock().unwrap_or_else(|p| p.into_inner());
                        rw.launch = Some(inst.launch);
                        rw.java_major = inst.java_major;
                        rw.build = inst.build;
                    }
                    let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
                    rt.state = ServerState::Stopped;
                    rt.alert = None;
                }
            }
            Err(e) => {
                tracing::warn!("serveur {} : installation impossible : {e}", row.id);
                let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
                rt.state = ServerState::NotInstalled;
                rt.alert = Some(ServerAlert::Failed);
                rt.error = Some(e.code());
            }
        }
        drop(guard);
    }

    /// Relance l'installation d'un serveur qui n'est pas installé.
    pub fn reinstall(self: &Arc<Self>, srv: &Arc<Server>) -> Result<(), AppError> {
        if srv.state() != ServerState::NotInstalled {
            return Err(AppError::conflict(ErrorCode::OperationInProgress));
        }
        let guard = self.begin(srv, OpKind::Install)?;
        let mgr = self.clone();
        let s2 = srv.clone();
        tokio::spawn(async move { mgr.install(s2, guard).await });
        Ok(())
    }

    /// L'utilisateur coche l'EULA : enregistrée (compte, instant) puis `eula.txt` écrit.
    pub async fn accept_eula(&self, srv: &Arc<Server>, user_id: i64) -> Result<(), AppError> {
        let id = srv.id.get();
        self.db
            .call(move |c, _| {
                c.execute(
                    "UPDATE servers SET eula_accepted_at = ?1, eula_accepted_by = ?2 WHERE id = ?3",
                    params![now(), user_id, id],
                )?;
                Ok(())
            })
            .await?;
        write_eula_accepted_by_user(&srv.dir).map_err(|_| AppError::internal())?;
        srv.row.lock().unwrap_or_else(|p| p.into_inner()).eula = true;
        self.bump();
        Ok(())
    }

    async fn set_desired(&self, srv: &Server, on: bool) {
        let id = srv.id.get();
        srv.row.lock().unwrap_or_else(|p| p.into_inner()).desired_running = on;
        let _ = self
            .db
            .call(move |c, _| {
                c.execute("UPDATE servers SET desired_running = ?1 WHERE id = ?2", params![on, id])?;
                Ok(())
            })
            .await;
    }

    /// Contrôles rapides avant un démarrage (réponse immédiate à l'utilisateur).
    fn precheck_start(&self, srv: &Server) -> Result<(), AppError> {
        let row = srv.row();
        if row.launch.is_none() {
            return Err(AppError::conflict(ErrorCode::NotInstalled));
        }
        if !row.eula {
            return Err(AppError::conflict(ErrorCode::EulaRequired));
        }
        if matches!(srv.state(), ServerState::Stopped | ServerState::Crashed)
            && (self.port_taken(row.port, Some(row.id)) || !port_free(row.port))
        {
            return Err(AppError::conflict(ErrorCode::PortInUse));
        }
        Ok(())
    }

    /// Démarrage demandé par un utilisateur (ou par la reprise) : contrôles, puis en tâche de
    /// fond Java (téléchargé au besoin) et lancement ; l'état voulu est enregistré. L'opération
    /// se termine une fois le processus lancé (l'attente du port se lit dans l'état `starting`).
    pub fn start(self: &Arc<Self>, srv: &Arc<Server>) -> Result<(), AppError> {
        self.precheck_start(srv)?;
        let guard = self.begin(srv, OpKind::Start)?;
        let (mgr, s2) = (self.clone(), srv.clone());
        tokio::spawn(async move {
            if let Err(e) = mgr.start_with(&s2, &guard).await {
                tracing::warn!("serveur {} : démarrage impossible ({:?})", s2.id, e.code);
            }
            drop(guard);
        });
        Ok(())
    }

    /// Lancement, futur en boîte : le redémarrage automatique (dans la supervision lancée par
    /// `launch`) rappelle cette fonction, un type explicite coupe le cycle de types.
    fn start_with<'a>(
        self: &'a Arc<Self>,
        srv: &'a Arc<Server>,
        guard: &'a OpGuard,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            if matches!(srv.state(), ServerState::Running | ServerState::Starting | ServerState::Stopping) {
                return Ok(());
            }
            let res = self.launch(srv, guard).await;
            match &res {
                Ok(()) => self.set_desired(srv, true).await,
                Err(e) => {
                    let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
                    rt.error = Some(e.code);
                    if rt.state == ServerState::Starting {
                        rt.state = ServerState::Stopped;
                    }
                }
            }
            res
        })
    }

    async fn launch(self: &Arc<Self>, srv: &Arc<Server>, guard: &OpGuard) -> Result<(), AppError> {
        let row = srv.row();
        let launch = row.launch.clone().ok_or_else(|| AppError::conflict(ErrorCode::NotInstalled))?;
        if !row.eula {
            return Err(AppError::conflict(ErrorCode::EulaRequired));
        }
        srv.rt.lock().unwrap_or_else(|p| p.into_inner()).error = None;
        // Jamais au travers d'un lien posé à la place de `.rcm` par un processus du serveur.
        let dir = srv.dir.clone();
        let tmp = tokio::task::spawn_blocking(move || crate::files::internal_dir(&dir, "tmp", true))
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or_else(AppError::internal)?;
        let java = match &row.java_path {
            Some(p) => {
                guard.step(OpStep::Resolve, None, None);
                crate::java::validate_custom(p, &tmp)
                    .await
                    .ok_or_else(|| AppError::conflict(ErrorCode::JavaNotFound))?
                    .0
            }
            None => {
                let major = crate::java::runtime_for(row.java_major);
                let progress = |d: u64, t: Option<u64>| guard.step(OpStep::DownloadJava, Some(d), t);
                crate::java::ensure(&self.catalog.http, &self.data, major, &progress).await.map_err(|e| {
                    tracing::warn!("Java {major} : {e}");
                    AppError::new(axum::http::StatusCode::BAD_GATEWAY, e.code())
                })?
            }
        };
        guard.step(OpStep::Launch, None, None);
        if self.port_taken(row.port, Some(row.id)) || !port_free(row.port) {
            return Err(AppError::conflict(ErrorCode::PortInUse));
        }
        // L'EULA a été acceptée par un utilisateur (base) : le fichier est réécrit s'il a disparu.
        if !srv.dir.join("eula.txt").is_file() {
            write_eula_accepted_by_user(&srv.dir).map_err(|_| AppError::internal())?;
        }
        {
            // Même verrou que l'enregistrement d'un réglage : pas d'écriture croisée du fichier.
            let _cfg = crate::configs_api::SAVE_LOCK.lock().await;
            self.write_properties(srv, false).map_err(|_| AppError::internal())?;
        }
        // Chemins posés hors du gestionnaire (fichier modifié à la main) : un monde ou un script
        // hors du dossier du serveur n'est jamais lancé.
        if let Some(r) = launch_refusal(&srv.dir) {
            srv.rt.lock().unwrap_or_else(|p| p.into_inner()).refusal = Some(r);
            return Err(AppError::unprocessable(ErrorCode::LaunchRefused));
        }
        let max_players = crate::props::get(&crate::files::server_properties(&srv.dir), "max-players")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let mut cmd = crate::java::command(&java, &srv.dir, &tmp);
        cmd.args(jvm_args(row.memory_mb, &tmp, cfg!(target_os = "linux")))
            .args(launch.args())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        srv.note(ManagerNote::Starting);
        let mut child = cmd.spawn().map_err(|e| {
            tracing::warn!("serveur {} : lancement impossible : {e}", row.id);
            AppError::new(axum::http::StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::LaunchFailed)
        })?;
        let pid = child.id().unwrap_or(0);
        #[cfg(windows)]
        let job = windows_job(&child);
        let stdin = child.stdin.take().ok_or_else(AppError::internal)?;
        let stdout = child.stdout.take().ok_or_else(AppError::internal)?;
        let stderr = child.stderr.take().ok_or_else(AppError::internal)?;
        let kill = Arc::new(Notify::new());
        *srv.proc.lock().await = Some(Proc {
            stdin,
            pid,
            kill: kill.clone(),
            #[cfg(windows)]
            _job: job,
        });
        {
            let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            rt.state = ServerState::Starting;
            rt.alert = None;
            rt.stop_requested = false;
            rt.started_at = None;
            rt.players.clear();
            rt.max_players = max_players;
        }
        self.bump();
        let mgr = self.clone();
        let s2 = srv.clone();
        tokio::spawn(async move { mgr.supervise(s2, child, stdout, stderr, kill).await });
        Ok(())
    }

    async fn supervise(
        self: Arc<Self>,
        srv: Arc<Server>,
        mut child: tokio::process::Child,
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
        kill: Arc<Notify>,
    ) {
        let (tx, mut rx) = mpsc::channel::<(LineSource, String)>(1024);
        for (src, reader) in [
            (LineSource::Out, Box::new(stdout) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
            (LineSource::Err, Box::new(stderr)),
        ] {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut r = tokio::io::BufReader::new(reader);
                let mut buf = Vec::new();
                while let Ok(true) = read_line_bounded(&mut r, &mut buf, READ_LINE_MAX).await {
                    let s = String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']).to_string();
                    if tx.send((src, s)).await.is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        // « En marche » = port de jeu joignable (le message « Done » seul ne suffit pas : un
        // serveur prêt mais injoignable est une panne). Adresse : `server-ip` si elle est posée.
        let local = srv.local_game_addr();
        let (port, ip) = (local.port(), local.ip());
        let t0 = Instant::now();
        let mut alerted = false;
        let mut probe = tokio::time::interval(Duration::from_secs(2));
        probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let status = loop {
            tokio::select! {
                Some((src, text)) = rx.recv() => {
                    self.on_line(&srv, src, &text);
                    // Plus rien en attente : l'historique part sur le disque (pas de minuterie au repos).
                    if rx.is_empty() {
                        srv.history.lock().unwrap_or_else(|p| p.into_inner()).flush();
                    }
                }
                st = child.wait() => break st,
                _ = kill.notified() => { let _ = child.start_kill(); }
                _ = probe.tick(), if srv.state() == ServerState::Starting => {
                    if tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect((ip, port))).await.is_ok_and(|r| r.is_ok()) {
                        self.mark_running(&srv);
                    } else if !alerted && t0.elapsed() > self.timings().startup_alert {
                        alerted = true;
                        srv.rt.lock().unwrap_or_else(|p| p.into_inner()).alert = Some(ServerAlert::PortNeverOpened);
                        srv.note(ManagerNote::PortNeverOpened);
                        tracing::warn!("serveur {} : processus vivant mais port {port} jamais ouvert", srv.id);
                        self.bump();
                    }
                }
            }
        };
        // Les dernières lignes (message de plantage) arrivent après la sortie.
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some((src, text)) = rx.recv().await {
                self.on_line(&srv, src, &text);
            }
        })
        .await;
        *srv.proc.lock().await = None;
        let ok = status.as_ref().is_ok_and(|s| s.success());
        let (crashed, restart, requested) = {
            let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            let requested = std::mem::take(&mut rt.stop_requested);
            let crashed = !requested && !ok;
            rt.state = if crashed { ServerState::Crashed } else { ServerState::Stopped };
            rt.started_at = None;
            rt.players.clear();
            let mut restart = false;
            if crashed && srv.row().auto_restart && !self.shutting_down.load(Ordering::Acquire) {
                let now = Instant::now();
                rt.crashes.retain(|t| now.duration_since(*t) < CRASH_WINDOW);
                rt.crashes.push_back(now);
                if rt.crashes.len() > CRASH_LIMIT {
                    rt.alert = Some(ServerAlert::CrashLoop);
                } else {
                    restart = true;
                }
            }
            (crashed, restart, requested)
        };
        srv.history.lock().unwrap_or_else(|p| p.into_inner()).flush();
        srv.note(if crashed { ManagerNote::Crashed } else { ManagerNote::Stopped });
        srv.publish_players();
        srv.exits.send_modify(|n| *n += 1);
        if crashed {
            tracing::warn!("serveur {} : arrêt inattendu ({status:?})", srv.id);
        }
        // Arrêt non demandé par le gestionnaire (plantage, `/stop` en jeu) : pas relancé au
        // prochain démarrage du gestionnaire, sauf redémarrage automatique. Arrêt du gestionnaire :
        // l'état voulu reste.
        if !self.shutting_down.load(Ordering::Acquire) && !restart && !requested {
            self.set_desired(&srv, false).await;
        }
        self.bump();
        if restart {
            let mgr = self.clone();
            // Un arrêt ou une suppression pendant l'attente change la génération : relance annulée
            // (sinon un serveur supprimé verrait son dossier recréé).
            let generation = srv.generation.load(Ordering::Acquire);
            tokio::spawn(async move {
                tokio::time::sleep(mgr.timings().restart_delay).await;
                if mgr.shutting_down.load(Ordering::Acquire)
                    || srv.generation.load(Ordering::Acquire) != generation
                    || mgr.get(srv.id).is_none()
                    || !srv.row().desired_running
                    || srv.state() != ServerState::Crashed
                {
                    return;
                }
                srv.note(ManagerNote::AutoRestart);
                if let Ok(g) = mgr.begin(&srv, OpKind::Start) {
                    let _ = mgr.start_with(&srv, &g).await;
                }
            });
        }
    }

    fn mark_running(&self, srv: &Server) {
        let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
        if rt.state == ServerState::Starting {
            rt.state = ServerState::Running;
            rt.started_at = Some(now());
            rt.alert = None;
            drop(rt);
            self.bump();
        }
    }

    fn on_line(&self, srv: &Server, src: LineSource, text: &str) {
        // Réponses aux mesures envoyées par le gestionnaire : lues puis retirées de la console.
        if self.probe_line(srv, text) {
            return;
        }
        let line = srv.line(src, text, None);
        match &line.event {
            Some(ConsoleEvent::Join { player }) => {
                {
                    let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
                    if !rt.players.iter().any(|p| &p.name == player) {
                        rt.players.push(PlayerInfo { name: player.clone(), since: Some(now()) });
                    }
                }
                srv.publish_players();
                self.bump();
            }
            Some(ConsoleEvent::Leave { player }) => {
                srv.rt.lock().unwrap_or_else(|p| p.into_inner()).players.retain(|p| &p.name != player);
                srv.publish_players();
                self.bump();
            }
            _ => {}
        }
    }

    /// Arrêt demandé : état voulu « arrêté », puis en tâche de fond `stop`, attente bornée,
    /// arrêt forcé au besoin.
    pub fn stop(self: &Arc<Self>, srv: &Arc<Server>) -> Result<(), AppError> {
        let g = self.begin(srv, OpKind::Stop)?;
        srv.generation.fetch_add(1, Ordering::AcqRel);
        {
            // Planté en attente de relance : l'arrêt demandé l'annule, l'état devient « arrêté ».
            let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            if rt.state == ServerState::Crashed {
                rt.state = ServerState::Stopped;
            }
        }
        self.bump();
        let (mgr, s2) = (self.clone(), srv.clone());
        tokio::spawn(async move {
            g.step(OpStep::WaitExit, None, None);
            mgr.set_desired(&s2, false).await;
            mgr.stop_inner(&s2, false).await;
            drop(g);
        });
        Ok(())
    }

    async fn stop_inner(&self, srv: &Arc<Server>, save_first: bool) {
        if srv.proc.lock().await.is_none() {
            return;
        }
        let mut exits = srv.exits.subscribe();
        let seen = *exits.borrow_and_update();
        {
            let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            rt.stop_requested = true;
            rt.state = ServerState::Stopping;
        }
        self.bump();
        if save_first {
            let _ = srv.send_stdin("save-all").await;
        }
        let _ = srv.send_stdin("stop").await;
        let wait = |d: Duration| {
            let mut ex = exits.clone();
            async move { tokio::time::timeout(d, ex.wait_for(|n| *n != seen)).await.is_ok() }
        };
        let stop_timeout = self.timings().stop_timeout;
        if !wait(stop_timeout).await {
            tracing::warn!("serveur {} : pas arrêté en {} s, arrêt forcé", srv.id, stop_timeout.as_secs());
            srv.note(ManagerNote::Killed);
            if let Some(p) = srv.proc.lock().await.as_ref() {
                p.kill.notify_one();
            }
            let _ = wait(Duration::from_secs(15)).await;
        }
        let _ = exits.borrow_and_update();
    }

    pub fn restart(self: &Arc<Self>, srv: &Arc<Server>) -> Result<(), AppError> {
        let row = srv.row();
        if row.launch.is_none() {
            return Err(AppError::conflict(ErrorCode::NotInstalled));
        }
        if !row.eula {
            return Err(AppError::conflict(ErrorCode::EulaRequired));
        }
        let g = self.begin(srv, OpKind::Restart)?;
        let (mgr, s2) = (self.clone(), srv.clone());
        tokio::spawn(async move {
            g.step(OpStep::WaitExit, None, None);
            mgr.stop_inner(&s2, false).await;
            if let Err(e) = mgr.start_with(&s2, &g).await {
                tracing::warn!("serveur {} : redémarrage impossible ({:?})", s2.id, e.code);
            }
            drop(g);
        });
        Ok(())
    }

    /// Suppression (après ré-authentification et nom recopié, vérifiés par la route) : en tâche
    /// de fond, arrêt, dossier déplacé dans la corbeille, ligne effacée (favoris compris).
    pub fn delete(self: &Arc<Self>, srv: &Arc<Server>) -> Result<(), AppError> {
        let g = self.begin(srv, OpKind::Delete)?;
        srv.generation.fetch_add(1, Ordering::AcqRel);
        let (mgr, s2) = (self.clone(), srv.clone());
        tokio::spawn(async move {
            if let Err(e) = mgr.delete_with(&s2, g).await {
                tracing::error!("serveur {} : suppression impossible ({:?})", s2.id, e.code);
            }
        });
        Ok(())
    }

    async fn delete_with(self: &Arc<Self>, srv: &Arc<Server>, g: OpGuard) -> Result<(), AppError> {
        g.step(OpStep::WaitExit, None, None);
        self.stop_inner(srv, false).await;
        let trash = crate::paths::trash_dir(&self.data, srv.id, now());
        if srv.dir.exists() {
            if let Some(p) = trash.parent() {
                std::fs::create_dir_all(p).map_err(|_| AppError::internal())?;
            }
            // L'historique de la console garde un fichier ouvert : fermé avant le déplacement.
            {
                let mut h = srv.history.lock().unwrap_or_else(|p| p.into_inner());
                *h = History::memory();
            }
            std::fs::rename(&srv.dir, &trash).map_err(|e| {
                tracing::error!("{} → {} : {e}", srv.dir.display(), trash.display());
                AppError::internal()
            })?;
        }
        let id = srv.id.get();
        self.db
            .call(move |c, _| {
                c.execute("DELETE FROM servers WHERE id = ?1", [id])?;
                Ok(())
            })
            .await?;
        self.servers.write().unwrap_or_else(|p| p.into_inner()).remove(&srv.id);
        drop(g);
        Ok(())
    }

    /// Réglages (nom, mémoire, port, redémarrage automatique, Java). Port et mémoire pris en
    /// compte au prochain démarrage.
    pub async fn update(
        self: &Arc<Self>,
        srv: &Arc<Server>,
        req: ServerSettingsRequest,
        is_admin: bool,
    ) -> Result<ServerInfo, AppError> {
        // Pendant un démarrage, un arrêt ou une installation, les réglages attendent la fin.
        if srv.info().op.is_some() || matches!(srv.state(), ServerState::Starting | ServerState::Stopping) {
            return Err(AppError::conflict(ErrorCode::OperationInProgress));
        }
        let name = req.name.trim().to_string();
        if !server_name_valid(&name) {
            return Err(AppError::unprocessable(ErrorCode::InvalidName));
        }
        if !(MEMORY_MIN_MB..=MEMORY_MAX_MB).contains(&req.memory_mb) {
            return Err(AppError::unprocessable(ErrorCode::InvalidMemory));
        }
        if req.port < PORT_MIN {
            return Err(AppError::unprocessable(ErrorCode::InvalidPort));
        }
        let current = srv.row();
        let java_path =
            if req.java == current.java_path.clone().map_or(JavaChoice::Managed, |path| JavaChoice::Path { path }) {
                current.java_path.clone()
            } else {
                self.check_java_choice(&req.java, is_admin).await?
            };
        let _g = self.create_lock.lock().await;
        self.check_memory(req.memory_mb, Some(srv.id))?;
        if req.port != current.port
            && (self.port_taken(req.port, Some(srv.id)) || req.port == current.rcon_port || !port_free(req.port))
        {
            return Err(AppError::conflict(ErrorCode::PortInUse));
        }
        let id = srv.id.get();
        let (n2, jp) = (name.clone(), java_path.clone());
        self.db
            .call(move |c, _| {
                c.execute(
                    "UPDATE servers SET name = ?1, memory_mb = ?2, port = ?3, auto_restart = ?4, java_path = ?5 WHERE id = ?6",
                    params![n2, req.memory_mb, req.port, req.auto_restart, jp, id],
                )?;
                Ok(())
            })
            .await?;
        {
            let mut r = srv.row.lock().unwrap_or_else(|p| p.into_inner());
            r.name = name;
            r.memory_mb = req.memory_mb;
            r.port = req.port;
            r.auto_restart = req.auto_restart;
            r.java_path = java_path;
        }
        if srv.state() != ServerState::Running {
            let _cfg = crate::configs_api::SAVE_LOCK.lock().await;
            let _ = self.write_properties(srv, false);
        }
        self.bump();
        Ok(srv.info())
    }

    /// Commande envoyée par un compte : écho dans la console, puis entrée standard.
    pub async fn command(&self, srv: &Arc<Server>, user: &str, cmd: &str) -> Result<(), AppError> {
        if !command_ok(cmd) {
            return Err(AppError::unprocessable(ErrorCode::InvalidCommand));
        }
        let cmd = cmd.trim().trim_start_matches('/');
        srv.send_stdin(cmd).await?;
        srv.line(
            LineSource::Input,
            &format!("> {cmd}"),
            Some(ConsoleEvent::Command { user: user.to_string(), command: cmd.to_string() }),
        );
        Ok(())
    }

    /// Reprise au démarrage du gestionnaire : serveurs dont l'état voulu est « en marche ».
    pub fn resume(self: &Arc<Self>) {
        for srv in self.all() {
            if srv.row().desired_running
                && let Err(e) = self.start(&srv)
            {
                tracing::warn!("serveur {} : reprise impossible ({:?})", srv.id, e.code);
            }
        }
    }

    /// Arrêt du gestionnaire : `save-all` puis `stop` de chaque serveur en parallèle (l'état
    /// voulu reste en base : ils repartent au prochain démarrage).
    pub async fn shutdown(self: &Arc<Self>) {
        self.shutting_down.store(true, Ordering::Release);
        let running: Vec<_> = self
            .all()
            .into_iter()
            .filter(|s| matches!(s.state(), ServerState::Running | ServerState::Starting))
            .collect();
        if running.is_empty() {
            return;
        }
        tracing::info!("arrêt de {} serveur(s)", running.len());
        let tasks: Vec<_> = running
            .into_iter()
            .map(|s| {
                let mgr = self.clone();
                tokio::spawn(async move { mgr.stop_inner(&s, true).await })
            })
            .collect();
        for t in tasks {
            let _ = t.await;
        }
    }

    /// Un abonné suit ce serveur : mesures échantillonnées tant qu'il y en a au moins un.
    pub fn watch(self: &Arc<Self>, srv: &Arc<Server>) -> WatchGuard {
        srv.watchers.fetch_add(1, Ordering::AcqRel);
        if !srv.sampling.swap(true, Ordering::AcqRel) {
            let mgr = self.clone();
            let s2 = srv.clone();
            tokio::spawn(async move {
                mgr.sample(&s2).await;
                s2.sampling.store(false, Ordering::Release);
            });
        }
        WatchGuard { srv: srv.clone() }
    }

    async fn sample(&self, srv: &Arc<Server>) {
        // `None` : système non pris en charge par sysinfo (CPU et mémoire restent inconnus).
        let mut sys = sysinfo::System::new().ok();
        let t = self.timings();
        let mut tick = tokio::time::interval(t.sample_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_probe: Option<Instant> = None;
        loop {
            tick.tick().await;
            if srv.watchers.load(Ordering::Acquire) == 0 {
                break;
            }
            let Some(pid) = srv.pid().await else { continue };
            let (s, cpu, mem) = tokio::task::spawn_blocking({
                let s = sys.take().or_else(|| sysinfo::System::new().ok());
                move || {
                    let Some(mut s) = s else { return (None, None, None) };
                    let p = sysinfo::Pid::from_u32(pid);
                    s.refresh_processes_specifics(
                        sysinfo::ProcessesToUpdate::Some(&[p]),
                        true,
                        sysinfo::ProcessRefreshKind::nothing().with_cpu().with_memory(),
                    );
                    let (c, m) = s.process(p).map(|x| (x.cpu_usage(), x.memory())).unzip();
                    (Some(s), c, m)
                }
            })
            .await
            .unwrap_or_default();
            sys = s;
            // Joueurs et ticks par l'entrée standard (RCON reste coupé : il écouterait sur toutes
            // les interfaces). Les réponses sont lues puis retirées de la console (`probe_line`).
            if srv.state() == ServerState::Running && last_probe.is_none_or(|l| l.elapsed() >= t.probe_every) {
                last_probe = Some(Instant::now());
                srv.rt.lock().unwrap_or_else(|p| p.into_inner()).probe_until = Some(Instant::now() + PROBE_WINDOW);
                let sw = srv.row().software;
                let _ = srv.send_stdin("list").await;
                if matches!(sw, Software::Paper | Software::Purpur | Software::Folia) {
                    let _ = srv.send_stdin("mspt").await;
                    let _ = srv.send_stdin("tps").await;
                } else {
                    let _ = srv.send_stdin("tick query").await;
                }
            }
            let (tps, mspt) = {
                let rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
                (rt.tps, rt.mspt)
            };
            let cores = available_cores();
            let stats = ServerStats {
                ts: crate::console::now_ms(),
                cpu: cpu.map(|c| cpu_machine_percent(c, cores)),
                cores_used: cpu.map(|c| (c / 100.0).clamp(0.0, cores)),
                cores: Some(cores.ceil() as u32),
                memory: mem,
                tps,
                mspt,
            };
            let _ = srv.events.send(ServerEvent::Stats(stats));
        }
    }

    /// Ligne de réponse à une mesure envoyée par le gestionnaire (pendant la fenêtre de mesure) :
    /// lue (joueurs, ticks) et retirée de la console. Rend `true` si la ligne est consommée.
    fn probe_line(&self, srv: &Server, text: &str) -> bool {
        let probe = {
            let rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            rt.probe_until.is_some_and(|u| Instant::now() < u)
        };
        if !probe {
            return false;
        }
        let Some(r) = probe_response(text) else { return false };
        let mut players_changed = false;
        {
            let mut rt = srv.rt.lock().unwrap_or_else(|p| p.into_inner());
            match r {
                Probe::List { max, names } => {
                    rt.max_players = max;
                    let before: Vec<&str> = rt.players.iter().map(|p| p.name.as_str()).collect();
                    if before != names.iter().map(String::as_str).collect::<Vec<_>>() {
                        let old = std::mem::take(&mut rt.players);
                        rt.players = names
                            .iter()
                            .filter(|n| crate::console::player_name_ok(n))
                            .map(|n| {
                                old.iter()
                                    .find(|p| &p.name == n)
                                    .cloned()
                                    .unwrap_or_else(|| PlayerInfo { name: n.clone(), since: None })
                            })
                            .collect();
                        players_changed = true;
                    }
                }
                Probe::Mspt(m) => {
                    rt.mspt = Some(m);
                    if !matches!(srv.row().software, Software::Paper | Software::Purpur | Software::Folia) {
                        rt.tps = Some(if m > 0.0 { (1000.0 / m).min(20.0) } else { 20.0 });
                    }
                }
                Probe::Tps(t) => rt.tps = Some(t),
                Probe::Other => {}
            }
        }
        if players_changed {
            srv.publish_players();
            self.bump();
        }
        true
    }

    /// Favoris d'un compte pour un serveur.
    pub async fn favorites(&self, srv: ServerId, user_id: i64) -> Result<Vec<Favorite>, AppError> {
        let sid = srv.get();
        self.db
            .call(move |c, _| {
                let mut s = c.prepare(
                    "SELECT id, label, command FROM server_favorites WHERE user_id = ?1 AND server_id = ?2 ORDER BY id",
                )?;
                let v = s
                    .query_map(params![user_id, sid], |r| {
                        Ok(Favorite { id: r.get(0)?, label: r.get(1)?, command: r.get(2)? })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(v)
            })
            .await
    }

    pub async fn add_favorite(&self, srv: ServerId, user_id: i64, req: FavoriteRequest) -> Result<Favorite, AppError> {
        let label = req.label.trim().to_string();
        if label.is_empty() || label.chars().count() > FAVORITE_LABEL_MAX || label.chars().any(char::is_control) {
            return Err(AppError::unprocessable(ErrorCode::InvalidName));
        }
        if !command_ok(&req.command) {
            return Err(AppError::unprocessable(ErrorCode::InvalidCommand));
        }
        let sid = srv.get();
        let cmd = req.command.trim().trim_start_matches('/').to_string();
        self.db
            .call(move |c, _| {
                let tx = write_tx(c)?;
                let n: i64 = tx.query_row(
                    "SELECT count(*) FROM server_favorites WHERE user_id = ?1 AND server_id = ?2",
                    params![user_id, sid],
                    |r| r.get(0),
                )?;
                if n as usize >= FAVORITES_MAX {
                    return Err(AppError::conflict(ErrorCode::LimitReached));
                }
                tx.execute(
                    "INSERT INTO server_favorites (user_id, server_id, label, command, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![user_id, sid, label, cmd, now()],
                )?;
                let id = tx.last_insert_rowid();
                tx.commit()?;
                Ok(Favorite { id, label, command: cmd })
            })
            .await
    }

    pub async fn delete_favorite(&self, srv: ServerId, user_id: i64, id: i64) -> Result<bool, AppError> {
        let sid = srv.get();
        self.db
            .call(move |c, _| {
                Ok(c.execute(
                    "DELETE FROM server_favorites WHERE id = ?1 AND user_id = ?2 AND server_id = ?3",
                    params![id, user_id, sid],
                )? == 1)
            })
            .await
    }

    /// Le serveur `id` existe-t-il en base ? (tests)
    pub async fn exists_in_db(&self, id: ServerId) -> bool {
        let i = id.get();
        self.db
            .call(move |c, _| {
                Ok(c.query_row("SELECT 1 FROM servers WHERE id = ?1", [i], |_| Ok(())).optional()?.is_some())
            })
            .await
            .unwrap_or(false)
    }
}

/// Objet Job « tuer à la fermeture » pour un processus serveur (Windows). Si le gestionnaire
/// meurt, le système ferme ses descripteurs, donc le Job, donc le serveur.
#[cfg(windows)]
fn windows_job(child: &tokio::process::Child) -> Option<win32job::Job> {
    let handle = child.raw_handle()?;
    let mut info = win32job::ExtendedLimitInfo::new();
    info.limit_kill_on_job_close();
    let job = win32job::Job::create_with_limit_info(&info).ok()?;
    // Conversion d'un pointeur en entier : aucune lecture mémoire, pas de code `unsafe`.
    match job.assign_process(handle as isize) {
        Ok(()) => Some(job),
        Err(e) => {
            tracing::warn!("objet Job refusé ({e:?}) : le serveur survivrait à un plantage du gestionnaire");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Processeur ramené à la machine : 400 % sur 8 cœurs = 50 %, borné à 0..100.
    #[test]
    fn processeur_en_pourcentage_de_la_machine() {
        assert_eq!(cpu_machine_percent(400.0, 8.0), 50.0);
        assert_eq!(cpu_machine_percent(400.0, 4.0), 100.0);
        assert_eq!(cpu_machine_percent(900.0, 4.0), 100.0, "mesure au-delà des cœurs : bornée");
        assert_eq!(cpu_machine_percent(12.5, 1.0), 12.5);
        assert_eq!(cpu_machine_percent(50.0, 0.0), 50.0, "zéro cœur lu : un seul");
        assert_eq!(cpu_machine_percent(f32::NAN, 8.0), 0.0);
        // Quota fractionnaire : 1,5 cœur (et non 2, arrondi de la bibliothèque standard).
        assert_eq!(cpu_machine_percent(75.0, 1.5), 50.0);
        assert!(available_cores() > 0.0);
    }

    /// Quotas cgroup lus tels quels (v2 `cpu.max`, v1 `cfs_quota_us` / `cfs_period_us`).
    #[test]
    fn quotas_cgroup_fractionnaires() {
        assert_eq!(parse_cpu_max("150000 100000\n"), Some(1.5));
        assert_eq!(parse_cpu_max("50000 100000"), Some(0.5));
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpu_max(""), None);
        assert_eq!(parse_cfs("250000\n", "100000\n"), Some(2.5));
        assert_eq!(parse_cfs("-1", "100000"), None);
    }

    /// Arguments de la JVM : OSHI sans udev sous Linux seulement (image distroless sans libudev),
    /// avant tout argument du logiciel.
    #[test]
    fn arguments_de_la_jvm() {
        let tmp = Path::new("tmp");
        let linux = jvm_args(2048, tmp, true);
        assert_eq!(linux[0], "-Xmx2048M");
        assert!(linux.iter().any(|a| a == "-Doshi.os.linux.allowudev=false"));
        assert!(linux.iter().all(|a| a.starts_with('-')), "rien qui ressemble à un argument du jeu");
        let other = jvm_args(1024, tmp, false);
        assert!(!other.iter().any(|a| a.contains("oshi")));
        assert!(other.contains(&"-Djava.awt.headless=true".to_string()));
    }

    #[test]
    fn commandes_acceptees() {
        assert!(command_ok("say bonjour"));
        assert!(command_ok("/give neo minecraft:diamond 64"));
        assert!(!command_ok(""));
        assert!(!command_ok("   "));
        assert!(!command_ok("stop\nop pirate"));
        assert!(!command_ok("say a\rb"));
        assert!(!command_ok(&"x".repeat(COMMAND_MAX + 1)));
    }

    /// L'EULA n'est écrite qu'à un seul endroit du code du produit, appelé après une acceptation
    /// enregistrée d'un utilisateur.
    #[test]
    fn eula_jamais_acceptee_automatiquement() {
        let sources = [
            ("servers.rs", include_str!("servers.rs")),
            ("api.rs", include_str!("api.rs")),
            ("servers_api.rs", include_str!("servers_api.rs")),
            ("minecraft.rs", include_str!("minecraft.rs")),
            ("lib.rs", include_str!("lib.rs")),
        ];
        let needle = ["eula", "=true"].concat();
        let mut found = 0;
        for (name, src) in sources {
            let n = src.matches(&needle).count();
            if name == "servers.rs" {
                // Le texte du fichier, et ce test.
                found += n;
            } else {
                assert_eq!(n, 0, "{name} écrit l'EULA");
            }
        }
        assert_eq!(found, 1, "un seul endroit écrit l'EULA");
        let calls = include_str!("servers.rs").matches(&["write_eula_accepted", "_by_user("].concat()).count();
        // Définition, création (case cochée), acceptation, relance après acceptation.
        assert_eq!(calls, 4);
    }

    /// Démarrage : extractions et téléchargements interrompus effacés, Java installé gardé,
    /// corbeille vidée de ce qui a plus de 30 jours seulement.
    #[test]
    fn nettoyage_au_demarrage() {
        let d = std::env::temp_dir().join(format!("rcm-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for p in ["java/.extract-ABC/bin", "java/25/bin", "trash/3-1700000000/world"] {
            std::fs::create_dir_all(d.join(p)).unwrap();
        }
        std::fs::write(d.join("java/.download-25.zip"), b"x").unwrap();
        std::fs::create_dir_all(d.join("servers/1/.rcm/tmp")).unwrap();
        std::fs::write(d.join("servers/1/.rcm/tmp/upload-abc.part"), b"x").unwrap();
        let now = std::time::SystemTime::now();
        cleanup(&d, now);
        assert!(!d.join("servers/1/.rcm/tmp/upload-abc.part").exists(), "envoi interrompu effacé");
        assert!(!d.join("java/.extract-ABC").exists());
        assert!(!d.join("java/.download-25.zip").exists());
        assert!(d.join("java/25/bin").exists());
        assert!(d.join("trash/3-1700000000").exists(), "récent : gardé");
        cleanup(&d, now + Duration::from_secs((TRASH_DAYS + 1) * 86_400));
        assert!(!d.join("trash/3-1700000000").exists(), "plus de 30 jours : effacé");
    }

    /// Réponses réelles (vanilla 26.3, Paper) reconnues ; une ligne ordinaire ne l'est pas.
    #[test]
    fn reponses_aux_mesures() {
        assert_eq!(
            probe_response(
                "[12:55:05] [Server thread/INFO]: System chat: There are 1 of a max of 20 players online: neo"
            ),
            Some(Probe::List { max: 20, names: vec!["neo".into()] })
        );
        assert_eq!(
            probe_response("[12:55:05] [Server thread/INFO]: Average time per tick: 4.1ms (Target: 50.0ms)"),
            Some(Probe::Mspt(4.1))
        );
        assert_eq!(probe_response("[10:00:00 INFO]: \u{1b}[0;32m◴ 1.2/0.5/3.1, 1.0/0.4/2.0"), Some(Probe::Mspt(1.2)));
        assert_eq!(
            probe_response("[10:00:00 INFO]: §6TPS from last 1m, 5m, 15m: §a*20.0, 20.0, 20.0"),
            Some(Probe::Tps(20.0))
        );
        assert_eq!(probe_response("[12:55:05] [Server thread/INFO]: The game is running normally"), Some(Probe::Other));
        assert_eq!(probe_response("[12:55:05] [Server thread/INFO]: <neo> There are 3 of us"), None);
        assert_eq!(probe_response("[12:55:05] [Server thread/INFO]: neo joined the game"), None);
    }

    #[tokio::test]
    async fn lecture_bornee_des_lignes() {
        let data = b"court\n".iter().chain([b'x'; 100].iter()).chain(b"\nfin".iter()).copied().collect::<Vec<u8>>();
        let mut r = tokio::io::BufReader::with_capacity(8, &data[..]);
        let mut buf = Vec::new();
        assert!(read_line_bounded(&mut r, &mut buf, 10).await.unwrap());
        assert_eq!(buf, b"court\n");
        assert!(read_line_bounded(&mut r, &mut buf, 10).await.unwrap());
        assert_eq!(buf.len(), 10, "ligne coupée à la borne");
        assert!(read_line_bounded(&mut r, &mut buf, 10).await.unwrap());
        assert_eq!(buf, b"fin");
        assert!(!read_line_bounded(&mut r, &mut buf, 10).await.unwrap());
    }
}
