//! Pilotage des serveurs, sans réseau : un faux `java` (`tests/outils/faux_java.rs`) imite la
//! console d'un serveur Minecraft. Cycle de vie, environnement vidé, arguments sans shell, EULA,
//! ports, opération unique, plantage et redémarrage borné, panne silencieuse, arrêt forcé, arrêt
//! et reprise du gestionnaire ; routes : identifiants hostiles, CSRF, suppression (nom recopié
//! puis ré-authentification), commande, EULA, thème, favoris.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use rc_manager::config::Config;
use rc_manager::db::Db;
use rc_manager::paths::ServerId;
use rc_manager::servers::{Server, Timings};
use rc_manager::{AppState, new_state, router};
use rc_manager_shared::{ConsoleEvent, ErrorCode, LineSource, ManagerNote, ServerAlert, ServerState};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

const PW: &str = "un mot de passe solide";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rcm-srv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Faux `java` copié sous son vrai nom (le gestionnaire n'accepte qu'un exécutable `java`).
fn fake_java(dir: &Path) -> PathBuf {
    let bin = dir.join("jdk").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let dest = bin.join(if cfg!(windows) { "java.exe" } else { "java" });
    std::fs::copy(env!("CARGO_BIN_EXE_rcm-faux-java"), &dest).unwrap();
    dest
}

struct Seed {
    port: u16,
    mode: &'static str,
    eula: bool,
    auto_restart: bool,
    desired: bool,
}

impl Default for Seed {
    fn default() -> Self {
        Seed { port: free_port(), mode: "", eula: true, auto_restart: false, desired: false }
    }
}

/// Base avec un serveur installé (lancement `-jar server.jar`) qui utilise le faux java.
fn seeded(data: &Path, s: &Seed) -> (Arc<AppState>, String, ServerId) {
    let db = Db::open_memory().unwrap();
    let java = fake_java(data);
    let rcon = free_port();
    db.with(|c| {
        c.execute(
            "INSERT INTO servers (id, name, software, game_version, memory_mb, port, rcon_port, rcon_password_enc,
              java_major, java_path, launch, auto_restart, desired_running, eula_accepted_at, created_at)
             VALUES (1, 'Survie', 'vanilla', '26.3', 1024, ?1, ?2, '', 25, ?3, '{\"kind\":\"jar\",\"jar\":\"server.jar\"}', ?4, ?5, ?6, 0)",
            rusqlite::params![s.port, rcon, java.to_string_lossy(), s.auto_restart, s.desired, s.eula.then_some(1)],
        )
        .unwrap();
    });
    let enc = db.keys().encrypt(&rc_manager::crypto::aad("servers", "rcon_password", 1), b"motdepasse");
    db.with(|c| c.execute("UPDATE servers SET rcon_password_enc = ?1 WHERE id = 1", [enc]).unwrap());
    let dir = data.join("servers").join("1");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("faux.txt"), s.mode).unwrap();
    let (st, token) = new_state(Config::with_data_dir(data.to_path_buf()), db);
    st.servers.set_timings(Timings {
        stop_timeout: Duration::from_secs(2),
        startup_alert: Duration::from_secs(1),
        restart_delay: Duration::from_millis(100),
        ..Timings::default()
    });
    (st, token.unwrap(), ServerId::parse("1").unwrap())
}

async fn wait(srv: &Server, what: &str, limit: Duration, pred: impl Fn(&rc_manager_shared::ServerInfo) -> bool) {
    let t0 = Instant::now();
    loop {
        let i = srv.info();
        if pred(&i) {
            return;
        }
        assert!(t0.elapsed() < limit, "{what} : délai dépassé, état {:?} {:?}", i.state, i);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn desired(st: &AppState) -> bool {
    st.db.with(|c| c.query_row("SELECT desired_running FROM servers WHERE id = 1", [], |r| r.get(0)).unwrap())
}

fn notes(srv: &Server, what: ManagerNote) -> usize {
    srv.history(5000, None)
        .iter()
        .filter(|l| matches!(&l.event, Some(ConsoleEvent::Manager { what: w }) if *w == what))
        .count()
}

/// Cycle complet : lancé sans shell (arguments un par un), environnement vidé (liste blanche
/// seulement), prêt une fois le port ouvert, commande en écho, arrêt propre par `stop`.
#[tokio::test]
async fn cycle_de_vie_avec_un_faux_java() {
    let d = tmp("cycle");
    let (st, _, id) = seeded(&d, &Seed::default());
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "démarrage", Duration::from_secs(20), |i| i.state == ServerState::Running).await;
    assert!(srv.info().started_at.is_some());
    assert!(desired(&st), "état voulu enregistré");
    st.servers.command(&srv, "admin", "/say bonjour").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let h = srv.history(100, None);
    assert!(h.iter().any(|l| l.source == LineSource::Input
        && matches!(&l.event, Some(ConsoleEvent::Command { user, command }) if user == "admin" && command == "say bonjour")));
    assert!(h.iter().any(|l| l.text.contains("<faux> say bonjour")), "{h:?}");
    st.servers.stop(&srv).unwrap();
    wait(&srv, "arrêt", Duration::from_secs(10), |i| i.state == ServerState::Stopped && i.op.is_none()).await;
    assert!(!desired(&st));
    let dir = d.join("servers").join("1");
    let recu = std::fs::read_to_string(dir.join("faux-recu.txt")).unwrap();
    assert_eq!(recu.lines().collect::<Vec<_>>(), ["say bonjour", "stop"]);
    // Environnement : liste blanche seulement (rien du gestionnaire, ni PATH Windows, ni RCM_*).
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
    let env = std::fs::read_to_string(dir.join("faux-env.txt")).unwrap();
    for k in env.lines().filter(|k| !k.is_empty()) {
        // Windows ajoute parfois des variables de lecteur (« =C: ») à tout processus.
        assert!(allowed.contains(&k) || k.starts_with('='), "variable héritée : {k}");
    }
    // Arguments passés un par un (aucune chaîne de shell).
    let args = std::fs::read_to_string(dir.join("faux-args.txt")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert!(args.contains(&"-Xmx1024M"), "{args:?}");
    assert_eq!(&args[args.len() - 3..], ["-jar", "server.jar", "nogui"]);
    // RCON coupé et sans mot de passe dans le fichier (il écouterait sur toutes les interfaces).
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    assert!(props.lines().any(|l| l == "enable-rcon=false"), "{props}");
    assert!(props.lines().any(|l| l == "rcon.password="), "{props}");
}

/// Mesures par l'entrée standard pendant qu'on regarde : joueurs et temps de tick lus dans les
/// réponses, qui n'encombrent pas la console.
#[tokio::test]
async fn mesures_par_l_entree_standard() {
    let d = tmp("probe");
    let (st, _, id) = seeded(&d, &Seed::default());
    st.servers.set_timings(Timings {
        stop_timeout: Duration::from_secs(2),
        startup_alert: Duration::from_secs(1),
        restart_delay: Duration::from_millis(100),
        sample_every: Duration::from_millis(200),
        probe_every: Duration::from_millis(400),
    });
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "démarrage", Duration::from_secs(20), |i| i.state == ServerState::Running).await;
    let mut rx = srv.events.subscribe();
    let _w = st.servers.watch(&srv);
    let t0 = Instant::now();
    let mut mspt = None;
    while mspt.is_none() {
        assert!(t0.elapsed() < Duration::from_secs(10), "aucune mesure de tick");
        if let Ok(Ok(rc_manager::servers::ServerEvent::Stats(s))) =
            tokio::time::timeout(Duration::from_secs(1), rx.recv()).await
        {
            mspt = s.mspt;
        }
    }
    assert_eq!(mspt, Some(4.1));
    wait(&srv, "joueurs", Duration::from_secs(5), |i| i.players == 1).await;
    assert_eq!(srv.players()[0].name, "neo");
    let h = srv.history(500, None);
    assert!(
        !h.iter().any(|l| l.text.contains("players online") || l.text.contains("Average time per tick")),
        "réponses des mesures dans la console"
    );
    st.servers.shutdown().await;
}

/// EULA non acceptée : démarrage refusé, aucun `eula.txt` écrit.
#[tokio::test]
async fn eula_jamais_acceptee_a_la_place_de_l_utilisateur() {
    let d = tmp("eula");
    let (st, _, id) = seeded(&d, &Seed { eula: false, ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    assert_eq!(st.servers.start(&srv).err().map(|e| e.code), Some(ErrorCode::EulaRequired));
    assert_eq!(st.servers.restart(&srv).err().map(|e| e.code), Some(ErrorCode::EulaRequired));
    assert!(!srv.dir.join("eula.txt").exists());
}

#[tokio::test]
async fn port_deja_pris_et_operation_unique() {
    let d = tmp("port");
    let seed = Seed::default();
    let (st, _, id) = seeded(&d, &seed);
    let srv = st.servers.get(id).unwrap();
    {
        let _l = std::net::TcpListener::bind(("127.0.0.1", seed.port)).unwrap();
        assert_eq!(st.servers.start(&srv).err().map(|e| e.code), Some(ErrorCode::PortInUse));
    }
    let g = st.servers.begin(&srv, rc_manager_shared::OpKind::Install).unwrap();
    assert_eq!(st.servers.start(&srv).err().map(|e| e.code), Some(ErrorCode::OperationInProgress));
    assert_eq!(st.servers.stop(&srv).err().map(|e| e.code), Some(ErrorCode::OperationInProgress));
    drop(g);
    assert!(srv.info().op.is_none());
}

/// Plantage sans redémarrage automatique : état « planté », pas relancé au prochain démarrage.
/// Avec : relancé, puis abandon et alerte après trop de plantages.
#[tokio::test]
async fn plantage_et_redemarrage_borne() {
    let d = tmp("crash");
    let (st, _, id) = seeded(&d, &Seed { mode: "crash", ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "plantage", Duration::from_secs(20), |i| i.state == ServerState::Crashed && i.op.is_none()).await;
    assert!(!desired(&st), "un plantage n'est pas relancé à la reprise");
    assert!(
        srv.history(50, None).iter().any(|l| l.text.contains("Exception in server tick loop")),
        "fin de sortie lue"
    );

    let d = tmp("crashloop");
    let (st, _, id) = seeded(&d, &Seed { mode: "crash", auto_restart: true, ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "boucle de plantage", Duration::from_secs(40), |i| i.alert == Some(ServerAlert::CrashLoop)).await;
    let starts = notes(&srv, ManagerNote::Starting);
    assert_eq!(starts, rc_manager::servers::CRASH_LIMIT + 1, "lancements");
    assert_eq!(notes(&srv, ManagerNote::AutoRestart), rc_manager::servers::CRASH_LIMIT);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(notes(&srv, ManagerNote::Starting), starts, "plus de relance après l'abandon");
}

/// Planté, relance automatique en attente : « Arrêter » l'annule (état arrêté), « Supprimer »
/// aussi (rien n'est recréé sur le disque).
#[tokio::test]
async fn arret_ou_suppression_annule_la_relance() {
    let slow = Timings {
        stop_timeout: Duration::from_secs(2),
        startup_alert: Duration::from_secs(1),
        restart_delay: Duration::from_millis(1500),
        ..Timings::default()
    };
    let d = tmp("cancel-stop");
    let (st, _, id) = seeded(&d, &Seed { mode: "crash", auto_restart: true, ..Default::default() });
    st.servers.set_timings(slow);
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "plantage", Duration::from_secs(20), |i| i.state == ServerState::Crashed && i.op.is_none()).await;
    st.servers.stop(&srv).unwrap();
    wait(&srv, "arrêt", Duration::from_secs(5), |i| i.op.is_none()).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(notes(&srv, ManagerNote::Starting), 1, "aucune relance après « Arrêter »");
    assert_eq!(srv.info().state, ServerState::Stopped);

    let d = tmp("cancel-delete");
    let (st, _, id) = seeded(&d, &Seed { mode: "crash", auto_restart: true, ..Default::default() });
    st.servers.set_timings(slow);
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "plantage", Duration::from_secs(20), |i| i.state == ServerState::Crashed && i.op.is_none()).await;
    st.servers.delete(&srv).unwrap();
    let t0 = Instant::now();
    while st.servers.get(id).is_some() {
        assert!(t0.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(!d.join("servers").join("1").exists(), "dossier recréé par une relance");
}

/// Processus vivant, port jamais ouvert : alerte ; puis arrêt forcé d'un serveur qui ignore `stop`.
#[tokio::test]
async fn panne_silencieuse_et_arret_force() {
    let d = tmp("noport");
    let (st, _, id) = seeded(&d, &Seed { mode: "noport", ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "alerte", Duration::from_secs(20), |i| i.alert == Some(ServerAlert::PortNeverOpened)).await;
    assert_eq!(srv.info().state, ServerState::Starting);
    assert_eq!(notes(&srv, ManagerNote::PortNeverOpened), 1);
    std::fs::write(srv.dir.join("faux.txt"), "ignore_stop").unwrap();
    st.servers.stop(&srv).unwrap();
    wait(&srv, "arrêt forcé", Duration::from_secs(20), |i| i.state == ServerState::Stopped && i.op.is_none()).await;

    let d = tmp("kill");
    let (st, _, id) = seeded(&d, &Seed { mode: "ignore_stop", ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "démarrage", Duration::from_secs(20), |i| i.state == ServerState::Running).await;
    let t0 = Instant::now();
    st.servers.stop(&srv).unwrap();
    wait(&srv, "arrêt forcé", Duration::from_secs(20), |i| i.state == ServerState::Stopped && i.op.is_none()).await;
    assert!(t0.elapsed() >= Duration::from_secs(2), "attente de l'arrêt propre d'abord");
    assert_eq!(notes(&srv, ManagerNote::Killed), 1);
}

/// Arrêt du gestionnaire : `save-all` puis `stop`, l'état voulu reste ; au redémarrage, repris.
#[tokio::test]
async fn arret_et_reprise_du_gestionnaire() {
    let d = tmp("shutdown");
    let seed = Seed::default();
    let (st, _, id) = seeded(&d, &seed);
    let srv = st.servers.get(id).unwrap();
    st.servers.start(&srv).unwrap();
    wait(&srv, "démarrage", Duration::from_secs(20), |i| i.state == ServerState::Running).await;
    st.servers.shutdown().await;
    assert_eq!(srv.info().state, ServerState::Stopped);
    let recu = std::fs::read_to_string(srv.dir.join("faux-recu.txt")).unwrap();
    assert_eq!(recu.lines().collect::<Vec<_>>(), ["save-all", "stop"]);
    assert!(desired(&st), "état voulu gardé pour la reprise");

    let d = tmp("resume");
    let (st, _, id) = seeded(&d, &Seed { desired: true, ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    st.servers.resume();
    wait(&srv, "reprise", Duration::from_secs(20), |i| i.state == ServerState::Running).await;
    st.servers.shutdown().await;
}

/// Banc (ignoré par défaut) : débit d'ingestion de la console (lecture, analyse, historique en
/// mémoire et sur disque, diffusion à un abonné). `cargo test --release --test servers banc --
/// --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn banc_flux_console() {
    const N: u64 = 200_000;
    let d = tmp("banc");
    let (st, _, id) = seeded(&d, &Seed { mode: "flood:200000", ..Default::default() });
    let srv = st.servers.get(id).unwrap();
    let mut rx = srv.events.subscribe();
    let counted = tokio::spawn(async move {
        let mut n = 0u64;
        while let Ok(e) = rx.recv().await {
            if matches!(e, rc_manager::servers::ServerEvent::Line(_)) {
                n += 1;
            }
            if n >= N {
                break;
            }
        }
        n
    });
    let t0 = Instant::now();
    st.servers.start(&srv).unwrap();
    let mut last = 0;
    loop {
        last = srv.history(1, None).last().map_or(last, |l| l.seq);
        if last >= N {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(120), "banc trop lent : {last} lignes");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let dt = t0.elapsed();
    let seen = tokio::time::timeout(Duration::from_secs(5), counted).await.map(|r| r.unwrap_or(0)).unwrap_or(0);
    let disk = std::fs::metadata(srv.dir.join(".rcm").join("console.jsonl")).map_or(0, |m| m.len());
    println!(
        "BANC console : {N} lignes en {:.2} s = {:.0} lignes/s ; abonné : {seen} reçues (retard toléré) ; disque {} Kio",
        dt.as_secs_f64(),
        N as f64 / dt.as_secs_f64(),
        disk / 1024
    );
    st.servers.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Routes

struct Client {
    app: Router,
    cookie: Option<String>,
    csrf: Option<String>,
}

impl Client {
    async fn call(&mut self, method: Method, path: &str, body: Option<Value>, csrf: bool) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method.clone()).uri(path).header("host", "127.0.0.1:8580");
        if method != Method::GET {
            b = b.header("content-type", "application/json");
        }
        if let Some(c) = &self.cookie {
            b = b.header("cookie", c);
        }
        if csrf && let Some(t) = &self.csrf {
            b = b.header("x-csrf-token", t);
        }
        let mut req = b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string()))).unwrap();
        req.extensions_mut().insert(ConnectInfo("10.0.0.1:5000".parse::<std::net::SocketAddr>().unwrap()));
        let res = self.app.clone().oneshot(req).await.unwrap();
        if let Some(sc) = res.headers().get("set-cookie").and_then(|v| v.to_str().ok()) {
            self.cookie = Some(sc.split(';').next().unwrap().to_string());
        }
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if let Some(t) = v["me"]["csrf_token"].as_str() {
            self.csrf = Some(t.to_string());
        }
        (status, v)
    }
    async fn post(&mut self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, path, Some(body), true).await
    }
    async fn get(&mut self, path: &str) -> (StatusCode, Value) {
        self.call(Method::GET, path, None, true).await
    }
}

async fn logged_in(data: &Path, seed: &Seed) -> (Arc<AppState>, Client) {
    let (st, token, _) = seeded(data, seed);
    let mut c = Client { app: router(st.clone()), cookie: None, csrf: None };
    let (s, v) = c.post("/api/setup", json!({"token": token, "username": "admin", "password": PW})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (st, c)
}

/// Identifiants hostiles : jamais un chemin, toujours 404 (lecture et action).
#[tokio::test]
async fn identifiants_hostiles() {
    let d = tmp("ids");
    let (_st, mut c) = logged_in(&d, &Seed::default()).await;
    let (s, v) = c.get("/api/servers/1").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for bad in ["0", "-1", "01", "2", "..", "%2e%2e", "..%2f1", "1%00", "1%2f..", "CON", "1e0", "99999999999999999999"]
    {
        let (s, _) = c.get(&format!("/api/servers/{bad}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "GET {bad}");
        let (s, _) = c.post(&format!("/api/servers/{bad}/start"), json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "POST {bad}");
        let (s, _) = c.get(&format!("/api/servers/{bad}/suggest/players?q=a")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "suggestions {bad}");
    }
    let (s, _) = c.get("/api/catalog/forge").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// Toute route qui modifie exige le jeton CSRF ; sans session : 401.
#[tokio::test]
async fn csrf_et_session_exiges() {
    let d = tmp("csrf");
    let (_st, mut c) = logged_in(&d, &Seed::default()).await;
    for (path, body) in [
        ("/api/servers/1/start", json!({})),
        ("/api/servers/1/stop", json!({})),
        ("/api/servers/1/restart", json!({})),
        ("/api/servers/1/eula", json!({"accept": true})),
        ("/api/servers/1/command", json!({"command": "op pirate"})),
        ("/api/servers/1/favorites", json!({"label": "a", "command": "b"})),
        ("/api/servers/1/delete", json!({"reauth": {"password": PW}, "confirm_name": "Survie"})),
        (
            "/api/servers",
            json!({"name": "x", "software": "vanilla", "version": "26.3", "memory_mb": 1024, "port": 25570}),
        ),
        ("/api/account/theme", json!({"primary": "#5fd0a0", "secondary": "#9fb4ff"})),
    ] {
        let (s, v) = c.call(Method::POST, path, Some(body.clone()), false).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path} : {v}");
        let mut anon = Client { app: c.app.clone(), cookie: None, csrf: None };
        let (s, _) = anon.post(path, body).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path} sans session");
    }
}

/// Suppression : le nom recopié est vérifié AVANT la ré-authentification (une faute de frappe ne
/// consomme pas le mot de passe), puis ré-authentification, puis dossier en corbeille.
#[tokio::test]
async fn suppression_nom_puis_reauthentification() {
    let d = tmp("delete");
    let (st, mut c) = logged_in(&d, &Seed::default()).await;
    let (s, v) =
        c.post("/api/servers/1/delete", json!({"reauth": {"password": "faux"}, "confirm_name": "Survi"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("name_mismatch")));
    let (s, v) =
        c.post("/api/servers/1/delete", json!({"reauth": {"password": "faux"}, "confirm_name": "Survie"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid_credentials")));
    assert!(st.servers.exists_in_db(ServerId::parse("1").unwrap()).await);
    let (s, v) = c.post("/api/servers/1/delete", json!({"reauth": {"password": PW}, "confirm_name": " Survie "})).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let t0 = Instant::now();
    while st.servers.get(ServerId::parse("1").unwrap()).is_some() {
        assert!(t0.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!st.servers.exists_in_db(ServerId::parse("1").unwrap()).await);
    assert!(!d.join("servers").join("1").exists());
    let trash: Vec<_> = std::fs::read_dir(d.join("trash")).unwrap().flatten().collect();
    assert_eq!(trash.len(), 1, "dossier gardé dans la corbeille");
    assert!(trash[0].path().join("faux.txt").exists());
    st.audit.flush().await;
    let n: i64 = st.db.with(|c| {
        c.query_row("SELECT count(*) FROM audit_log WHERE action = 'server_deleted'", [], |r| r.get(0)).unwrap()
    });
    assert_eq!(n, 1);
}

#[tokio::test]
async fn eula_commande_theme_favoris() {
    let d = tmp("routes");
    let (st, mut c) = logged_in(&d, &Seed { eula: false, ..Default::default() }).await;
    let (s, v) = c.post("/api/servers/1/start", json!({})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("eula_required")));
    let (s, _) = c.post("/api/servers/1/eula", json!({"accept": false})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!d.join("servers").join("1").join("eula.txt").exists());
    let (s, v) = c.post("/api/servers/1/eula", json!({"accept": true})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["eula"], true);
    let by: Option<i64> =
        st.db.with(|c| c.query_row("SELECT eula_accepted_by FROM servers WHERE id = 1", [], |r| r.get(0)).unwrap());
    assert!(by.is_some(), "acceptation enregistrée avec son compte");
    assert!(std::fs::read_to_string(d.join("servers").join("1").join("eula.txt")).unwrap().contains("eula=true"));

    // Commande : serveur arrêté, puis saisie invalide (retour à la ligne = seconde commande).
    let (s, v) = c.post("/api/servers/1/command", json!({"command": "list"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("not_running")));
    let (s, v) = c.post("/api/servers/1/command", json!({"command": "say a\nop pirate"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid_command")));

    // Thème : couleur invalide refusée, valide gardée et rendue par /me.
    let (s, _) = c.post("/api/account/theme", json!({"primary": "red", "secondary": "#9fb4ff"})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = c.post("/api/account/theme", json!({"primary": "#5fd0a0;x", "secondary": "#9fb4ff"})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let t = json!({"primary": "#ff8a65", "secondary": "#8fd3ff", "tone": "warm", "appearance": "dark"});
    let (s, _) = c.post("/api/account/theme", t.clone()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, me) = c.get("/api/auth/me").await;
    assert_eq!(me["theme"], t);

    // Favoris : ajout, liste, borne, suppression.
    let (s, f) = c.post("/api/servers/1/favorites", json!({"label": "Jour", "command": "/time set day"})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(f["command"], "time set day");
    let (s, _) = c.post("/api/servers/1/favorites", json!({"label": "", "command": "x"})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    for i in 1..rc_manager_shared::FAVORITES_MAX {
        let (s, _) = c.post("/api/servers/1/favorites", json!({"label": format!("f{i}"), "command": "list"})).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, v) = c.post("/api/servers/1/favorites", json!({"label": "trop", "command": "list"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("limit_reached")));
    let (_, list) = c.get("/api/servers/1/favorites").await;
    assert_eq!(list.as_array().unwrap().len(), rc_manager_shared::FAVORITES_MAX);
    let (s, _) = c.post("/api/servers/1/favorites/delete", json!({"id": f["id"]})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = c.post("/api/servers/1/favorites/delete", json!({"id": f["id"]})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// Création : saisies invalides refusées avant tout téléchargement (aucun réseau ici).
#[tokio::test]
async fn creation_saisies_invalides() {
    let d = tmp("create");
    let (_st, mut c) = logged_in(&d, &Seed::default()).await;
    let base = json!({"name": "Nouveau", "software": "vanilla", "version": "26.3", "memory_mb": 2048, "port": 25570});
    for (k, v, code) in [
        ("name", json!(""), "invalid_name"),
        ("name", json!("a\nb"), "invalid_name"),
        ("name", json!("x".repeat(49)), "invalid_name"),
        ("memory_mb", json!(100), "invalid_memory"),
        ("memory_mb", json!(1_000_000), "invalid_memory"),
        ("port", json!(80), "invalid_port"),
        ("version", json!("../26.3"), "invalid_version"),
        ("version", json!("CON"), "invalid_version"),
    ] {
        let mut b = base.clone();
        b[k] = v;
        let (s, r) = c.post("/api/servers", b).await;
        assert_eq!((s, r["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some(code)), "{k}");
    }
    let mut b = base.clone();
    b["software"] = json!("forge");
    let (s, _) = c.post("/api/servers", b).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

fn create_req(port: u16, memory_mb: u32) -> rc_manager_shared::CreateServerRequest {
    rc_manager_shared::CreateServerRequest {
        name: "Nouveau".into(),
        software: rc_manager_shared::Software::Vanilla,
        version: "26.3".into(),
        memory_mb,
        port,
        java: rc_manager_shared::JavaChoice::Managed,
        accept_eula: false,
    }
}

fn settings_req(memory_mb: u32, port: u16) -> rc_manager_shared::ServerSettingsRequest {
    rc_manager_shared::ServerSettingsRequest {
        name: "Survie".into(),
        memory_mb,
        port,
        auto_restart: false,
        java: rc_manager_shared::JavaChoice::Path { path: String::new() },
    }
}

/// Bornes (nombre de serveurs, mémoire totale), création tout ou rien, réglages refusés pendant
/// un démarrage.
#[tokio::test]
async fn bornes_creation_atomique_et_reglages() {
    use rc_manager::servers::Limits;
    let d = tmp("limits");
    let seed = Seed { mode: "noport", ..Default::default() };
    let (st, _, id) = seeded(&d, &seed);
    let mgr = &st.servers;
    // Compte créateur (clé étrangère des serveurs).
    st.db.with(|c| {
        c.execute("INSERT INTO users (id, username, password_hash, created_at) VALUES (1, 'admin', 'x', 0)", [])
            .unwrap()
    });
    mgr.catalog.preload(
        rc_manager_shared::Software::Vanilla,
        vec![rc_manager_shared::GameVersion { id: "26.3".into(), stable: true }],
    );
    let srv = mgr.get(id).unwrap();
    let java = srv.row().java_path.unwrap();
    let keep_java = |m: u32, p: u16| {
        let mut r = settings_req(m, p);
        r.java = rc_manager_shared::JavaChoice::Path { path: java.clone() };
        r
    };
    mgr.set_limits(Limits { max_servers: 1, ..Limits::default() });
    assert_eq!(
        mgr.create(create_req(free_port(), 1024), 1, true).await.err().map(|e| e.code),
        Some(ErrorCode::LimitReached)
    );
    mgr.set_limits(Limits { max_servers: 10, max_memory_mb: 1500, max_installs: 1, ..Limits::default() });
    assert_eq!(
        mgr.create(create_req(free_port(), 1024), 1, true).await.err().map(|e| e.code),
        Some(ErrorCode::LimitReached)
    );
    assert!(mgr.update(&srv, keep_java(1400, seed.port), true).await.is_ok());
    assert_eq!(
        mgr.update(&srv, keep_java(2048, seed.port), true).await.err().map(|e| e.code),
        Some(ErrorCode::LimitReached)
    );
    mgr.set_limits(Limits::default());

    // Dossier impossible à créer (un fichier à sa place) : ni ligne en base, ni serveur.
    std::fs::write(d.join("servers").join("2"), b"bouchon").unwrap();
    assert_eq!(
        mgr.create(create_req(free_port(), 1024), 1, true).await.err().map(|e| e.code),
        Some(ErrorCode::Internal)
    );
    let n: i64 = st.db.with(|c| c.query_row("SELECT count(*) FROM servers", [], |r| r.get(0)).unwrap());
    assert_eq!(n, 1, "ligne orpheline");
    assert_eq!(mgr.list().len(), 1);

    // Pendant le démarrage (port jamais ouvert : reste « démarrage ») : réglages refusés.
    mgr.start(&srv).unwrap();
    wait(&srv, "démarrage", Duration::from_secs(20), |i| i.state == ServerState::Starting && i.op.is_none()).await;
    assert_eq!(
        mgr.update(&srv, keep_java(1024, seed.port), true).await.err().map(|e| e.code),
        Some(ErrorCode::OperationInProgress)
    );
    mgr.shutdown().await;
}
