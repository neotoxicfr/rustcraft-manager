//! Fichiers de configuration (onglet « Réglages ») :
//! - aller-retour sur des fichiers RÉELS de chaque logiciel (`tests/fixtures/configs`, écrits par
//!   les serveurs officiels, Paper, Purpur, Folia, Fabric, Quilt lors des essais) : rien ne change
//!   si rien ne change, chaque édition ne touche que sa ligne, ajout puis retrait d'un élément
//!   de liste rend le fichier d'origine à l'octet ;
//! - routes : liste blanche et confinement, CSRF, vérification, enregistrement (empreinte,
//!   analyseur, clés gérées, refus pendant un démarrage), historique et restauration.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use rc_manager::config::Config;
use rc_manager::configs::{check, entries};
use rc_manager::db::Db;
use rc_manager::{AppState, new_state, router};
use rc_manager_shared::{ConfigEdit, ConfigFormat, ConfigSeg, ConfigValue, EntryKind};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/configs");
const PW: &str = "un mot de passe solide";
/// Places de transfert du gestionnaire : par compte et pour tout le processus. Tous les tests
/// se connectent avec le compte 1 : ceux qui envoient ou téléchargent passent un par un.
static TRANSFERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixtures() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new(FIXTURES), Path::new(FIXTURES), &mut out);
    out.sort();
    assert!(out.len() >= 20, "fichiers réels manquants dans {FIXTURES}");
    out
}

fn changed(v: &ConfigValue, props: bool) -> ConfigValue {
    match v {
        ConfigValue::Bool(b) => ConfigValue::Bool(!b),
        ConfigValue::Int(n) => ConfigValue::Int(n.wrapping_add(1)),
        ConfigValue::Float(f) => ConfigValue::Float(f + 1.5),
        ConfigValue::Str(s) if props && s == "true" => ConfigValue::Str("false".into()),
        ConfigValue::Str(s) => ConfigValue::Str(format!("{s}x")),
        ConfigValue::Null => ConfigValue::Str("x".into()),
    }
}

/// Aller-retour sans perte sur chaque fichier réel, pour chaque valeur et chaque liste.
#[test]
fn aller_retour_sur_des_fichiers_reels() {
    let mut edits = 0;
    for (rel, text) in fixtures() {
        let format = ConfigFormat::from_name(&rel).unwrap();
        let tree = entries(format, &text).unwrap_or_else(|e| panic!("{rel} : {e:?}"));
        // Arbre vide permis seulement pour un fichier de commentaires (lithium.properties).
        let only_comments = text.lines().all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'));
        assert!(!tree.is_empty() || only_comments, "{rel} : arbre vide");
        let c = check(format, &text, &[]);
        assert!(c.error.is_none() && c.text.is_none(), "{rel}");
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        for e in &tree {
            match (&e.kind, &e.value) {
                (EntryKind::Value, Some(v)) => {
                    // Même valeur : fichier identique à l'octet.
                    let same = check(format, &text, &[ConfigEdit::Set { path: e.path.clone(), value: v.clone() }]);
                    assert_eq!(same.text.as_deref(), Some(text.as_str()), "{rel} {:?}", e.path);
                    // Autre valeur : seule la ligne de la valeur change.
                    let props = format == ConfigFormat::Properties;
                    let c = check(format, &text, &[ConfigEdit::Set { path: e.path.clone(), value: changed(v, props) }]);
                    if c.error.is_some() {
                        // Seul refus permis : une valeur non éditable du mode visuel.
                        continue;
                    }
                    let out = c.text.unwrap();
                    let new_lines: Vec<&str> = out.split_inclusive('\n').collect();
                    assert_eq!(new_lines.len(), lines.len(), "{rel} {:?}", e.path);
                    let diff: Vec<usize> = (0..lines.len()).filter(|&i| lines[i] != new_lines[i]).collect();
                    assert_eq!(diff.len(), 1, "{rel} {:?} : {diff:?}", e.path);
                    // Retour à la valeur d'origine : le fichier d'origine à l'octet (style de la
                    // valeur gardé : apostrophes, guillemets, simple). Les nombres à virgule
                    // s'écrivent sous leur forme la plus courte (`0.10` redevient `0.1`).
                    if !matches!(v, ConfigValue::Float(_)) {
                        let back = check(format, &out, &[ConfigEdit::Set { path: e.path.clone(), value: v.clone() }]);
                        assert_eq!(back.text.as_deref(), Some(text.as_str()), "{rel} {:?} : retour", e.path);
                    }
                    edits += 1;
                }
                (EntryKind::List, _) if e.editable_list => {
                    let n =
                        tree.iter().filter(|x| x.path.len() == e.path.len() + 1 && x.path.starts_with(&e.path)).count();
                    let push = ConfigEdit::Push { path: e.path.clone(), value: ConfigValue::Str("ajout".into()) };
                    let mut idx = e.path.clone();
                    idx.push(ConfigSeg::Index(n));
                    let c = check(format, &text, &[push, ConfigEdit::Remove { path: idx }]);
                    assert!(c.error.is_none(), "{rel} {:?} : {:?}", e.path, c.error);
                    assert_eq!(c.text.as_deref(), Some(text.as_str()), "{rel} {:?} : ajout puis retrait", e.path);
                    edits += 1;
                }
                _ => {}
            }
        }
    }
    assert!(edits > 1000, "{edits} éditions seulement");
}

/// `server.properties` de chaque version : les clés écrites par le jeu sont toutes lues.
#[test]
fn proprietes_de_chaque_version() {
    for (rel, text) in fixtures().into_iter().filter(|(r, _)| r.ends_with("server.properties")) {
        let keys = text.lines().filter(|l| !l.starts_with('#') && l.contains('=')).count();
        let tree = entries(ConfigFormat::Properties, &text).unwrap();
        assert_eq!(tree.len(), keys, "{rel}");
        let lt = tree.iter().find(|e| e.path == [ConfigSeg::Key("level-type".into())]).unwrap();
        assert!(matches!(&lt.value, Some(ConfigValue::Str(s)) if !s.contains('\\')), "{rel} : échappement résolu");
    }
}

// ---------------------------------------------------------------------------------------------
// Routes

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rcm-cfgapi-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

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
        let bytes = axum::body::to_bytes(res.into_body(), 8 << 20).await.unwrap();
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
    /// Requête au corps brut ; rend aussi les en-têtes et les octets de la réponse.
    async fn raw(
        &mut self,
        method: Method,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut b = Request::builder().method(method).uri(path).header("host", "127.0.0.1:8580");
        if !content_type.is_empty() {
            b = b.header("content-type", content_type);
        }
        if let Some(c) = &self.cookie {
            b = b.header("cookie", c);
        }
        if let Some(t) = &self.csrf {
            b = b.header("x-csrf-token", t);
        }
        let mut req = b.body(Body::from(body)).unwrap();
        req.extensions_mut().insert(ConnectInfo("10.0.0.1:5000".parse::<std::net::SocketAddr>().unwrap()));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = axum::body::to_bytes(res.into_body(), 64 << 20).await.unwrap();
        (status, headers, bytes.to_vec())
    }
    async fn upload(&mut self, dir: &str, name: &str, data: &[u8], overwrite: bool) -> (StatusCode, Value) {
        let path = format!("/api/servers/1/files/upload?path={dir}&name={name}&overwrite={overwrite}");
        let (s, _, b) = self.raw(Method::POST, &path, "application/octet-stream", data.to_vec()).await;
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }
}

/// Serveur Paper (fichiers réels) piloté par le faux java, et un compte connecté.
async fn paper(data: &Path, mode: &str) -> (Arc<AppState>, Client, PathBuf) {
    paper_cfg(data, mode, 1024).await
}

/// Même serveur, envoi de fichier borné à `upload_mb` Mio.
async fn paper_cfg(data: &Path, mode: &str, upload_mb: u64) -> (Arc<AppState>, Client, PathBuf) {
    let db = Db::open_memory().unwrap();
    let bin = data.join("jdk").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let java = bin.join(if cfg!(windows) { "java.exe" } else { "java" });
    std::fs::copy(env!("CARGO_BIN_EXE_rcm-faux-java"), &java).unwrap();
    let port = free_port();
    db.with(|c| {
        c.execute(
            "INSERT INTO servers (id, name, software, game_version, memory_mb, port, rcon_port, rcon_password_enc,
              java_major, java_path, launch, eula_accepted_at, created_at)
             VALUES (1, 'Survie', 'paper', '26.3', 1024, ?1, ?2, '', 25, ?3, '{\"kind\":\"jar\",\"jar\":\"server.jar\"}', 1, 0)",
            rusqlite::params![port, free_port(), java.to_string_lossy()],
        )
        .unwrap();
    });
    let enc = db.keys().encrypt(&rc_manager::crypto::aad("servers", "rcon_password", 1), b"motdepasse");
    db.with(|c| c.execute("UPDATE servers SET rcon_password_enc = ?1 WHERE id = 1", [enc]).unwrap());
    let dir = data.join("servers").join("1");
    std::fs::create_dir_all(dir.join("config")).unwrap();
    for f in
        ["server.properties", "bukkit.yml", "spigot.yml", "config/paper-global.yml", "config/paper-world-defaults.yml"]
    {
        std::fs::copy(Path::new(FIXTURES).join("paper-26.3").join(f), dir.join(f)).unwrap();
    }
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    let props = rc_manager::props::patch(&props, &[("server-port", port.to_string())]);
    std::fs::write(dir.join("server.properties"), props).unwrap();
    std::fs::write(dir.join("faux.txt"), mode).unwrap();
    let mut cfg = Config::with_data_dir(data.to_path_buf());
    cfg.upload_max_mb = upload_mb;
    let (st, token) = new_state(cfg, db);
    let mut c = Client { app: router(st.clone()), cookie: None, csrf: None };
    let (s, v) = c.post("/api/setup", json!({"token": token.unwrap(), "username": "admin", "password": PW})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (st, c, dir)
}

/// Liste blanche et confinement par les routes : tout chemin hostile = 404, sans lecture.
#[tokio::test]
async fn chemins_hostiles_par_les_routes() {
    let d = tmp("hostiles");
    let (_st, mut c, dir) = paper(&d, "").await;
    std::fs::write(d.join("dehors.yml"), "a: 1\n").unwrap();
    std::fs::write(dir.join("ops.json"), "[]").unwrap();
    let (s, v) = c.get("/api/servers/1/configs").await;
    assert_eq!(s, StatusCode::OK);
    let paths: Vec<&str> = v.as_array().unwrap().iter().map(|f| f["path"].as_str().unwrap()).collect();
    assert_eq!(
        paths,
        ["server.properties", "bukkit.yml", "spigot.yml", "config/paper-global.yml", "config/paper-world-defaults.yml"]
    );
    for bad in [
        "../dehors.yml",
        "..%2Fdehors.yml",
        "%2e%2e/dehors.yml",
        "usercache.json",
        "purpur.yml",
        "C:/x.yml",
        "config/../bukkit.yml",
    ] {
        let (s, _) = c.get(&format!("/api/servers/1/config?path={bad}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "lecture {bad}");
        let (s, _) = c.post("/api/servers/1/config/check", json!({"path": bad, "text": "a: 1\n"})).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "vérification {bad}");
        let (s, _) =
            c.post("/api/servers/1/config/save", json!({"path": bad, "text": "a: 1\n", "base_hash": ""})).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "écriture {bad}");
    }
    assert_eq!(std::fs::read_to_string(d.join("dehors.yml")).unwrap(), "a: 1\n");
    // CSRF exigé pour vérifier et enregistrer ; session pour lire.
    for path in ["/api/servers/1/config/check", "/api/servers/1/config/save"] {
        let body = json!({"path": "bukkit.yml", "text": "a: 1\n", "base_hash": ""});
        let (s, _) = c.call(Method::POST, path, Some(body), false).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}");
    }
    let mut anon = Client { app: c.app.clone(), cookie: None, csrf: None };
    let (s, _) = anon.get("/api/servers/1/config?path=bukkit.yml").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// Enregistrement : empreinte, analyseur, clés gérées, historique, restauration, audit.
#[tokio::test]
async fn enregistrement_historique_restauration() {
    let d = tmp("save");
    let (st, mut c, dir) = paper(&d, "").await;
    let orig = std::fs::read_to_string(dir.join("spigot.yml")).unwrap();
    let (s, f) = c.get("/api/servers/1/config?path=spigot.yml").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(f["text"].as_str(), Some(orig.as_str()));
    let hash = f["hash"].as_str().unwrap().to_string();
    // Vérification avec une édition visuelle : texte rendu, fichier inchangé.
    let (s, v) = c
        .post(
            "/api/servers/1/config/check",
            json!({"path": "spigot.yml", "text": orig, "edits": [
                {"op": "set", "path": ["settings", "debug"], "value": {"t": "bool", "v": true}}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let edited = v["text"].as_str().unwrap().to_string();
    assert_eq!(edited, orig.replacen("  debug: false", "  debug: true", 1));
    assert_eq!(std::fs::read_to_string(dir.join("spigot.yml")).unwrap(), orig);
    // Analyseur : texte invalide refusé (ligne donnée par la vérification), rien d'écrit.
    let bad = format!("{orig}\nsettings: [\n");
    let (_, v) = c.post("/api/servers/1/config/check", json!({"path": "spigot.yml", "text": bad})).await;
    assert!(v["error"]["line"].as_u64().unwrap() > 1, "{v}");
    // Valide mais non vérifiable (plusieurs documents) : refusé pour tous, cause rendue pour
    // l'interface ; ailleurs, simple avertissement (enregistrable par un administrateur).
    let docs = format!("{orig}---\na: 1\n");
    let (_, v) = c.post("/api/servers/1/config/check", json!({"path": "spigot.yml", "text": docs})).await;
    assert_eq!(v["error"]["unverifiable"], "many_documents", "{v}");
    let (_, v) =
        c.post("/api/servers/1/config/check", json!({"path": "bukkit.yml", "text": "a: !!set {x: null}\n"})).await;
    assert_eq!((v["error"].is_null(), v["unverifiable"].as_str()), (true, Some("collection_tag")), "{v}");
    let (s, v) =
        c.post("/api/servers/1/config/save", json!({"path": "spigot.yml", "text": bad, "base_hash": hash})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("config_invalid")));
    // Empreinte : fichier changé sur le disque depuis l'ouverture.
    let (s, v) =
        c.post("/api/servers/1/config/save", json!({"path": "spigot.yml", "text": edited, "base_hash": "0"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("config_changed")));
    assert_eq!(std::fs::read_to_string(dir.join("spigot.yml")).unwrap(), orig);
    // Identique : rien d'écrit, pas d'historique.
    let (s, v) =
        c.post("/api/servers/1/config/save", json!({"path": "spigot.yml", "text": orig, "base_hash": hash})).await;
    assert_eq!((s, v["unchanged"].as_bool()), (StatusCode::OK, Some(true)));
    // Enregistrement : écrit tel quel, version d'avant dans l'historique.
    let (s, v) =
        c.post("/api/servers/1/config/save", json!({"path": "spigot.yml", "text": edited, "base_hash": hash})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["restart_needed"].as_bool(), Some(false));
    assert_eq!(std::fs::read_to_string(dir.join("spigot.yml")).unwrap(), edited);
    let names: Vec<String> =
        std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "aucun temporaire restant : {names:?}");
    let (_, h) = c.get("/api/servers/1/config/history?path=spigot.yml").await;
    let h = h.as_array().unwrap().clone();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0]["user"].as_str(), Some("admin"));
    let (s, ver) = c.get(&format!("/api/servers/1/config/history/{}", h[0]["id"])).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ver["text"].as_str(), Some(orig.as_str()), "état du disque avant l'écriture");
    // Contenu chiffré en base.
    let enc: String =
        st.db.with(|c| c.query_row("SELECT content_enc FROM server_config_history", [], |r| r.get(0)).unwrap());
    assert!(!enc.contains("bungeecord"));
    // Restauration : la version relue s'enregistre comme un texte.
    let (_, f) = c.get("/api/servers/1/config?path=spigot.yml").await;
    let (s, _) = c
        .post("/api/servers/1/config/save", json!({"path": "spigot.yml", "text": ver["text"], "base_hash": f["hash"]}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(std::fs::read_to_string(dir.join("spigot.yml")).unwrap(), orig);
    let (s, _) = c.get("/api/servers/1/config/history/99999").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    st.audit.flush().await;
    let n: i64 = st.db.with(|c| {
        c.query_row("SELECT count(*) FROM audit_log WHERE action = 'config_saved'", [], |r| r.get(0)).unwrap()
    });
    assert_eq!(n, 2);
}

/// Clés gérées par le gestionnaire : refusées à la vérification (clé nommée) et à l'écriture.
#[tokio::test]
async fn cles_gerees_refusees() {
    let d = tmp("gerees");
    let (_st, mut c, dir) = paper(&d, "").await;
    let (_, f) = c.get("/api/servers/1/config?path=server.properties").await;
    let text = f["text"].as_str().unwrap();
    // Valeur contraire de celle du fichier (le Paper d'essai date d'avant la coupure de RCON).
    let rcon = if rc_manager::props::get(text, "enable-rcon").as_deref() == Some("true") { "false" } else { "true" };
    for (k, v) in [("server-port", "25999"), ("enable-rcon", rcon), ("rcon.password", "x"), ("query.port", "1")] {
        let bad = rc_manager::props::patch(text, &[(k, v.into())]);
        let (_, r) = c.post("/api/servers/1/config/check", json!({"path": "server.properties", "text": bad})).await;
        assert_eq!(r["error"]["managed_key"].as_str(), Some(k));
        let (s, _) = c
            .post(
                "/api/servers/1/config/save",
                json!({"path": "server.properties", "text": bad, "base_hash": f["hash"]}),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{k}");
    }
    let ok = rc_manager::props::patch(text, &[("motd", "Bonjour".into())]);
    let (s, _) = c
        .post("/api/servers/1/config/save", json!({"path": "server.properties", "text": ok, "base_hash": f["hash"]}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(std::fs::read_to_string(dir.join("server.properties")).unwrap(), ok);
}

/// Écriture refusée pendant un démarrage ; « redémarrage nécessaire » quand le serveur tourne.
#[tokio::test]
async fn refus_pendant_un_demarrage() {
    let d = tmp("demarrage");
    let (st, mut c, dir) = paper(&d, "").await;
    let (_, f) = c.get("/api/servers/1/config?path=bukkit.yml").await;
    let text = f["text"].as_str().unwrap().to_string();
    let edited = text.replacen("allow-end: true", "allow-end: false", 1);
    assert_ne!(edited, text);
    // Serveur de gestion JSON-RPC allumé à la main sur toutes les interfaces : coupé au lancement.
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    let props = rc_manager::props::patch(
        &props,
        &[("management-server-enabled", "true".into()), ("management-server-host", "0.0.0.0".into())],
    );
    std::fs::write(dir.join("server.properties"), props).unwrap();
    let (s, v) = c.post("/api/servers/1/start", json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let (s, v) = c
        .post("/api/servers/1/config/save", json!({"path": "bukkit.yml", "text": edited, "base_hash": f["hash"]}))
        .await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("server_busy")));
    assert_eq!(std::fs::read_to_string(dir.join("bukkit.yml")).unwrap(), text);
    let srv = st.servers.get(rc_manager::paths::ServerId::parse("1").unwrap()).unwrap();
    let t0 = std::time::Instant::now();
    while srv.info().state != rc_manager_shared::ServerState::Running || srv.info().op.is_some() {
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", srv.info());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (s, v) = c
        .post("/api/servers/1/config/save", json!({"path": "bukkit.yml", "text": edited, "base_hash": f["hash"]}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["restart_needed"].as_bool(), Some(true));
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    assert_eq!(rc_manager::props::get(&props, "management-server-enabled").as_deref(), Some("false"));
    let (s, _) = c.post("/api/servers/1/stop", json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let t0 = std::time::Instant::now();
    while srv.info().state != rc_manager_shared::ServerState::Stopped {
        assert!(t0.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Corps : un fichier de plus de 1 Mio est refusé (413), un fichier de 600 Kio passe (au-delà
/// des 64 Kio des autres routes).
#[tokio::test]
async fn tailles_bornees() {
    let d = tmp("tailles");
    let (_st, mut c, _dir) = paper(&d, "").await;
    let big = format!("a: '{}'\n", "x".repeat(600 * 1024));
    let (s, v) = c.post("/api/servers/1/config/check", json!({"path": "bukkit.yml", "text": big})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let huge = "x".repeat(1024 * 1024 + 1);
    let (s, v) = c.post("/api/servers/1/config/check", json!({"path": "bukkit.yml", "text": huge})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("file_too_large")));
}

async fn chk(c: &mut Client, path: &str, text: String) -> Value {
    c.post("/api/servers/1/config/check", json!({"path": path, "text": text})).await.1
}

/// Réglages réservés aux administrateurs (relecture : 2 et 3) : serveur de gestion JSON-RPC
/// verrouillé pour tous ; `online-mode`, `restart-script`, `bungeecord`, ports des mods refusés aux
/// autres comptes (texte comme visuel), avertis pour un administrateur ; chemins qui sortent du
/// dossier refusés à tous, et au lancement.
#[tokio::test]
async fn reglages_reserves_et_chemins() {
    let d = tmp("reserves");
    let (st, mut c, dir) = paper(&d, "").await;
    let (_, p) = c.get("/api/servers/1/config?path=server.properties").await;
    let props = p["text"].as_str().unwrap().to_string();
    let (_, s) = c.get("/api/servers/1/config?path=spigot.yml").await;
    let spigot = s["text"].as_str().unwrap().to_string();
    // Serveur de gestion : clé gérée, même pour un administrateur.
    for (k, v) in [
        ("management-server-enabled", "true"),
        ("management-server-host", "0.0.0.0"),
        ("management-server-tls-keystore", "C:/x.jks"),
    ] {
        let r = chk(&mut c, "server.properties", rc_manager::props::patch(&props, &[(k, v.into())])).await;
        assert_eq!(r["error"]["managed_key"].as_str(), Some(k), "{r}");
    }
    // Chemins hors du dossier : refusés à tous.
    for bad in ["../autre", "C:/Windows", "/etc", "mondes/../../x", "NUL"] {
        let r = chk(&mut c, "server.properties", rc_manager::props::patch(&props, &[("level-name", bad.into())])).await;
        assert_eq!(r["error"]["unsafe_key"].as_str(), Some("level-name"), "{bad} {r}");
    }
    let r =
        chk(&mut c, "server.properties", rc_manager::props::patch(&props, &[("level-name", "mondes/survie".into())]))
            .await;
    assert!(r["error"].is_null(), "{r}");
    let script = |v: &str| spigot.replace("restart-script: ./start.sh", &format!("restart-script: {v}"));
    for bad in ["/bin/sh", "../../evil.sh", "'C:\\x.bat'", "'a.bat & calc'", "'x;rm -rf y'", "'./start.sh x'"] {
        let r = chk(&mut c, "spigot.yml", script(bad)).await;
        assert_eq!(r["error"]["unsafe_key"].as_str(), Some("settings.restart-script"), "{bad} {r}");
    }
    // Administrateur : réglage réservé permis, signalé.
    let online_off = rc_manager::props::patch(&props, &[("online-mode", "false".into())]);
    let r = chk(&mut c, "server.properties", online_off.clone()).await;
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(r["sensitive"], json!(["online-mode"]));
    // Autre compte : refus nommé à la vérification, 403 à l'écriture, fichier intact.
    st.db.with(|c| c.execute("UPDATE users SET is_admin = 0", []).unwrap());
    let cases: Vec<(&'static str, String, &str, &str)> = vec![
        ("server.properties", online_off, "online-mode", props.as_str()),
        ("spigot.yml", script("./restart.sh"), "settings.restart-script", spigot.as_str()),
        ("spigot.yml", spigot.replace("bungeecord: false", "bungeecord: true"), "settings.bungeecord", spigot.as_str()),
    ];
    for (path, text, key, orig) in cases {
        let r = chk(&mut c, path, text.clone()).await;
        assert_eq!(r["error"]["admin_key"].as_str(), Some(key), "{r}");
        let (_, f) = c.get(&format!("/api/servers/1/config?path={path}")).await;
        let (s, v) =
            c.post("/api/servers/1/config/save", json!({"path": path, "text": text, "base_hash": f["hash"]})).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")), "{key}");
        assert_eq!(std::fs::read_to_string(dir.join(path)).unwrap(), orig);
    }
    // Édition visuelle d'un réglage réservé : même refus (le texte produit est contrôlé).
    let (_, r) = c
        .post(
            "/api/servers/1/config/check",
            json!({"path": "server.properties", "text": props, "edits": [
                {"op": "set", "path": ["online-mode"], "value": {"t": "str", "v": "false"}}
            ]}),
        )
        .await;
    assert_eq!(r["error"]["admin_key"].as_str(), Some("online-mode"), "{r}");
    // Réglage ordinaire : permis.
    let motd = rc_manager::props::patch(&props, &[("motd", "Salut".into())]);
    let r = chk(&mut c, "server.properties", motd).await;
    assert!(r["error"].is_null() && r["sensitive"].is_null(), "{r}");
    st.audit.flush().await;
    let n: i64 = st.db.with(|c| {
        c.query_row("SELECT count(*) FROM audit_log WHERE action = 'config_refused'", [], |r| r.get(0)).unwrap()
    });
    assert_eq!(n, 3);
    // Lancement refusé si un chemin sort du dossier (fichier modifié à la main).
    std::fs::write(dir.join("server.properties"), rc_manager::props::patch(&props, &[("level-name", "../x".into())]))
        .unwrap();
    let (s, v) = c.post("/api/servers/1/start", json!({})).await;
    let srv = st.servers.get(rc_manager::paths::ServerId::parse("1").unwrap()).unwrap();
    let t0 = std::time::Instant::now();
    while srv.info().op.is_some() {
        assert!(t0.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    let state = srv.info().state;
    assert!(
        matches!(state, rc_manager_shared::ServerState::Stopped | rc_manager_shared::ServerState::Crashed),
        "{s} {v} {state:?}"
    );
}

/// Chemin en double (YAML, JSON) : le jeu lit la dernière occurrence, le visuel viserait la
/// première : arbre refusé avec le chemin nommé, éditions refusées, texte toujours vérifié.
#[test]
fn doublons_refuses_en_visuel() {
    for (f, t, dup) in [
        (ConfigFormat::Yaml, "a: 1\nb:\n  c: 2\nb:\n  c: 3\n", "b"),
        (ConfigFormat::Yaml, "a: 1\na: 2\n", "a"),
        (ConfigFormat::Json, "{\"a\": 1, \"a\": 2}", "a"),
        (ConfigFormat::Json5, "{a: {b: 1, b: 2}}", "a.b"),
    ] {
        let c = check(f, t, &[]);
        assert!(c.error.is_none(), "{t}");
        assert_eq!(c.duplicate.as_deref(), Some(dup), "{t}");
        assert!(c.entries.is_empty(), "{t}");
        let e = check(f, t, &[ConfigEdit::Set { path: vec![ConfigSeg::Key("a".into())], value: ConfigValue::Int(9) }]);
        assert!(e.text.is_none() && e.duplicate.is_some(), "{t}");
    }
    assert!(check(ConfigFormat::Yaml, "a: 1\nb: 2\n", &[]).duplicate.is_none());
}

/// Historique : ligne écrite APRÈS l'écriture réussie (une écriture ratée n'en laisse pas) ;
/// quota global en octets, les plus anciennes versions partent.
#[tokio::test]
async fn historique_apres_ecriture_et_quota() {
    let d = tmp("histo");
    let (st, mut c, dir) = paper(&d, "").await;
    let count = |st: &AppState| -> i64 {
        st.db.with(|c| c.query_row("SELECT count(*) FROM server_config_history", [], |r| r.get(0)).unwrap())
    };
    let (_, f) = c.get("/api/servers/1/config?path=bukkit.yml").await;
    let text = f["text"].as_str().unwrap().replacen("allow-end: true", "allow-end: false", 1);
    // Écriture impossible : fichier en lecture seule (Windows), dossier en lecture seule (Unix).
    let target = if cfg!(windows) { dir.join("bukkit.yml") } else { dir.clone() };
    let mut perm = std::fs::metadata(&target).unwrap().permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(&target, perm.clone()).unwrap();
    let (s, _) =
        c.post("/api/servers/1/config/save", json!({"path": "bukkit.yml", "text": text, "base_hash": f["hash"]})).await;
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    std::fs::set_permissions(&target, perm).unwrap();
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(count(&st), 0, "aucune version fantôme");
    // Quota global : des versions anciennes qui le remplissent déjà partent à l'enregistrement.
    let big = rc_manager::configs_api::HISTORY_TOTAL_BYTES as i64 / 2;
    st.db.with(|c| {
        for i in 0..3 {
            c.execute(
                "INSERT INTO server_config_history (server_id, path, ts, user_id, size, content_enc)
                 VALUES (1, 'spigot.yml', ?1, NULL, ?2, 'x')",
                rusqlite::params![i, big],
            )
            .unwrap();
        }
    });
    let (s, v) =
        c.post("/api/servers/1/config/save", json!({"path": "bukkit.yml", "text": text, "base_hash": f["hash"]})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let total: i64 =
        st.db.with(|c| c.query_row("SELECT sum(size) FROM server_config_history", [], |r| r.get(0)).unwrap());
    assert!(total <= rc_manager::configs_api::HISTORY_TOTAL_BYTES as i64, "{total}");
    let newest: String = st.db.with(|c| {
        c.query_row("SELECT path FROM server_config_history ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap()
    });
    assert_eq!(newest, "bukkit.yml");
}

fn json_file(dir: &Path, f: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join(f)).unwrap()).unwrap()
}

async fn wait_state(st: &AppState, want: rc_manager_shared::ServerState) {
    let srv = st.servers.get(rc_manager::paths::ServerId::parse("1").unwrap()).unwrap();
    let t0 = std::time::Instant::now();
    while srv.info().state != want || srv.info().op.is_some() {
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", srv.info());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Listes d'accès, serveur arrêté : fichiers créés, entrées écrites sans perte (UUID hors ligne
/// ou de `usercache.json`, niveau, limite, raison, expiration), valeurs hostiles refusées,
/// fichier illisible jamais écrasé, interrupteurs de la liste blanche, historique et audit.
#[tokio::test]
async fn listes_d_acces_serveur_arrete() {
    let d = tmp("acces");
    let (st, mut c, dir) = paper(&d, "").await;
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    std::fs::write(dir.join("server.properties"), rc_manager::props::patch(&props, &[("online-mode", "false".into())]))
        .unwrap();
    let (s, v) = c.get("/api/servers/1/access").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["online_mode"], false);
    // Une lecture n'écrit rien ; le mode JSON ouvre une liste absente comme vide, l'enregistrement
    // la crée.
    for f in ["whitelist.json", "ops.json", "banned-players.json", "banned-ips.json"] {
        assert!(!dir.join(f).exists(), "{f} non créé par une lecture");
        let (s, v) = c.get(&format!("/api/servers/1/config?path={f}")).await;
        assert_eq!((s, v["text"].as_str()), (StatusCode::OK, Some("[]")), "{v}");
        let (s, chk) = c.post("/api/servers/1/config/check", json!({"path": f, "text": v["text"]})).await;
        assert!(s == StatusCode::OK && chk["error"].is_null(), "liste absente : valide dès l'ouverture {chk}");
    }
    let (_, v) = c.get("/api/servers/1/config?path=banned-ips.json").await;
    let save = json!({"path": "banned-ips.json", "text": "[]", "base_hash": v["hash"]});
    let (s, v) = c.post("/api/servers/1/config/save", save).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(std::fs::read_to_string(dir.join("banned-ips.json")).unwrap(), "[]");
    let (s, _) = c.get("/api/servers/1/config?path=config/whitelist.json").await;
    assert_eq!(s, StatusCode::NOT_FOUND, "seules les listes du dossier du serveur");
    let add = |list: &str, target: &str, extra: Value| {
        let mut b = json!({"list": list, "target": target});
        b.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        b
    };
    let (s, v) = c.post("/api/servers/1/access/add", add("whitelist", "Steve", json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["by_console"], false);
    assert_eq!(
        json_file(&dir, "whitelist.json"),
        json!([{"uuid": rc_manager::access::offline_uuid("Steve"), "name": "Steve"}])
    );
    let (s, _) = c
        .post("/api/servers/1/access/add", add("ops", "Steve", json!({"level": 2, "bypasses_player_limit": true})))
        .await;
    assert_eq!(s, StatusCode::OK);
    let ops = json_file(&dir, "ops.json");
    assert_eq!((ops[0]["level"].clone(), ops[0]["bypassesPlayerLimit"].clone()), (json!(2), json!(true)));
    let later = rc_manager::db::now() + 3600;
    let (s, _) = c
        .post(
            "/api/servers/1/access/add",
            add("banned_players", "Griefer", json!({"reason": "Grief", "expires": later})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let b = json_file(&dir, "banned-players.json");
    assert_eq!(b[0]["reason"], "Grief");
    assert_eq!(b[0]["expires"], rc_manager::access::game_date(later));
    let (s, _) = c.post("/api/servers/1/access/add", add("banned_ips", " 10.0.0.5 ", json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_file(&dir, "banned-ips.json")[0]["expires"], "forever");
    // Champ inconnu ajouté à la main : gardé quand l'entrée est remplacée.
    let mut w = json_file(&dir, "ops.json");
    w[0]["note"] = json!("x");
    std::fs::write(dir.join("ops.json"), serde_json::to_string_pretty(&w).unwrap()).unwrap();
    let (s, _) = c.post("/api/servers/1/access/add", add("ops", "steve", json!({"level": 4}))).await;
    assert_eq!(s, StatusCode::OK);
    let ops = json_file(&dir, "ops.json");
    assert_eq!(
        (ops.as_array().unwrap().len(), ops[0]["level"].clone(), ops[0]["note"].clone()),
        (1, json!(4), json!("x"))
    );
    // Valeurs hostiles : 422, rien d'écrit.
    let before = std::fs::read(dir.join("ops.json")).unwrap();
    for bad in [
        add("ops", "Bob;op x", json!({})),
        add("ops", "Bob\nop x", json!({})),
        add("ops", "", json!({})),
        add("ops", &"a".repeat(17), json!({})),
        add("ops", "Bob", json!({"level": 5})),
        add("ops", "Bob", json!({"level": 0})),
        add("banned_players", "Bob", json!({"reason": "a\nop Bob"})),
        add("banned_players", "Bob", json!({"expires": 1})),
        add("banned_ips", "1.2.3.4 x", json!({})),
        add("banned_ips", "../x", json!({})),
    ] {
        let (s, v) = c.post("/api/servers/1/access/add", bad.clone()).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid_value")), "{bad}");
    }
    assert_eq!(std::fs::read(dir.join("ops.json")).unwrap(), before);
    // Retrait.
    let (s, _) = c.post("/api/servers/1/access/remove", json!({"list": "banned_ips", "target": "10.0.0.5"})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_file(&dir, "banned-ips.json"), json!([]));
    let (s, _) = c.post("/api/servers/1/access/remove", json!({"list": "whitelist", "target": "Inconnu"})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Fichier illisible : signalé, jamais écrasé.
    std::fs::write(dir.join("banned-players.json"), "{abîmé").unwrap();
    let (_, v) = c.get("/api/servers/1/access").await;
    assert_eq!(v["unreadable"], json!(["banned_players"]));
    let (s, v) = c.post("/api/servers/1/access/add", add("banned_players", "Bob", json!({}))).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("config_invalid")));
    assert_eq!(std::fs::read_to_string(dir.join("banned-players.json")).unwrap(), "{abîmé");
    // Mode JSON : forme vérifiée (liste d'objets).
    let (_, f) = c.get("/api/servers/1/config?path=whitelist.json").await;
    let (s, _) = c
        .post("/api/servers/1/config/save", json!({"path": "whitelist.json", "text": "{}", "base_hash": f["hash"]}))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // Interrupteurs de la liste blanche.
    let (s, _) = c.post("/api/servers/1/access/whitelist", json!({"enabled": true, "enforce": true})).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = c.get("/api/servers/1/access").await;
    assert_eq!((v["white_list"].clone(), v["enforce_whitelist"].clone()), (json!(true), json!(true)));
    // CSRF exigé.
    let (s, _) =
        c.call(Method::POST, "/api/servers/1/access/add", Some(add("whitelist", "Alex", json!({}))), false).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Historique (mode JSON) et audit.
    let n: i64 = st.db.with(|c| {
        c.query_row("SELECT count(*) FROM server_config_history WHERE path = 'whitelist.json'", [], |r| r.get(0))
            .unwrap()
    });
    assert_eq!(n, 1);
    st.audit.flush().await;
    let n: i64 = st.db.with(|c| {
        c.query_row("SELECT count(*) FROM audit_log WHERE action LIKE 'access_%'", [], |r| r.get(0)).unwrap()
    });
    assert_eq!(n, 7);
}

/// En ligne : joueur déjà venu pris dans `usercache.json` (UUID officiel, casse du jeu), sans
/// appel réseau ; hôte de Mojang dans la liste fermée, rien d'autre.
#[tokio::test]
async fn uuid_officiel_par_le_cache_du_jeu() {
    let d = tmp("usercache");
    let (_st, mut c, dir) = paper(&d, "").await;
    std::fs::write(
        dir.join("usercache.json"),
        r#"[{"name":"Alex","uuid":"6ab43178-89fd-4905-97f6-0f67d9d76fd9","expiresOn":"2026-11-20 10:00:00 +0000"}]"#,
    )
    .unwrap();
    let (s, v) = c.get("/api/servers/1/access/resolve?name=alex").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({"name": "Alex", "uuid": "6ab43178-89fd-4905-97f6-0f67d9d76fd9", "offline": false}));
    let (s, _) = c.post("/api/servers/1/access/add", json!({"list": "whitelist", "target": "alex"})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        std::fs::read_to_string(dir.join("whitelist.json")).unwrap(),
        "[\n  {\n    \"uuid\": \"6ab43178-89fd-4905-97f6-0f67d9d76fd9\",\n    \"name\": \"Alex\"\n  }\n]"
    );
    let (s, _) = c.get("/api/servers/1/access/resolve?name=a%2Fb").await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let ok = |u: &str| rc_manager::download::url_allowed(&reqwest::Url::parse(u).unwrap());
    assert!(ok("https://api.mojang.com/users/profiles/minecraft/Alex"));
    assert!(!ok("https://api.mojang.com.evil.example/users/profiles/minecraft/Alex"));
    assert!(!ok("http://api.mojang.com/users/profiles/minecraft/Alex"));
}

/// Serveur en marche : actions par la console (immédiates), réglages que la console ne sait pas
/// faire refusés (409), mode JSON : liste blanche relue, autres listes refusées.
#[tokio::test]
async fn listes_d_acces_serveur_en_marche() {
    let d = tmp("acces-marche");
    let (st, mut c, dir) = paper(&d, "").await;
    let (s, _) = c.post("/api/servers/1/start", json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    wait_state(&st, rc_manager_shared::ServerState::Running).await;
    for (path, body) in [
        ("/api/servers/1/access/add", json!({"list": "whitelist", "target": "Bob"})),
        ("/api/servers/1/access/add", json!({"list": "banned_players", "target": "Eve", "reason": "Triche"})),
        ("/api/servers/1/access/remove", json!({"list": "ops", "target": "Bob"})),
        ("/api/servers/1/access/whitelist", json!({"enabled": false, "enforce": false})),
    ] {
        let (s, v) = c.post(path, body).await;
        assert_eq!((s, v["by_console"].as_bool()), (StatusCode::OK, Some(true)), "{path}");
    }
    for (path, body) in [
        ("/api/servers/1/access/add", json!({"list": "ops", "target": "Bob", "level": 2})),
        (
            "/api/servers/1/access/add",
            json!({"list": "banned_players", "target": "Eve", "expires": rc_manager::db::now() + 60}),
        ),
        ("/api/servers/1/access/whitelist", json!({"enabled": true, "enforce": true})),
    ] {
        let (s, v) = c.post(path, body).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("stop_first")), "{path}");
    }
    // Console : un pseudo hors norme n'ajoute jamais de mots à la commande.
    for (list, bad) in
        [("whitelist", "Eve stop"), ("ops", "@a"), ("banned_players", "Eve;stop"), ("banned_ips", "1.2.3.4 x")]
    {
        let (s, v) = c.post("/api/servers/1/access/add", json!({"list": list, "target": bad})).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid_value")), "{bad}");
        let (s, _) = c.post("/api/servers/1/access/remove", json!({"list": list, "target": bad})).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let t0 = std::time::Instant::now();
    loop {
        let (_, h) = c.get("/api/servers/1/console").await;
        let text = h["lines"].to_string();
        if ["<faux> whitelist add Bob", "<faux> ban Eve Triche", "<faux> deop Bob", "<faux> whitelist off"]
            .iter()
            .all(|l| text.contains(l))
        {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "{text}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Mode JSON en marche.
    std::fs::write(dir.join("whitelist.json"), "[]").unwrap();
    std::fs::write(dir.join("ops.json"), "[]").unwrap();
    let (_, f) = c.get("/api/servers/1/config?path=whitelist.json").await;
    let text = r#"[{"uuid":"6ab43178-89fd-4905-97f6-0f67d9d76fd9","name":"Alex"}]"#;
    let (s, v) = c
        .post("/api/servers/1/config/save", json!({"path": "whitelist.json", "text": text, "base_hash": f["hash"]}))
        .await;
    assert_eq!((s, v["restart_needed"].as_bool()), (StatusCode::OK, Some(false)), "{v}");
    let (_, f) = c.get("/api/servers/1/config?path=ops.json").await;
    let (s, v) =
        c.post("/api/servers/1/config/save", json!({"path": "ops.json", "text": text, "base_hash": f["hash"]})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("stop_first")));
    let t0 = std::time::Instant::now();
    while !c.get("/api/servers/1/console").await.1["lines"].to_string().contains("<faux> whitelist reload") {
        assert!(t0.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (s, _) = c.post("/api/servers/1/stop", json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    wait_state(&st, rc_manager_shared::ServerState::Stopped).await;
}

// ---------------------------------------------------------------------------------------------
// Gestionnaire de fichiers

fn tmp_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir.join(".rcm").join("tmp"))
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

fn link_dir(target: &Path, link: &Path) -> bool {
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

/// Fichiers par les routes : confinement (formes hostiles, `.rcm`, liens), lecture, écriture
/// avec empreinte, dossier, déplacement, corbeille (nom recopié), téléchargement et zip, audit.
#[tokio::test]
async fn fichiers_par_les_routes() {
    let _t = TRANSFERS.lock().await;
    let d = tmp("fichiers");
    let (st, mut c, dir) = paper(&d, "").await;
    std::fs::create_dir_all(dir.join(".rcm")).unwrap();
    std::fs::write(dir.join(".rcm").join("secret.txt"), "interne").unwrap();
    std::fs::write(d.join("dehors.txt"), "dehors").unwrap();
    let (s, v) = c.get("/api/servers/1/files?path=").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let names: Vec<&str> = v["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"server.properties") && names.contains(&"config"), "{names:?}");
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case(".rcm")), "{names:?}");
    // Formes hostiles : 422 sans toucher au disque, sur chaque route.
    for bad in [
        "..",
        "../dehors.txt",
        "%2e%2e/dehors.txt",
        "..%2Fdehors.txt",
        "C:/x",
        "/etc/passwd",
        ".rcm/secret.txt",
        ".RCM/secret.txt",
        "CON",
        "a\\..\\b",
        "config/../../dehors.txt",
    ] {
        let q = bad.replace('%', "%25").replace('\\', "%5C");
        let (s, _) = c.get(&format!("/api/servers/1/files/read?path={q}")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "lecture {bad}");
        let (s, _) = c.get(&format!("/api/servers/1/files/download?path={q}")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "téléchargement {bad}");
        let (s, _) = c.get(&format!("/api/servers/1/files?path={q}")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "liste {bad}");
        for (route, body) in [
            ("write", json!({"path": bad, "text": "x"})),
            ("mkdir", json!({"path": bad})),
            ("delete", json!({"path": bad, "confirm": bad})),
            ("move", json!({"from": "bukkit.yml", "to": bad})),
            ("move", json!({"from": bad, "to": "x.txt"})),
        ] {
            let (s, _) = c.post(&format!("/api/servers/1/files/{route}"), body).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{route} {bad}");
        }
        let (s, _) = c.upload("", bad, b"x", true).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "envoi {bad}");
    }
    assert_eq!(std::fs::read_to_string(d.join("dehors.txt")).unwrap(), "dehors");
    assert_eq!(std::fs::read_to_string(dir.join(".rcm").join("secret.txt")).unwrap(), "interne");
    // Lien vers l'extérieur : listé comme lien, jamais suivi.
    let outside = tmp("fichiers-dehors");
    std::fs::write(outside.join("s.txt"), "secret").unwrap();
    assert!(link_dir(&outside, &dir.join("lien")));
    let (_, v) = c.get("/api/servers/1/files?path=").await;
    let lien = v["entries"].as_array().unwrap().iter().find(|e| e["name"] == "lien").cloned().unwrap();
    assert_eq!(lien["kind"], "link");
    for path in [
        "/api/servers/1/files/read?path=lien/s.txt",
        "/api/servers/1/files/download?path=lien",
        "/api/servers/1/files?path=lien",
    ] {
        let (s, _) = c.get(path).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    let (s, _) = c.post("/api/servers/1/files/write", json!({"path": "lien/n.txt", "text": "x"})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = c.upload("lien", "n.txt", b"x", false).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(!outside.join("n.txt").exists());
    std::fs::remove_dir(dir.join("lien")).or_else(|_| std::fs::remove_file(dir.join("lien"))).unwrap();
    // Lecture d'un fichier sensible : tracée ; binaire : refusé à l'édition.
    let (s, v) = c.get("/api/servers/1/files/read?path=server.properties").await;
    assert_eq!((s, v["sensitive"].as_bool(), v["format"].as_str()), (StatusCode::OK, Some(true), Some("properties")));
    std::fs::write(dir.join("server.jar"), b"PK\x03\x04\0\0").unwrap();
    let (s, v) = c.get("/api/servers/1/files/read?path=server.jar").await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("not_text")));
    // Écriture : création, puis remplacement à l'empreinte seulement.
    let (s, v) = c.post("/api/servers/1/files/write", json!({"path": "notes.txt", "text": "un"})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v2) = c.post("/api/servers/1/files/write", json!({"path": "notes.txt", "text": "deux"})).await;
    assert_eq!((s, v2["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")));
    let (s, _) = c
        .post("/api/servers/1/files/write", json!({"path": "notes.txt", "text": "deux", "base_hash": v["hash"]}))
        .await;
    assert_eq!(s, StatusCode::OK);
    // Analyseur du format avant écriture.
    let (s, v) = c.post("/api/servers/1/files/write", json!({"path": "plugins-cfg.yml", "text": "a: [\n"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("config_invalid")));
    let (_, v) = c.post("/api/servers/1/files/check", json!({"path": "x.yml", "text": "a: [\n"})).await;
    assert!(v["error"]["line"].as_u64().is_some(), "{v}");
    // eula.txt : écran de l'EULA seulement.
    std::fs::write(dir.join("eula.txt"), "eula=true\n").unwrap();
    let (s, v) = c
        .post("/api/servers/1/files/write", json!({"path": "eula.txt", "text": "eula=false\n", "base_hash": "x"}))
        .await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("managed_file")));
    let (s, _) = c.post("/api/servers/1/files/delete", json!({"path": "EULA.txt"})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // Dossier, déplacement, corbeille (nom recopié exigé), restauration.
    let (s, _) = c.post("/api/servers/1/files/mkdir", json!({"path": "sauvegardes"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = c.post("/api/servers/1/files/move", json!({"from": "notes.txt", "to": "sauvegardes/notes.txt"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, v) = c.post("/api/servers/1/files/delete", json!({"path": "sauvegardes", "confirm": "sauvegarde"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("name_mismatch")));
    assert!(dir.join("sauvegardes/notes.txt").exists());
    let (s, _) = c.post("/api/servers/1/files/delete", json!({"path": "sauvegardes", "confirm": "sauvegardes"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!dir.join("sauvegardes").exists());
    let (_, t) = c.get("/api/servers/1/files/trash").await;
    assert_eq!((t[0]["path"].as_str(), t[0]["user"].as_str()), (Some("sauvegardes"), Some("admin")));
    let (s, _) = c.post("/api/servers/1/files/trash/restore", json!({"id": t[0]["id"]})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(std::fs::read_to_string(dir.join("sauvegardes/notes.txt")).unwrap(), "deux");
    let (s, _) = c.post("/api/servers/1/files/delete", json!({"path": "sauvegardes/notes.txt"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, t) = c.get("/api/servers/1/files/trash").await;
    // Effacement définitif : ré-authentification exigée (mot de passe faux ou absent : refus).
    let (s, _) = c.post("/api/servers/1/files/trash/purge", json!({"id": t[0]["id"]})).await;
    assert!(s.is_client_error(), "{s}");
    let bad = json!({"id": t[0]["id"], "reauth": {"password": "faux mot de passe"}});
    let (s, _) = c.post("/api/servers/1/files/trash/purge", bad).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(c.get("/api/servers/1/files/trash").await.1.as_array().unwrap().len(), 1, "rien d'effacé");
    let ok = json!({"id": t[0]["id"], "reauth": {"password": PW}});
    let (s, _) = c.post("/api/servers/1/files/trash/purge", ok).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, t) = c.get("/api/servers/1/files/trash").await;
    assert_eq!(t, json!([]));
    // Effacement définitif sans corbeille (élément trop gros pour elle) : ré-authentification,
    // dossier : nom recopié ; tracé.
    std::fs::create_dir_all(dir.join("gros/sous")).unwrap();
    std::fs::write(dir.join("gros/sous/a.bin"), b"a").unwrap();
    let (s, _) = c.post("/api/servers/1/files/erase", json!({"path": "gros", "confirm": "gros"})).await;
    assert!(s.is_client_error(), "{s}");
    let bad = json!({"path": "gros", "confirm": "gros", "reauth": {"password": "faux mot de passe"}});
    assert_eq!(c.post("/api/servers/1/files/erase", bad).await.0, StatusCode::UNAUTHORIZED);
    let wrong = json!({"path": "gros", "confirm": "autre", "reauth": {"password": PW}});
    let (s, v) = c.post("/api/servers/1/files/erase", wrong).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("name_mismatch")));
    assert!(dir.join("gros/sous/a.bin").exists());
    let ok = json!({"path": "gros", "confirm": "gros", "reauth": {"password": PW}});
    assert_eq!(c.post("/api/servers/1/files/erase", ok).await.0, StatusCode::NO_CONTENT);
    assert!(!dir.join("gros").exists());
    assert_eq!(c.get("/api/servers/1/files/trash").await.1, json!([]), "pas de corbeille");
    // Téléchargement : fichier tel quel ; dossier en zip, sans `.rcm`.
    let (s, h, b) = c.raw(Method::GET, "/api/servers/1/files/download?path=bukkit.yml", "", Vec::new()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, std::fs::read(dir.join("bukkit.yml")).unwrap());
    assert!(h["content-disposition"].to_str().unwrap().contains("bukkit.yml"));
    let (s, h, b) = c.raw(Method::GET, "/api/servers/1/files/download?path=", "", Vec::new()).await;
    assert_eq!((s, h["content-type"].to_str().unwrap()), (StatusCode::OK, "application/zip"));
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(b)).unwrap();
    let names: Vec<String> = (0..z.len()).map(|i| z.by_index(i).unwrap().name().unwrap().to_string()).collect();
    assert!(names.contains(&"config/paper-global.yml".to_string()), "{names:?}");
    assert!(!names.iter().any(|n| n.to_lowercase().starts_with(".rcm")), "{names:?}");
    st.audit.flush().await;
    let count = |a: &str| -> i64 {
        st.db.with(|c| c.query_row("SELECT count(*) FROM audit_log WHERE action = ?1", [a], |r| r.get(0)).unwrap())
    };
    assert_eq!(count("file_read"), 1, "lecture sensible tracée");
    assert_eq!(count("file_downloaded"), 2);
    assert_eq!(count("file_trashed"), 2);
    assert_eq!(count("file_erased"), 1);
    let _ = std::fs::remove_dir_all(&outside);
}

/// Envois : en flux, taille bornée par la configuration, temporaire toujours effacé, écrasement
/// sur demande seulement, type de corps exigé, gardes des réglages appliquées au contenu.
#[tokio::test]
async fn envois_de_fichiers() {
    let _t = TRANSFERS.lock().await;
    let d = tmp("envois");
    let (_st, mut c, dir) = paper_cfg(&d, "", 1).await;
    let (s, v) = c.upload("", "monde.dat", &[7u8; 300 * 1024], false).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(std::fs::read(dir.join("monde.dat")).unwrap(), vec![7u8; 300 * 1024]);
    // Empreinte des octets reçus, calculée au fil de l'eau (rien n'est relu sous le verrou).
    assert_eq!(v["hash"].as_str().unwrap(), rc_manager::configs::hash(&[7u8; 300 * 1024]));
    let (s, v) = c.upload("", "monde.dat", b"x", false).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")));
    let (s, _) = c.upload("", "monde.dat", b"x", true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(std::fs::read(dir.join("monde.dat")).unwrap(), b"x");
    // Écrasé : l'ancien est à la corbeille, récupérable comme une suppression.
    let (_, t) = c.get("/api/servers/1/files/trash").await;
    let t = t.as_array().unwrap();
    assert_eq!((t.len(), t[0]["path"].as_str()), (1, Some("monde.dat")), "{t:?}");
    // Fichier de réglages écrasé : sa version précédente rejoint aussi leur historique.
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    let motd = rc_manager::props::patch(&props, &[("motd", "Envoi".into())]);
    let (s, v) = c.upload("", "server.properties", motd.as_bytes(), true).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, h) = c.get("/api/servers/1/config/history?path=server.properties").await;
    assert_eq!(h.as_array().map(Vec::len), Some(1), "{h}");
    let (_, ver) = c.get(&format!("/api/servers/1/config/history/{}", h[0]["id"])).await;
    assert_eq!(ver["text"].as_str(), Some(props.as_str()));
    let (s, v) = c.upload("", "gros.bin", &vec![1u8; 1024 * 1024 + 1], false).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("file_too_large")));
    assert!(!dir.join("gros.bin").exists());
    let (s, _) = c.upload("pas-de-dossier", "a.txt", b"x", false).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Contenu d'un fichier de réglages : clé gérée changée = refus, comme dans l'éditeur.
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    let bad = rc_manager::props::patch(&props, &[("server-port", "1".into())]);
    let (s, _) = c.upload("", "server.properties", bad.as_bytes(), true).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(std::fs::read_to_string(dir.join("server.properties")).unwrap(), props);
    // Corps JSON ou sans type : refusé avant la route (anti-CSRF).
    let (s, _, _) =
        c.raw(Method::POST, "/api/servers/1/files/upload?name=a.txt", "application/json", b"x".to_vec()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = c.raw(Method::POST, "/api/servers/1/files/upload?name=a.txt", "", b"x".to_vec()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Sans jeton anti-CSRF.
    let saved = c.csrf.take();
    let (s, _) = c.upload("", "a.txt", b"x", false).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    c.csrf = saved;
    assert!(!dir.join("a.txt").exists());
    assert_eq!(tmp_files(&dir), Vec::<String>::new(), "aucun temporaire restant");
}

/// Corps d'envoi qui n'avance qu'au rythme du test.
struct Stalled(tokio::sync::mpsc::Receiver<Result<axum::body::Bytes, std::io::Error>>);

impl futures_core::Stream for Stalled {
    type Item = Result<axum::body::Bytes, std::io::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// Envois bornés : taille annoncée au-delà de la place libre du disque (507), envois simultanés
/// par compte (503 au-delà, place rendue à la fin).
#[tokio::test]
async fn envois_place_libre_et_simultanes() {
    let _t = TRANSFERS.lock().await;
    let d = tmp("envois-bornes");
    // Borne d'envoi démesurée (1 Pio) : seule la place libre du disque arrête l'envoi annoncé.
    let (_st, c, dir) = paper_cfg(&d, "", 1 << 30).await;
    let req = |name: &str, len: Option<u64>, body: Body| {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/servers/1/files/upload?name={name}"))
            .header("host", "127.0.0.1:8580")
            .header("content-type", "application/octet-stream")
            .header("cookie", c.cookie.clone().unwrap())
            .header("x-csrf-token", c.csrf.clone().unwrap());
        if let Some(n) = len {
            b = b.header("content-length", n);
        }
        let mut r = b.body(body).unwrap();
        r.extensions_mut().insert(ConnectInfo("10.0.0.1:5000".parse::<std::net::SocketAddr>().unwrap()));
        r
    };
    let res = c.app.clone().oneshot(req("gros.bin", Some(1 << 49), Body::from("x"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert!(!dir.join("gros.bin").exists());
    // Deux envois en cours pour le compte : le troisième est refusé tout de suite.
    let mut senders = Vec::new();
    let mut pending = Vec::new();
    for i in 0..2 {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        senders.push(tx);
        pending.push(tokio::spawn(c.app.clone().oneshot(req(
            &format!("lent{i}.bin"),
            None,
            Body::from_stream(Stalled(rx)),
        ))));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let res = c.app.clone().oneshot(req("lent0.bin", None, Body::from("x"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(senders);
    for p in pending {
        assert_eq!(p.await.unwrap().unwrap().status(), StatusCode::OK);
    }
    let res = c.app.clone().oneshot(req("lent0.bin", None, Body::from("x"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "place rendue (le fichier existe déjà)");
}

/// Compte non administrateur : programmes (créer, envoyer, renommer vers ou depuis) et réglages
/// réservés (par l'éditeur, un envoi ou un renommage) refusés ; le reste permis.
#[tokio::test]
async fn fichiers_compte_ordinaire() {
    let _t = TRANSFERS.lock().await;
    let d = tmp("fichiers-ordinaire");
    let (st, mut c, dir) = paper(&d, "").await;
    std::fs::write(dir.join("outil.jar"), b"PK").unwrap();
    // Copie de `server.properties` avec seulement `online-mode` changé (réglage réservé).
    let props0 = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    std::fs::write(dir.join("off.txt"), rc_manager::props::patch(&props0, &[("online-mode", "false".into())])).unwrap();
    st.db.with(|c| c.execute("UPDATE users SET is_admin = 0", []).unwrap());
    let forbidden = |s: StatusCode| assert_eq!(s, StatusCode::FORBIDDEN);
    forbidden(c.post("/api/servers/1/files/write", json!({"path": "start.sh", "text": "rm -rf /"})).await.0);
    forbidden(c.upload("", "plugin.jar", b"PK", false).await.0);
    forbidden(c.post("/api/servers/1/files/move", json!({"from": "off.txt", "to": "lancer.bat"})).await.0);
    forbidden(c.post("/api/servers/1/files/move", json!({"from": "outil.jar", "to": "outil.txt"})).await.0);
    forbidden(c.post("/api/servers/1/files/move", json!({"from": "off.txt", "to": "server.properties"})).await.0);
    let props = std::fs::read_to_string(dir.join("server.properties")).unwrap();
    let off = rc_manager::props::patch(&props, &[("online-mode", "false".into())]);
    let (_, f) = c.get("/api/servers/1/files/read?path=server.properties").await;
    forbidden(
        c.post("/api/servers/1/files/write", json!({"path": "server.properties", "text": off, "base_hash": f["hash"]}))
            .await
            .0,
    );
    forbidden(c.upload("", "server.properties", off.as_bytes(), true).await.0);
    std::fs::create_dir_all(dir.join("plugins/carte")).unwrap();
    forbidden(
        c.post("/api/servers/1/files/write", json!({"path": "plugins/carte/config.yml", "text": "web-port: 8100\n"}))
            .await
            .0,
    );
    assert_eq!(std::fs::read_to_string(dir.join("server.properties")).unwrap(), props);
    assert!(!dir.join("start.sh").exists() && !dir.join("plugin.jar").exists() && dir.join("outil.jar").exists());
    let (s, _) =
        c.post("/api/servers/1/files/write", json!({"path": "plugins/carte/config.yml", "text": "zoom: 3\n"})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = c.post("/api/servers/1/files/delete", json!({"path": "outil.jar"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "supprimer reste permis (corbeille)");
    // Fichiers sans analyseur des greffons : règle par ligne (éditeur, envoi).
    forbidden(
        c.post("/api/servers/1/files/write", json!({"path": "plugins/carte/carte.conf", "text": "web-port = 1\n"}))
            .await
            .0,
    );
    forbidden(c.upload("plugins/carte", "carte.conf", b"web-port = 1\n", false).await.0);
    forbidden(c.upload("plugins/carte", "donnees.db", b"\0\x01", false).await.0);
    // Supprimer ou déplacer = écrire vide ; restaurer = créer : réglages réservés compris.
    forbidden(c.post("/api/servers/1/files/delete", json!({"path": "server.properties"})).await.0);
    forbidden(c.post("/api/servers/1/files/delete", json!({"path": "config", "confirm": "config"})).await.0);
    forbidden(
        c.post("/api/servers/1/files/move", json!({"from": "config/paper-global.yml", "to": "vieux.yml"})).await.0,
    );
    st.db.with(|c| c.execute("UPDATE users SET is_admin = 1", []).unwrap());
    let (s, _) = c.post("/api/servers/1/files/delete", json!({"path": "config/paper-global.yml"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    st.db.with(|c| c.execute("UPDATE users SET is_admin = 0", []).unwrap());
    let (_, t) = c.get("/api/servers/1/files/trash").await;
    let item = t.as_array().unwrap().iter().find(|i| i["path"] == "config/paper-global.yml").unwrap().clone();
    forbidden(c.post("/api/servers/1/files/trash/restore", json!({"id": item["id"]})).await.0);
    // Effacement définitif : administrateurs seulement, même avec le bon mot de passe.
    let purge = json!({"id": item["id"], "reauth": {"password": PW}});
    forbidden(c.post("/api/servers/1/files/trash/purge", purge).await.0);
    let erase = json!({"path": "server.properties", "reauth": {"password": PW}});
    forbidden(c.post("/api/servers/1/files/erase", erase).await.0);
    let (_, t) = c.get("/api/servers/1/files/trash").await;
    assert!(t.as_array().unwrap().iter().any(|i| i["id"] == item["id"]), "toujours dans la corbeille");
    assert!(dir.join("server.properties").exists() && !dir.join("config/paper-global.yml").exists());
    assert!(!dir.join("plugins/carte/carte.conf").exists() && !dir.join("plugins/carte/donnees.db").exists());
}

/// Serveur en marche : monde (et ses parents) intouchable, listes d'accès par l'onglet Joueurs ;
/// démarrage en cours : rien n'est modifiable.
#[tokio::test]
async fn fichiers_serveur_en_marche() {
    let _t = TRANSFERS.lock().await;
    let d = tmp("fichiers-marche");
    let (st, mut c, dir) = paper(&d, "").await;
    std::fs::create_dir_all(dir.join("world/region")).unwrap();
    std::fs::write(dir.join("world/level.dat"), b"x").unwrap();
    let (s, _) = c.post("/api/servers/1/start", json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (s, v) = c.post("/api/servers/1/files/write", json!({"path": "notes.txt", "text": "x"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("server_busy")), "démarrage");
    wait_state(&st, rc_manager_shared::ServerState::Running).await;
    for (route, body) in [
        ("write", json!({"path": "world/x.txt", "text": "x"})),
        ("mkdir", json!({"path": "world/region/r"})),
        ("delete", json!({"path": "world/level.dat"})),
        ("move", json!({"from": "world", "to": "monde"})),
        ("move", json!({"from": "bukkit.yml", "to": "world_nether"})),
    ] {
        let (s, v) = c.post(&format!("/api/servers/1/files/{route}"), body).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("world_in_use")), "{route}");
    }
    let (s, _) = c.upload("world", "x.mca", b"x", false).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, v) = c.post("/api/servers/1/files/write", json!({"path": "ops.json", "text": "[]"})).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("stop_first")));
    let (s, v) = c.post("/api/servers/1/files/write", json!({"path": "notes.txt", "text": "x"})).await;
    assert_eq!((s, v["restart_needed"].as_bool()), (StatusCode::OK, Some(false)), "hors du monde : permis");
    // Fichier de réglages : le jeu ne le relit qu'au démarrage, l'éditeur le dit.
    let (_, r) = c.get("/api/servers/1/files/read?path=bukkit.yml").await;
    let text = format!("{}# note\n", r["text"].as_str().unwrap());
    let (s, v) =
        c.post("/api/servers/1/files/write", json!({"path": "bukkit.yml", "text": text, "base_hash": r["hash"]})).await;
    assert_eq!((s, v["restart_needed"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    let (s, _, _) = c.raw(Method::GET, "/api/servers/1/files/download?path=world", "", Vec::new()).await;
    assert_eq!(s, StatusCode::OK, "téléchargement du monde permis");
    let (s, _) = c.post("/api/servers/1/stop", json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    wait_state(&st, rc_manager_shared::ServerState::Stopped).await;
}
