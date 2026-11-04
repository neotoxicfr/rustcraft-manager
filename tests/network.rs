//! Adresses publiques, sans Internet :
//! - aiguilleur en vrai TCP sur la boucle locale (faux serveur Minecraft derrière) : routage par
//!   nom (casse, point final, suffixe FML), relais dans les deux sens, refus propres (statut,
//!   déconnexion), poignées de main hostiles, délai, plafond par adresse ;
//! - faux Cloudflare en HTTP local : aperçu puis application par l'API, jeton exigé, nuage gris
//!   et commentaire, resynchronisation sans écraser ce qui a été retouché à la main, port changé,
//!   renommage, suppression du serveur, audit ;
//! - sans jeton : enregistrements à créer à la main, rien d'écrit ailleurs.

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxPath, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use rc_manager::config::{ApiToken, Config};
use rc_manager::db::Db;
use rc_manager::network::cloudflare::Cloudflare;
use rc_manager::network::handshake::{Handshake, encode_handshake, packet, read_packet, status_ping};
use rc_manager::network::router::{self, Limits, OFFLINE_MOTD, Route, Routes, UNKNOWN_MOTD};
use rc_manager::paths::ServerId;
use rc_manager::{AppState, new_state};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

const PW: &str = "un mot de passe solide";
const TOKEN: &str = "jeton-de-test-cloudflare-0123456789";
const ZONE_ID: &str = "0123456789abcdef0123456789abcdef";
const IP: &str = "198.51.99.4";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rcm-net-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------------------------
// Aiguilleur

/// Faux serveur Minecraft : répond au statut (version « Faux 26.3 ») ; en connexion, renvoie en
/// écho tout ce qui suit la poignée de main.
async fn fake_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let Ok((0, body)) = read_packet(&mut s, 1024).await else { return };
                let state = *body.last().unwrap();
                if state == 1 {
                    let _ = read_packet(&mut s, 16).await;
                    let json =
                        json!({"version": {"name": "Faux 26.3", "protocol": 775}, "players": {"max": 20, "online": 3}})
                            .to_string();
                    let mut b = Vec::new();
                    rc_manager::network::handshake::write_varint(&mut b, json.len() as i32);
                    b.extend_from_slice(json.as_bytes());
                    let _ = s.write_all(&packet(0, &b)).await;
                    if let Ok((1, p)) = read_packet(&mut s, 16).await {
                        let _ = s.write_all(&packet(1, &p)).await;
                    }
                } else {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    addr
}

struct Table(HashMap<&'static str, Route>);

impl Routes for Table {
    fn route(&self, h: &str) -> Route {
        self.0.get(h).cloned().unwrap_or(Route::Unknown)
    }
}

async fn start_router(routes: Table, limits: Limits) -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(router::run(l, Arc::new(routes), limits, rx));
    (addr, tx)
}

fn limits(max_per_ip: usize) -> Limits {
    Limits {
        max_connections: 64,
        max_per_ip,
        handshake_timeout: Duration::from_millis(400),
        idle_timeout: Duration::from_secs(5),
    }
}

/// Lit jusqu'à la fermeture (bornée dans le temps).
async fn read_to_close(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await.expect("fermée à temps");
    out
}

#[tokio::test]
async fn aiguilleur_route_relaie_et_refuse() {
    let backend = fake_backend().await;
    let table = Table(HashMap::from([
        ("survie.example.com", Route::Backend(backend)),
        ("arrete.example.com", Route::Offline),
        // Nom connu dont le serveur n'écoute pas : refus comme arrêté.
        ("mort.example.com", Route::Backend(format!("127.0.0.1:{}", free_port()).parse().unwrap())),
    ]));
    let (addr, _stop) = start_router(table, limits(16)).await;
    let ping = |host: &'static str| async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), status_ping(&mut s, host, 25565)).await.unwrap()
    };
    // Routage exact, casse et point final ignorés, suffixe FML retiré.
    for host in ["survie.example.com", "Survie.Example.COM.", "survie.example.com\0FML3\0"] {
        let r = ping(host).await.unwrap_or_else(|e| panic!("{host:?} : {e}"));
        assert_eq!((r.version.as_str(), r.online, r.max), ("Faux 26.3", 3, 20), "{host:?}");
    }
    // Nom inconnu, voisin ou suffixé, serveur arrêté ou injoignable : statut du gestionnaire.
    for host in [
        "inconnu.example.com",
        "survie.example.com.evil",
        "xsurvie.example.com",
        "arrete.example.com",
        "mort.example.com",
    ] {
        let r = ping(host).await.unwrap_or_else(|e| panic!("{host} : {e}"));
        assert_eq!(r.version, "Rustcraft Manager", "{host}");
    }
    // Connexion (état 2) à un nom inconnu ou arrêté : paquet de déconnexion lisible puis fermeture.
    for (host, motd) in [("inconnu.example.com", UNKNOWN_MOTD), ("arrete.example.com", OFFLINE_MOTD)] {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let hs = Handshake { protocol: 775, address: host.into(), port: 25565, next_state: 2 };
        s.write_all(&encode_handshake(&hs)).await.unwrap();
        let out = read_to_close(&mut s).await;
        let mut r = &out[..];
        let (id, body) = read_packet(&mut r, 4096).await.unwrap();
        assert_eq!(id, 0);
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(motd), "{text}");
    }
    // Relais dans les deux sens : octets envoyés avec la poignée de main, puis après.
    let mut s = TcpStream::connect(addr).await.unwrap();
    let hs = Handshake { protocol: 775, address: "survie.example.com".into(), port: 25565, next_state: 2 };
    let mut first = encode_handshake(&hs);
    first.extend_from_slice("collé".as_bytes());
    s.write_all(&first).await.unwrap();
    let mut got = vec![0u8; "collé".len()];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut got)).await.unwrap().unwrap();
    assert_eq!(got, "collé".as_bytes());
    let big = vec![7u8; 200_000];
    let (mut rd, mut wr) = s.into_split();
    let sender = tokio::spawn(async move {
        wr.write_all(&big).await.unwrap();
        wr
    });
    let mut back = vec![0u8; 200_000];
    tokio::time::timeout(Duration::from_secs(5), rd.read_exact(&mut back)).await.unwrap().unwrap();
    assert!(back.iter().all(|&b| b == 7));
    drop(sender.await.unwrap());
}

#[tokio::test]
async fn aiguilleur_bornes_anti_abus() {
    let backend = fake_backend().await;
    let (addr, _stop) =
        start_router(Table(HashMap::from([("survie.example.com", Route::Backend(backend))])), limits(2)).await;
    // Ping hérité, poignée de main démesurée, octets quelconques : fermé sans relais.
    let mut huge = Vec::new();
    rc_manager::network::handshake::write_varint(&mut huge, 1_000_000);
    huge.extend_from_slice(&[0u8; 64]);
    for junk in [vec![0xFE, 0x01, 0xFA], huge, b"GET / HTTP/1.1\r\n\r\n".to_vec()] {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&junk).await.unwrap();
        assert!(read_to_close(&mut s).await.is_empty(), "{junk:?}");
    }
    // Client muet : coupé après le délai de poignée de main.
    let t0 = std::time::Instant::now();
    let mut s = TcpStream::connect(addr).await.unwrap();
    assert!(read_to_close(&mut s).await.is_empty());
    assert!(t0.elapsed() >= Duration::from_millis(350), "{:?}", t0.elapsed());
    // Deux connexions muettes de la même adresse : la troisième est fermée tout de suite.
    let _a = TcpStream::connect(addr).await.unwrap();
    let _b = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t0 = std::time::Instant::now();
    let mut c = TcpStream::connect(addr).await.unwrap();
    assert!(read_to_close(&mut c).await.is_empty());
    assert!(t0.elapsed() < Duration::from_millis(300), "refus immédiat : {:?}", t0.elapsed());
    // Places rendues : une nouvelle connexion passe de nouveau.
    drop((_a, _b));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let r =
        tokio::time::timeout(Duration::from_secs(3), status_ping(&mut s, "survie.example.com", 25565)).await.unwrap();
    assert_eq!(r.unwrap().version, "Faux 26.3");
}

// ---------------------------------------------------------------------------------------------
// Faux Cloudflare

#[derive(Default)]
struct Fake {
    records: Mutex<Vec<Value>>,
    next: Mutex<u64>,
    /// Requêtes reçues sans le bon jeton.
    unauthorized: Mutex<u32>,
}

fn authorized(f: &Fake, h: &HeaderMap) -> bool {
    let ok = h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
    if !ok {
        *f.unauthorized.lock().unwrap() += 1;
    }
    ok
}

/// Corps reçu → enregistrement tel que Cloudflare le rend (SRV : `data`, `content` sans la
/// priorité, `priority` à part).
fn stored(id: &str, b: &Value) -> Value {
    let mut r = b.clone();
    r["id"] = json!(id);
    if b["type"] == "SRV" {
        let d = &b["data"];
        r["content"] = json!(format!("{} {} {}", d["weight"], d["port"], d["target"].as_str().unwrap()));
        r["priority"] = d["priority"].clone();
        r["proxied"] = json!(false);
    }
    r
}

fn ok(result: Value) -> axum::response::Response {
    axum::response::IntoResponse::into_response(axum::Json(json!({"success": true, "errors": [], "result": result})))
}

fn denied() -> axum::response::Response {
    axum::response::IntoResponse::into_response((
        StatusCode::FORBIDDEN,
        axum::Json(json!({"success": false, "errors": [{"code": 10000, "message": "Authentication error"}]})),
    ))
}

async fn fake_list(
    State(f): State<Arc<Fake>>,
    h: HeaderMap,
    AxPath(zone): AxPath<String>,
    Query(q): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if !authorized(&f, &h) || zone != ZONE_ID {
        return denied();
    }
    // Pages de 2 : la pagination est réellement suivie.
    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let all = f.records.lock().unwrap().clone();
    let pages = all.len().div_ceil(2).max(1);
    let slice: Vec<Value> = all.into_iter().skip((page - 1) * 2).take(2).collect();
    axum::response::IntoResponse::into_response(axum::Json(json!({
        "success": true, "errors": [], "result": slice, "result_info": {"page": page, "total_pages": pages}
    })))
}

async fn fake_create(
    State(f): State<Arc<Fake>>,
    h: HeaderMap,
    AxPath(_z): AxPath<String>,
    axum::Json(b): axum::Json<Value>,
) -> axum::response::Response {
    if !authorized(&f, &h) {
        return denied();
    }
    let id = {
        let mut n = f.next.lock().unwrap();
        *n += 1;
        format!("{:032x}", *n)
    };
    let r = stored(&id, &b);
    f.records.lock().unwrap().push(r.clone());
    ok(r)
}

async fn fake_put(
    State(f): State<Arc<Fake>>,
    h: HeaderMap,
    AxPath((_z, id)): AxPath<(String, String)>,
    axum::Json(b): axum::Json<Value>,
) -> axum::response::Response {
    if !authorized(&f, &h) {
        return denied();
    }
    let mut recs = f.records.lock().unwrap();
    let Some(r) = recs.iter_mut().find(|r| r["id"] == id.as_str()) else { return denied() };
    *r = stored(&id, &b);
    ok(r.clone())
}

async fn fake_delete(
    State(f): State<Arc<Fake>>,
    h: HeaderMap,
    AxPath((_z, id)): AxPath<(String, String)>,
) -> axum::response::Response {
    if !authorized(&f, &h) {
        return denied();
    }
    f.records.lock().unwrap().retain(|r| r["id"] != id.as_str());
    ok(json!({"id": id}))
}

async fn fake_cloudflare(seed: Vec<Value>) -> (Arc<Fake>, String) {
    let f = Arc::new(Fake { records: Mutex::new(seed), next: Mutex::new(100), ..Default::default() });
    let app = Router::new()
        .route("/client/v4/zones/{zone}/dns_records", axum::routing::get(fake_list).post(fake_create))
        .route("/client/v4/zones/{zone}/dns_records/{id}", axum::routing::put(fake_put).delete(fake_delete))
        .with_state(f.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (f, format!("http://{addr}/client/v4"))
}

fn find<'a>(recs: &'a [Value], kind: &str, name: &str) -> Vec<&'a Value> {
    recs.iter().filter(|r| r["type"] == kind && r["name"] == name).collect()
}

// ---------------------------------------------------------------------------------------------
// État et client de l'API

fn state(data: &std::path::Path, port: u16, f: impl FnOnce(&mut Config)) -> (Arc<AppState>, String) {
    let db = Db::open_memory().unwrap();
    let enc = db.keys().encrypt(&rc_manager::crypto::aad("servers", "rcon_password", 1), b"motdepasse");
    db.with(|c| {
        c.execute(
            "INSERT INTO servers (id, name, software, game_version, memory_mb, port, rcon_port, rcon_password_enc, created_at)
             VALUES (1, 'Survie', 'vanilla', '26.3', 1024, ?1, ?2, ?3, 0)",
            rusqlite::params![port, free_port(), enc],
        )
        .unwrap();
    });
    std::fs::create_dir_all(data.join("servers").join("1")).unwrap();
    let mut cfg = Config::with_data_dir(data.to_path_buf());
    cfg.public_ip_detect = false;
    f(&mut cfg);
    let (st, token) = new_state(cfg, db);
    st.network.set_ips(Some(IP.parse().unwrap()), None);
    (st, token.unwrap())
}

struct Client {
    app: Router,
    cookie: Option<String>,
    csrf: Option<String>,
}

impl Client {
    async fn call(&mut self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method.clone()).uri(path).header("host", "127.0.0.1:8580");
        if method != Method::GET {
            b = b.header("content-type", "application/json");
        }
        if let Some(c) = &self.cookie {
            b = b.header("cookie", c);
        }
        if let Some(t) = &self.csrf {
            b = b.header("x-csrf-token", t);
        }
        let mut req = b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string()))).unwrap();
        req.extensions_mut().insert(ConnectInfo("10.0.0.1:5000".parse::<SocketAddr>().unwrap()));
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
        self.call(Method::POST, path, Some(body)).await
    }
}

async fn admin(st: &Arc<AppState>, token: &str) -> Client {
    let mut c = Client { app: rc_manager::router(st.clone()), cookie: None, csrf: None };
    let (s, v) = c.post("/api/setup", json!({"token": token, "username": "admin", "password": PW})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    c
}

/// Aperçu puis application ; rend la réponse de l'application.
async fn set_address(c: &mut Client, address: Value) -> Value {
    let (s, pre) = c.post("/api/servers/1/address/preview", json!({ "address": address })).await;
    assert_eq!(s, StatusCode::OK, "{pre}");
    let (s, v) = c.post("/api/servers/1/address", json!({ "address": address, "digest": pre["digest"] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn audit_details(st: &AppState) -> Vec<(String, String)> {
    st.audit.flush().await;
    st.db.with(|c| {
        let mut s = c.prepare("SELECT action, coalesce(detail, '') FROM audit_log ORDER BY id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    })
}

#[tokio::test]
async fn cloudflare_simule_sans_ecraser_le_manuel() {
    let d = tmp("cloudflare");
    let port = 25570;
    // Zone : joker orange de l'utilisateur, A posé à la main sur crea, enregistrement sans rapport.
    let seed = vec![
        json!({"id": "a1", "type": "A", "name": "*.example.com", "content": "104.16.0.1", "proxied": true}),
        json!({"id": "a2", "type": "A", "name": "crea.example.com", "content": "198.51.99.9", "proxied": false}),
        json!({"id": "a3", "type": "TXT", "name": "example.com", "content": "v=spf1 -all", "comment": "rustcraft-manager"}),
    ];
    let (fake, base) = fake_cloudflare(seed).await;
    let (st, token) = state(&d, port, |c| c.dns_zone = Some("example.com".into()));
    st.network.set_dns(Some(Arc::new(Cloudflare::with_base(ApiToken::parse(TOKEN).unwrap(), ZONE_ID, &base, false))));
    let mut c = admin(&st, &token).await;

    // Saisies refusées : hors zone, nom invalide, aiguilleur coupé.
    for (addr, code) in [
        (json!({"hostname": "survie.example.org", "mode": "record"}), "outside_zone"),
        (json!({"hostname": "*.example.com", "mode": "record"}), "invalid_hostname"),
        (json!({"hostname": "survie.example.com", "mode": "router"}), "router_disabled"),
    ] {
        let (_, v) = c.post("/api/servers/1/address/preview", json!({ "address": addr })).await;
        assert_eq!(v["code"], code, "{addr}");
    }

    // Aperçu : A + SRV à créer (port 25570), rien d'écrit encore.
    let addr = json!({"hostname": "Survie.Example.com.", "mode": "record"});
    let (s, pre) = c.post("/api/servers/1/address/preview", json!({ "address": addr })).await;
    assert_eq!(s, StatusCode::OK, "{pre}");
    let kinds: Vec<&str> = pre["changes"].as_array().unwrap().iter().map(|x| x["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["create", "create"], "{pre}");
    assert_eq!(fake.records.lock().unwrap().len(), 3);
    // Empreinte fausse ou absente : refus, rien d'écrit.
    for digest in [json!("0000"), Value::Null] {
        let (s, v) = c.post("/api/servers/1/address", json!({ "address": addr, "digest": digest })).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("preview_outdated")));
    }
    assert_eq!(fake.records.lock().unwrap().len(), 3);
    let (s, v) = c.post("/api/servers/1/address", json!({ "address": addr, "digest": pre["digest"] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"].as_array().unwrap().len(), 2);
    assert_eq!(v["view"]["address"]["hostname"], "survie.example.com");
    {
        let recs = fake.records.lock().unwrap();
        let a = find(&recs, "A", "survie.example.com");
        assert_eq!(a.len(), 1);
        assert_eq!((a[0]["content"].as_str(), a[0]["proxied"].as_bool()), (Some(IP), Some(false)));
        assert!(a[0]["comment"].as_str().unwrap().starts_with("rustcraft-manager "));
        let srv = find(&recs, "SRV", "_minecraft._tcp.survie.example.com");
        assert_eq!(
            (srv[0]["data"]["port"].as_u64(), srv[0]["data"]["target"].as_str()),
            (Some(25570), Some("survie.example.com"))
        );
        // Joker, A manuel et TXT marqué à la main (sans empreinte) intacts.
        assert_eq!(recs.iter().filter(|r| ["a1", "a2", "a3"].contains(&r["id"].as_str().unwrap())).count(), 3);
    }
    // Resynchronisation (comme au démarrage) : rien à faire.
    assert!(st.network.sync(&st).await);
    assert_eq!(st.network.info().last_sync.unwrap().applied, 0);

    // A retouché à la main chez Cloudflare : jamais écrasé, même après un changement de port.
    {
        let mut recs = fake.records.lock().unwrap();
        let a = recs.iter_mut().find(|r| r["type"] == "A" && r["name"] == "survie.example.com").unwrap();
        a["content"] = json!("198.51.99.77");
    }
    let (s, v) = c
        .post(
            "/api/servers/1/settings",
            json!({"name": "Survie", "memory_mb": 1024, "port": 25571, "auto_restart": false}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(st.network.sync(&st).await);
    let summary = st.network.info().last_sync.unwrap();
    assert_eq!((summary.applied, summary.conflicts), (1, 1), "{summary:?}");
    {
        let recs = fake.records.lock().unwrap();
        assert_eq!(find(&recs, "A", "survie.example.com")[0]["content"], "198.51.99.77");
        assert_eq!(find(&recs, "SRV", "_minecraft._tcp.survie.example.com")[0]["data"]["port"], 25571);
    }

    // Renommage vers crea (A manuel en place) : conflit montré, A manuel gardé, SRV créé ;
    // l'ancien SRV (à nous, intact) part, l'ancien A retouché reste.
    let crea = json!({"hostname": "crea.example.com", "mode": "record"});
    let (_, pre) = c.post("/api/servers/1/address/preview", json!({ "address": crea })).await;
    assert_eq!(pre["conflicts"][0]["reason"], "manual", "{pre}");
    assert_eq!(pre["conflicts"][0]["existing"], "A 198.51.99.9");
    let v = set_address(&mut c, crea).await;
    assert_eq!(v["conflicts"].as_array().unwrap().len(), 1, "{v}");
    {
        let recs = fake.records.lock().unwrap();
        assert!(find(&recs, "SRV", "_minecraft._tcp.survie.example.com").is_empty());
        assert_eq!(find(&recs, "A", "survie.example.com")[0]["content"], "198.51.99.77");
        let a = find(&recs, "A", "crea.example.com");
        assert_eq!((a.len(), a[0]["id"].as_str()), (1, Some("a2")));
        assert_eq!(find(&recs, "SRV", "_minecraft._tcp.crea.example.com").len(), 1);
    }

    // Nouvelle IP publique : nos enregistrements suivent (ici, rien d'autre que le SRV n'est à nous).
    // Suppression du serveur : ce qui est à nous part, le reste est gardé.
    let srv = st.servers.get(ServerId::parse("1").unwrap()).unwrap();
    st.servers.delete(&srv).unwrap();
    let t0 = std::time::Instant::now();
    while st.servers.get(ServerId::parse("1").unwrap()).is_some() {
        assert!(t0.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(st.network.sync(&st).await);
    {
        let recs = fake.records.lock().unwrap();
        assert!(recs.iter().all(|r| r["type"] != "SRV"), "{recs:?}");
        let ids: Vec<&str> = recs.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(recs.len(), 4, "{ids:?}");
    }
    assert_eq!(*fake.unauthorized.lock().unwrap(), 0);

    // Audit : chaque action, jamais le jeton.
    let rows = audit_details(&st).await;
    let count = |a: &str| rows.iter().filter(|(x, _)| x == a).count();
    assert_eq!(count("address_changed"), 2);
    assert_eq!(count("dns_record_created"), 3, "{rows:?}");
    assert_eq!(count("dns_record_updated"), 1);
    assert_eq!(count("dns_record_deleted"), 2);
    assert!(rows.iter().all(|(_, d)| !d.contains(TOKEN)));
}

/// Jeton refusé par Cloudflare : aperçu en 502 (dns_failed), échec audité, réglage inchangé.
#[tokio::test]
async fn cloudflare_en_echec() {
    let d = tmp("cf-echec");
    let (_fake, base) = fake_cloudflare(Vec::new()).await;
    let (st, token) = state(&d, 25565, |c| c.dns_zone = Some("example.com".into()));
    let wrong = ApiToken::parse("un-autre-jeton-0123456789abcdef").unwrap();
    st.network.set_dns(Some(Arc::new(Cloudflare::with_base(wrong, ZONE_ID, &base, false))));
    let mut c = admin(&st, &token).await;
    let addr = json!({"hostname": "survie.example.com", "mode": "record"});
    let (s, v) = c.post("/api/servers/1/address/preview", json!({ "address": addr })).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("dns_failed")));
    assert!(!st.network.sync(&st).await);
    assert!(st.network.info().last_sync.unwrap().failed);
    assert!(st.network.address(ServerId::parse("1").unwrap()).is_none());
    let rows = audit_details(&st).await;
    assert!(
        rows.iter().any(|(a, d)| a == "dns_sync_failed" && d.contains("403") && !d.contains("un-autre-jeton")),
        "{rows:?}"
    );
}

/// Sans jeton : enregistrements exacts à créer à la main, rien n'est écrit chez personne ; mode
/// aiguilleur : routes de l'aiguilleur, port réservé refusé aux serveurs ; test de joignabilité.
#[tokio::test]
async fn sans_jeton_et_aiguilleur() {
    let d = tmp("manuel");
    let router_port = free_port();
    let (st, token) = state(&d, 25570, |c| {
        c.router = Some(rc_manager::config::Router {
            listen: "127.0.0.1".parse().unwrap(),
            port: router_port,
            max_connections: 16,
            max_per_ip: 4,
        })
    });
    let mut c = admin(&st, &token).await;
    let (s, v) = c.call(Method::GET, "/api/servers/1/address", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (v["network"]["cloudflare"].as_bool(), v["network"]["router_port"].as_u64()),
        (Some(false), Some(router_port as u64))
    );
    assert!(v["address"].is_null());
    // Mode direct : A + SRV vers le port du serveur, aucun changement « chez Cloudflare ».
    let (_, pre) = c
        .post(
            "/api/servers/1/address/preview",
            json!({"address": {"hostname": "survie.example.org", "mode": "record"}}),
        )
        .await;
    assert!(pre["changes"].is_null(), "{pre}");
    assert_eq!(pre["records"][0], json!({"kind": "A", "name": "survie.example.org", "content": IP}));
    assert_eq!(pre["records"][1]["content"], "0 5 25570 survie.example.org");
    // Aiguilleur : SRV vers le port de l'aiguilleur (pas 25565 ici).
    let v = set_address(&mut c, json!({"hostname": "survie.example.org", "mode": "router"})).await;
    assert_eq!(v["view"]["records"][1]["content"], format!("0 5 {router_port} survie.example.org"));
    assert!(v["applied"].as_array().unwrap().is_empty());
    let routes = st.network.routes(st.servers.clone());
    assert_eq!(routes.route("survie.example.org"), Route::Offline, "serveur arrêté");
    assert_eq!(routes.route("autre.example.org"), Route::Unknown);
    // Le port de l'aiguilleur n'est jamais donné à un serveur.
    let (s, v) = c
        .post(
            "/api/servers/1/settings",
            json!({"name": "Survie", "memory_mb": 1024, "port": router_port, "auto_restart": false}),
        )
        .await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::CONFLICT, Some("port_in_use")));
    // Retiré : plus de route.
    set_address(&mut c, Value::Null).await;
    assert_eq!(routes.route("survie.example.org"), Route::Unknown);
    // Test de joignabilité : nom qui ne se résout pas (.invalid, RFC 2606).
    set_address(&mut c, json!({"hostname": "survie.invalid", "mode": "record"})).await;
    let (s, v) = c.post("/api/servers/1/address/test", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["failed"], "resolve");
    // Lecture seule pour tous, écriture : session et CSRF.
    let mut anon = Client { app: rc_manager::router(st.clone()), cookie: None, csrf: None };
    let (s, _) = anon.post("/api/servers/1/address/preview", json!({"address": null})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    c.csrf = None;
    let (s, _) = c.post("/api/servers/1/address", json!({"address": null, "digest": "x"})).await;
    assert_ne!(s, StatusCode::OK);
}
