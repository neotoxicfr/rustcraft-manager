//! Bout en bout : le vrai serveur sur un port libre de 127.0.0.1, base dans un fichier, parlé en
//! HTTP/1.1 brut sur TCP (aucun client HTTP en dépendance), WebSocket compris.

use rc_manager::config::Config;
use rc_manager::crypto::{Keys, MasterKey};
use rc_manager::db::Db;
use rc_manager::{new_state, serve};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

async fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if method != "GET" {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    // Corps éventuellement découpé (chunked) : on garde le JSON entre la première accolade et la
    // dernière, suffisant ici.
    let body = match (body.find('{'), body.rfind('}')) {
        (Some(a), Some(b)) if b >= a => body[a..=b].to_string(),
        _ => body.to_string(),
    };
    Reply { status, head: head.to_string(), body }
}

#[tokio::test]
async fn serveur_reel_sur_port_libre() {
    let dir = std::env::temp_dir().join(format!("rcm-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config::with_data_dir(dir.clone());
    let key = MasterKey::generate();
    let db = Db::open(&cfg.db_path(), Keys::derive(&key)).unwrap();
    let (state, token) = new_state(cfg, db);
    let token = token.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, state, async {
        let _ = stop_rx.await;
    }));

    let r = http(addr, "GET", "/api/health", &[], "").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("\"ok\":true"), "{}", r.body);

    let r = http(addr, "GET", "/api/setup", &[], "").await;
    assert_eq!(r.body, r#"{"needed":true,"passkeys":false}"#);

    let body = format!(r#"{{"token":"{token}","username":"admin","password":"un mot de passe solide"}}"#);
    let r = http(addr, "POST", "/api/setup", &[], &body).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let cookie = r.header("set-cookie").unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let cookie = cookie.split(';').next().unwrap().to_string();

    let r = http(addr, "GET", "/api/auth/me", &[("Cookie", &cookie)], "").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("\"username\":\"admin\""));
    let csrf = r.body.split("\"csrf_token\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();

    // Interface (embarquée ou page d'explication) servie, compressée si demandé.
    let r = http(addr, "GET", "/", &[("Accept-Encoding", "gzip")], "").await;
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").unwrap().starts_with("text/html"));
    assert!(r.header("content-security-policy").is_some());
    let etag = r.header("etag").unwrap();
    let r = http(addr, "GET", "/", &[("Accept-Encoding", "gzip"), ("If-None-Match", &etag)], "").await;
    assert_eq!(r.status, 304);
    // L'ETag désigne une représentation : celle non compressée ne correspond pas.
    if etag.ends_with("-gz\"") {
        let r = http(addr, "GET", "/", &[("If-None-Match", &etag)], "").await;
        assert_eq!(r.status, 200);
    }

    // WebSocket : poignée de main puis message d'accueil.
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /api/ws HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {cookie}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let mut got = Vec::new();
    while !String::from_utf8_lossy(&got).contains("hello") {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("pas de message d'accueil")
            .unwrap();
        assert!(n > 0, "connexion fermée : {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 101"), "{text}");
    assert!(text.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "clé d'acceptation RFC 6455");
    drop(s);

    // WebSocket depuis une autre origine : refusé.
    let r = http(
        addr,
        "GET",
        "/api/ws",
        &[("Cookie", &cookie), ("Origin", "https://evil.example"), ("Upgrade", "websocket")],
        "",
    )
    .await;
    assert_eq!(r.status, 403);

    // Déconnexion avec CSRF, puis session morte.
    let r = http(addr, "POST", "/api/auth/logout", &[("Cookie", &cookie), ("X-CSRF-Token", &csrf)], "{}").await;
    assert_eq!(r.status, 204);
    let r = http(addr, "GET", "/api/auth/me", &[("Cookie", &cookie)], "").await;
    assert_eq!(r.status, 401);

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    // La base persiste : un second démarrage ne propose plus de jeton.
    let cfg = Config::with_data_dir(dir.clone());
    let (_, token2) = new_state(cfg.clone(), Db::open(&cfg.db_path(), Keys::derive(&key)).unwrap());
    assert!(token2.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Serveur réel en mémoire avec une configuration ajustée ; rend (adresse, cookie, arrêt, tâche).
async fn start(
    f: impl FnOnce(&mut Config),
) -> (SocketAddr, String, tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<std::io::Result<()>>) {
    let mut cfg = Config::with_data_dir(std::env::temp_dir());
    f(&mut cfg);
    let (state, token) = new_state(cfg, Db::open_memory().unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, state, async {
        let _ = rx.await;
    }));
    let body = format!(r#"{{"token":"{}","username":"admin","password":"un mot de passe solide"}}"#, token.unwrap());
    let r = http(addr, "POST", "/api/setup", &[], &body).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let cookie = r.header("set-cookie").unwrap().split(';').next().unwrap().to_string();
    (addr, cookie, tx, server)
}

/// Lit jusqu'à la fermeture par le serveur ; rend le temps mis, `None` si rien dans `limit`.
async fn closed_within(s: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout_at(tokio::time::Instant::from_std(t0 + limit), s.read(&mut buf)).await {
            Err(_) => return None,
            Ok(Ok(0)) | Ok(Err(_)) => return Some(t0.elapsed()),
            Ok(Ok(_)) => {}
        }
    }
}

/// Poignée de main WebSocket ; rend la connexion après la réponse 101, ou le statut reçu.
async fn ws_open(addr: SocketAddr, cookie: &str) -> Result<TcpStream, u16> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /api/ws HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {cookie}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0, "fermée pendant la poignée de main");
        got.push(buf[0]);
    }
    let status: u16 = String::from_utf8_lossy(&got).split(' ').nth(1).unwrap().parse().unwrap();
    if status == 101 { Ok(s) } else { Err(status) }
}

use std::time::Duration;

/// Revue I4 : en-têtes trop lents, connexion inactive, plafond de connexions.
#[tokio::test]
async fn delais_et_plafond_de_connexions() {
    let (addr, _cookie, stop, server) = start(|c| {
        c.header_read_timeout = Duration::from_millis(400);
        c.max_connections = 16;
    })
    .await;
    // En-têtes envoyés au compte-gouttes (slowloris) : coupé.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /api/health HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    let t = closed_within(&mut s, Duration::from_secs(3)).await;
    assert!(t.is_some(), "en-têtes incomplets jamais coupés");
    // Connexion ouverte sans rien envoyer : fermée aussi.
    let mut s = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(3)).await.is_some(), "connexion inactive gardée");
    // Après une requête, l'attente de la suivante est bornée de même.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET /api/health HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes()).await.unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(3)).await.is_some(), "connexion gardée inactive");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();

    // Plafond : les connexions au-delà sont fermées tout de suite.
    let (addr, _cookie, stop, server) = start(|c| c.max_connections = 3).await;
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(TcpStream::connect(addr).await.unwrap());
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut extra = TcpStream::connect(addr).await.unwrap();
    let t = closed_within(&mut extra, Duration::from_secs(2)).await;
    assert!(t.is_some(), "connexion au-delà du plafond acceptée");
    drop(held);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = http(addr, "GET", "/api/health", &[], "").await;
    assert_eq!(r.status, 200, "places rendues");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// WebSocket : trames de plus de 64 Kio refusées dès l'en-tête, canaux par session plafonnés,
/// client muet coupé.
#[tokio::test]
async fn websocket_trames_et_plafond_par_session() {
    let (addr, cookie, stop, server) = start(|c| {
        c.ws_per_session = 2;
        c.ws_idle_timeout = Duration::from_millis(500);
    })
    .await;
    // Trame annoncée à 1 Mio (texte, masquée) sans charge : coupée sans attendre la charge.
    let mut s = ws_open(addr, &cookie).await.unwrap();
    let mut frame = vec![0x81u8, 0x80 | 127];
    frame.extend_from_slice(&(1u64 << 20).to_be_bytes());
    frame.extend_from_slice(&[1, 2, 3, 4]);
    s.write_all(&frame).await.unwrap();
    assert!(
        closed_within(&mut s, Duration::from_millis(300)).await.is_some(),
        "trame démesurée attendue au lieu d'être refusée"
    );
    drop(s);
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Deux canaux au plus par session.
    let a = ws_open(addr, &cookie).await.unwrap();
    let mut b = ws_open(addr, &cookie).await.unwrap();
    assert_eq!(ws_open(addr, &cookie).await.err(), Some(429));
    // Client muet : coupé après le délai d'inactivité, et sa place rendue.
    assert!(closed_within(&mut b, Duration::from_secs(3)).await.is_some(), "client muet gardé");
    drop(a);
    drop(b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(ws_open(addr, &cookie).await.is_ok(), "places rendues");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// Revue I-C : un WebSocket garde sa place de connexion (hyper la rendait à l'upgrade) ; l'arrêt
/// ferme les canaux ouverts.
#[tokio::test]
async fn websocket_garde_sa_place_de_connexion() {
    let (addr, cookie, stop, server) = start(|c| {
        c.max_connections = 3;
        c.ws_per_session = 10;
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(ws_open(addr, &cookie).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut extra = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut extra, Duration::from_secs(2)).await.is_some(), "4e connexion acceptée");
    // Arrêt : rendu sans attendre les 10 s de vidange (les canaux se ferment).
    let t0 = std::time::Instant::now();
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(5), "arrêt bloqué par les WebSocket : {:?}", t0.elapsed());
    drop(held);
}

/// Plafond de connexions par adresse (mineur 6).
#[tokio::test]
async fn plafond_de_connexions_par_adresse() {
    let (addr, _cookie, stop, server) = start(|c| c.max_connections_per_ip = 2).await;
    let a = TcpStream::connect(addr).await.unwrap();
    let b = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut c, Duration::from_secs(2)).await.is_some(), "3e connexion de la même adresse acceptée");
    drop((a, b));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(http(addr, "GET", "/api/health", &[], "").await.status, 200, "places rendues");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
