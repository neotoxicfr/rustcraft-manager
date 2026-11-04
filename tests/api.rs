//! Tests de l'API sur le routeur en mémoire (sans réseau) : premier compte, connexion, limite de
//! tentatives (y compris en parallèle), TOTP (valide, invalide, rejoué, session provisoire
//! brûlée), codes de secours, ré-authentification, CSRF, cookies, sessions expirées, mandataires
//! de confiance, en-têtes de sécurité, version, délais.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use rc_manager::config::{Config, CookieSecure, ProxySpec};
use rc_manager::crypto::aad;
use rc_manager::db::Db;
use rc_manager::{AppState, new_state, router, totp};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const PW: &str = "un mot de passe solide";

struct Client {
    app: Router,
    peer: SocketAddr,
    /// Cookie de session suivi comme un navigateur (`nom=valeur`).
    cookie: Option<String>,
    csrf: Option<String>,
    extra: Vec<(&'static str, String)>,
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Resp {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or("")
    }
    fn set_cookie(&self) -> String {
        self.headers.get("set-cookie").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
}

fn request(
    peer: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, String)],
    body: Option<Value>,
) -> Request<Body> {
    let mut b = Request::builder().method(method.clone()).uri(path).header("host", "127.0.0.1:8580");
    if method != Method::GET {
        b = b.header("content-type", "application/json");
    }
    for (k, v) in headers {
        b = b.header(*k, v);
    }
    let body = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
    let mut req = b.body(body).unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

async fn read(res: axum::response::Response) -> Resp {
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp { status, headers, body }
}

impl Client {
    fn new(app: &Router, peer: &str) -> Client {
        Client { app: app.clone(), peer: peer.parse().unwrap(), cookie: None, csrf: None, extra: Vec::new() }
    }

    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut h = self.extra.clone();
        if let Some(c) = &self.cookie {
            h.push(("cookie", c.clone()));
        }
        if let Some(t) = &self.csrf {
            h.push(("x-csrf-token", t.clone()));
        }
        h
    }

    async fn call(&mut self, method: Method, path: &str, body: Option<Value>) -> Resp {
        let req = request(self.peer, method, path, &self.headers(), body);
        let r = read(self.app.clone().oneshot(req).await.unwrap()).await;
        if let Some(sc) = r.headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
            let pair = sc.split(';').next().unwrap().trim().to_string();
            if sc.contains("Max-Age=0") || pair.ends_with('=') {
                self.cookie = None;
                self.csrf = None;
            } else {
                self.cookie = Some(pair);
            }
        }
        if let Some(t) = r.body["me"]["csrf_token"].as_str().or_else(|| r.body["csrf_token"].as_str()) {
            self.csrf = Some(t.to_string());
        }
        r
    }

    async fn post(&mut self, path: &str, body: Value) -> Resp {
        self.call(Method::POST, path, Some(body)).await
    }
    async fn get(&mut self, path: &str) -> Resp {
        self.call(Method::GET, path, None).await
    }
    async fn login(&mut self, user: &str, pw: &str) -> Resp {
        self.post("/api/auth/login", json!({"username": user, "password": pw})).await
    }
}

fn setup_app(f: impl FnOnce(&mut Config)) -> (Router, Arc<AppState>, String) {
    let mut cfg = Config::with_data_dir(std::env::temp_dir());
    f(&mut cfg);
    let (st, token) = new_state(cfg, Db::open_memory().unwrap());
    (router(st.clone()), st, token.expect("jeton du premier compte"))
}

/// Application avec un administrateur `admin` déjà créé (et connecté dans le client rendu).
async fn with_admin(f: impl FnOnce(&mut Config)) -> (Router, Arc<AppState>, Client) {
    let (app, st, token) = setup_app(f);
    let mut c = Client::new(&app, "10.0.0.1:5000");
    let r = c.post("/api/setup", json!({"token": token, "username": "admin", "password": PW})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    (app, st, c)
}

/// Lignes du journal d'audit (après écriture de ce qui attend) : (action, nom, ip, nombre).
async fn audit_rows(st: &AppState) -> Vec<(String, Option<String>, Option<String>, i64)> {
    st.audit.flush().await;
    type Raw = (i64, String, Option<String>, Option<String>, i64);
    let raw: Vec<Raw> = st.db.with(|c| {
        let mut s = c.prepare("SELECT id, action, username, ip, count FROM audit_log ORDER BY id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    });
    // Adresse chiffrée en base, déchiffrée ici pour les vérifications.
    raw.into_iter()
        .map(|(id, a, u, ip, n)| {
            assert!(ip.as_deref().is_none_or(|v| v.starts_with("v1:")), "adresse en clair : {ip:?}");
            (a, u, rc_manager::audit::open(st.db.keys(), "ip", id, ip.as_deref()), n)
        })
        .collect()
}

async fn audit_actions(st: &AppState) -> Vec<String> {
    audit_rows(st).await.into_iter().map(|a| a.0).collect()
}

fn current_step() -> u64 {
    totp::step_at(rc_manager::db::now() as u64)
}

fn decrypt_col(st: &AppState, col: &str) -> Vec<u8> {
    let (id, enc): (i64, String) = st.db.with(|c| {
        c.query_row(&format!("SELECT id, {col}_enc FROM users WHERE username = 'admin'"), [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
    });
    assert!(enc.starts_with("v1:"), "{col} chiffré en base");
    st.db.keys().decrypt(&aad("users", col, id), &enc).unwrap()
}

fn sessions(st: &AppState) -> i64 {
    st.db.with(|c| c.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0)).unwrap())
}

fn reauth(pw: &str, code: Option<String>) -> Value {
    json!({"password": pw, "code": code})
}

/// Active le TOTP de `c` (connecté) ; rend (secret, codes de secours).
async fn enable_totp(st: &AppState, c: &mut Client) -> (Vec<u8>, Vec<String>) {
    let r = c.post("/api/account/totp/setup", json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    let pending = decrypt_col(st, "totp_pending");
    let r = c
        .post(
            "/api/account/totp/enable",
            json!({"reauth": reauth(PW, None), "code": totp::code(&pending, current_step())}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let codes = r.body["recovery_codes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    (pending, codes)
}

#[tokio::test]
async fn jeton_du_premier_compte_a_usage_unique() {
    let (app, st, token) = setup_app(|_| {});
    let mut c = Client::new(&app, "10.0.0.1:5000");
    assert_eq!(c.get("/api/setup").await.body["needed"], true);

    let r = c.post("/api/setup", json!({"token": "FAUX", "username": "admin", "password": PW})).await;
    assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, "invalid_setup_token"));

    // Saisie invalide : refusée sans consommer le jeton.
    let r = c.post("/api/setup", json!({"token": token, "username": "admin", "password": "court"})).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNPROCESSABLE_ENTITY, "weak_password"));
    let r = c.post("/api/setup", json!({"token": token, "username": "a b", "password": PW})).await;
    assert_eq!(r.code(), "invalid_username");

    let r = c.post("/api/setup", json!({"token": token, "username": "admin", "password": PW})).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["status"], "logged_in");
    assert_eq!(r.body["me"]["is_admin"], true);
    assert!(c.cookie.is_some());
    assert_eq!(c.get("/api/auth/me").await.body["username"], "admin");

    // Second usage du même jeton : refusé.
    let mut other = Client::new(&app, "10.0.0.2:5000");
    let r = other.post("/api/setup", json!({"token": token, "username": "pirate", "password": PW})).await;
    assert_eq!((r.status, r.code()), (StatusCode::CONFLICT, "setup_not_needed"));
    assert_eq!(other.get("/api/setup").await.body["needed"], false);
    let n: i64 = st.db.with(|c| c.query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap());
    assert_eq!(n, 1);
    let actions = audit_actions(&st).await;
    assert!(actions.contains(&"setup_bad_token".into()));
    assert!(actions.contains(&"setup_admin_created".into()));
}

#[tokio::test]
async fn connexion_bons_et_mauvais_mots_de_passe() {
    let (app, st, _) = with_admin(|_| {}).await;
    let mut c = Client::new(&app, "10.0.0.3:5000");
    let r = c.login("admin", "mauvais mot de passe").await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "invalid_credentials"));
    assert!(c.cookie.is_none());
    // Compte inconnu : même réponse.
    let r = c.login("personne", PW).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "invalid_credentials"));
    // Nom insensible à la casse.
    let r = c.login("ADMIN", PW).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["status"], "logged_in");
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::OK);
    // Déconnexion : session détruite côté serveur.
    let old = c.cookie.clone();
    let r = c.post("/api/auth/logout", json!({})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.set_cookie().contains("Max-Age=0"));
    c.cookie = old;
    let r = c.get("/api/auth/me").await;
    // L'API ne redirige jamais : 401 avec un code machine.
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "unauthorized"));
    let rows = audit_rows(&st).await;
    let failed: i64 = rows.iter().filter(|a| a.0 == "login_failed").map(|a| a.3).sum();
    assert_eq!(failed, 2);
    assert!(rows.iter().any(|a| a.0 == "logout"));
}

#[tokio::test]
async fn limite_de_tentatives() {
    let (app, _st, _) = with_admin(|_| {}).await;
    let mut c = Client::new(&app, "10.0.0.4:5000");
    for _ in 0..5 {
        assert_eq!(c.login("admin", "mauvais mot de passe").await.status, StatusCode::UNAUTHORIZED);
    }
    // Même le bon mot de passe est refusé pendant la fenêtre.
    let r = c.login("admin", PW).await;
    assert_eq!((r.status, r.code()), (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"));
    assert!(r.headers.contains_key("retry-after"));
    assert!(r.body["retry_after_secs"].as_u64().unwrap() > 0);
    // Une autre adresse n'est pas bloquée (pas de verrouillage du compte lui-même).
    let mut other = Client::new(&app, "10.0.0.5:5000");
    assert_eq!(other.login("admin", PW).await.status, StatusCode::OK);
}

/// Statuts de `n` requêtes lancées en même temps.
async fn burst(app: &Router, n: usize, mk: impl Fn(usize) -> Request<Body>) -> Vec<(StatusCode, String)> {
    let tasks: Vec<_> = (0..n)
        .map(|i| {
            let app = app.clone();
            let req = mk(i);
            tokio::spawn(async move {
                let r = read(app.oneshot(req).await.unwrap()).await;
                (r.status, r.code().to_string())
            })
        })
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

/// Revue B1 : 50 mauvais mots de passe envoyés EN MÊME TEMPS depuis une adresse ne donnent pas 50
/// essais ; au plus `login_max_failures` atteignent Argon2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limite_tenue_sous_requetes_simultanees() {
    let (app, _st, _) = with_admin(|cfg| cfg.auth_inflight_per_ip = 1000).await;
    let peer: SocketAddr = "10.0.0.30:5000".parse().unwrap();
    let st = burst(&app, 50, |_| {
        request(
            peer,
            Method::POST,
            "/api/auth/login",
            &[],
            Some(json!({"username": "admin", "password": "mauvais mot de passe"})),
        )
    })
    .await;
    let tried = st.iter().filter(|s| s.0 == StatusCode::UNAUTHORIZED).count();
    let limited = st.iter().filter(|s| s.0 == StatusCode::TOO_MANY_REQUESTS).count();
    assert!(tried <= 5, "{tried} essais passés sur 50");
    assert_eq!(tried + limited, 50, "{st:?}");
}

/// Requêtes d'authentification en cours bornées par adresse (noms tous différents : seule cette
/// borne s'applique).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requetes_en_cours_bornees_par_adresse() {
    let (app, _st, _) = with_admin(|cfg| cfg.login_max_failures = 1000).await;
    let peer: SocketAddr = "10.0.0.31:5000".parse().unwrap();
    let st = burst(&app, 24, |i| {
        request(
            peer,
            Method::POST,
            "/api/auth/login",
            &[],
            Some(json!({"username": format!("u{i}x"), "password": "mauvais mot de passe"})),
        )
    })
    .await;
    let busy = st.iter().filter(|s| s.0 == StatusCode::TOO_MANY_REQUESTS).count();
    // 4 places par adresse : la grande majorité refusée tout de suite (marge pour l'ordonnanceur).
    assert!(busy >= 12, "{st:?}");
}

/// Revue B2 : une IPv6 par /64 (changer d'adresse dans son /64 ne remet pas le compteur à zéro),
/// IPv4 vue en IPv6 = IPv4 ; nom invalide absent de l'audit ; échecs agrégés.
#[tokio::test]
async fn ipv6_par_64_et_audit_agrege() {
    let (app, st, _) = with_admin(|_| {}).await;
    for i in 1..=5 {
        let mut c = Client::new(&app, &format!("[2001:db8:5:6::{i}]:5000"));
        assert_eq!(c.login("admin", "mauvais mot de passe").await.status, StatusCode::UNAUTHORIZED);
    }
    let mut c = Client::new(&app, "[2001:db8:5:6::abcd]:5000");
    assert_eq!(c.login("admin", PW).await.status, StatusCode::TOO_MANY_REQUESTS);
    let mut c = Client::new(&app, "[2001:db8:5:7::1]:5000");
    assert_eq!(c.login("admin", PW).await.status, StatusCode::OK, "autre /64");
    for _ in 0..5 {
        let mut c = Client::new(&app, "10.0.0.40:5000");
        c.login("admin", "mauvais mot de passe").await;
    }
    let mut c = Client::new(&app, "[::ffff:10.0.0.40]:5000");
    assert_eq!(c.login("admin", PW).await.status, StatusCode::TOO_MANY_REQUESTS);
    // Nom tenté invalide (peut-être un mot de passe tapé au mauvais endroit) : pas dans l'audit.
    let mut c = Client::new(&app, "10.0.0.41:5000");
    c.login("mon mot de passe secret", PW).await;
    let rows = audit_rows(&st).await;
    let fails: Vec<_> = rows.iter().filter(|r| r.0 == "login_failed").collect();
    assert!(fails.iter().all(|r| r.1.as_deref() != Some("mon mot de passe secret")));
    assert!(fails.iter().any(|r| r.1.is_none() && r.2.as_deref() == Some("10.0.0.41")));
    // 5 échecs depuis 10.0.0.40 : une seule ligne, comptée 5.
    let r = fails.iter().find(|r| r.2.as_deref() == Some("10.0.0.40")).unwrap();
    assert_eq!(r.3, 5);
}

#[tokio::test]
async fn totp_valide_invalide_rejoue_et_codes_de_secours() {
    let (app, st, mut c) = with_admin(|_| {}).await;

    // Activation sans préparation : refusée.
    let r = c.post("/api/account/totp/enable", json!({"reauth": reauth(PW, None), "code": "000000"})).await;
    assert_eq!(r.code(), "totp_setup_missing");
    let r = c.post("/api/account/totp/setup", json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body["qr_svg"].as_str().unwrap().contains("<svg"));
    assert!(r.body["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/"));
    // Secret en attente chiffré en base (`v1:`), lié à sa ligne.
    let pending = decrypt_col(&st, "totp_pending");
    assert_eq!(rc_manager::crypto::base32(&pending), r.body["secret"].as_str().unwrap());
    let now = current_step();
    // Mauvais code d'activation.
    let wrong = format!("{:06}", (totp::hotp(&pending, now, 6) + 1) % 1_000_000);
    let r = c.post("/api/account/totp/enable", json!({"reauth": reauth(PW, None), "code": wrong})).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "invalid_totp"));
    let r = c
        .post("/api/account/totp/enable", json!({"reauth": reauth(PW, None), "code": totp::code(&pending, now)}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let codes: Vec<String> =
        r.body["recovery_codes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(c.get("/api/auth/me").await.body["totp_enabled"], true);
    let secret = decrypt_col(&st, "totp_secret");
    assert_eq!(secret, pending);
    // Codes de secours en HMAC (schéma 1), jamais en clair.
    let schemes: Vec<i64> = st.db.with(|c| {
        c.prepare("SELECT scheme FROM recovery_codes")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    });
    assert!(schemes.iter().all(|s| *s == 1));

    // Connexion : mot de passe puis code.
    let mut d = Client::new(&app, "10.0.0.6:5000");
    let r = d.login("admin", PW).await;
    assert_eq!(r.body["status"], "totp_required");
    assert!(d.cookie.is_some());
    // La session provisoire n'ouvre rien d'autre.
    assert_eq!(d.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
    // Le code d'activation (même pas) est un rejeu.
    let r = d.post("/api/auth/totp", json!({"code": totp::code(&secret, now)})).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "invalid_totp"));
    let r = d.post("/api/auth/totp", json!({"code": "12345"})).await;
    assert_eq!(r.code(), "invalid_totp");
    let next = totp::code(&secret, current_step() + 1);
    let r = d.post("/api/auth/totp", json!({"code": next})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["status"], "logged_in");
    assert_eq!(d.get("/api/auth/me").await.status, StatusCode::OK);

    // Même code une seconde fois (autre connexion) : rejeu refusé.
    let mut e = Client::new(&app, "10.0.0.7:5000");
    assert_eq!(e.login("admin", PW).await.body["status"], "totp_required");
    let r = e.post("/api/auth/totp", json!({"code": next})).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "invalid_totp"));

    // Code de secours (minuscules, sans tiret : toléré), une seule fois.
    let rc = codes[3].replace('-', "").to_lowercase();
    let r = e.post("/api/auth/totp", json!({"code": rc})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(e.get("/api/auth/me").await.body["recovery_codes_left"], 9);
    let mut f = Client::new(&app, "10.0.0.8:5000");
    assert_eq!(f.login("admin", PW).await.body["status"], "totp_required");
    let r = f.post("/api/auth/totp", json!({"code": codes[3]})).await;
    assert_eq!(r.code(), "invalid_totp");

    // Désactivation : mot de passe ET code exigés.
    let r =
        c.post("/api/account/totp/disable", json!({"reauth": reauth("faux faux faux", Some(codes[0].clone()))})).await;
    assert_eq!(r.code(), "invalid_credentials");
    let r = c.post("/api/account/totp/disable", json!({"reauth": reauth(PW, None)})).await;
    assert_eq!(r.code(), "invalid_totp");
    let r = c.post("/api/account/totp/disable", json!({"reauth": reauth(PW, Some(codes[0].clone()))})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(c.get("/api/auth/me").await.body["totp_enabled"], false);
    let actions = audit_actions(&st).await;
    for a in ["totp_enabled", "login_totp_failed", "totp_disabled", "reauth_failed"] {
        assert!(actions.contains(&a.to_string()), "{a} absent de l'audit");
    }
}

/// Session provisoire brûlée après PENDING_TOTP_TRIES codes faux, même envoyés en parallèle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_provisoire_brulee() {
    // Limiteurs larges : seule la borne de la session provisoire joue ici.
    let (app, st, mut c) = with_admin(|cfg| {
        cfg.login_max_failures = 1000;
        cfg.auth_inflight_per_ip = 1000;
    })
    .await;
    let (secret, _) = enable_totp(&st, &mut c).await;
    let mut d = Client::new(&app, "10.0.0.50:5000");
    assert_eq!(d.login("admin", PW).await.body["status"], "totp_required");
    let headers = d.headers();
    let peer = d.peer;
    let wrong = format!("{:06}", (totp::hotp(&secret, current_step(), 6) + 7) % 1_000_000);
    let st_codes =
        burst(&app, 20, |_| request(peer, Method::POST, "/api/auth/totp", &headers, Some(json!({"code": wrong}))))
            .await;
    // Au plus PENDING_TOTP_TRIES codes réellement vérifiés (`invalid_totp`), le reste refusé
    // avant (`unauthorized` : session brûlée).
    let checked = st_codes.iter().filter(|s| s.1 == "invalid_totp").count();
    let gone = st_codes.iter().filter(|s| s.1 == "unauthorized").count();
    // Plafond dur du second facteur pour le compte (toutes adresses) : 429 au-delà.
    let locked = st_codes.iter().filter(|s| s.1 == "too_many_attempts").count();
    assert!((1..=rc_manager::api::PENDING_TOTP_TRIES as usize).contains(&checked), "{st_codes:?}");
    assert_eq!(checked + gone + locked, 20, "{st_codes:?}");
    let attempts: i64 =
        st.db.with(|c| c.query_row("SELECT count(*) FROM sessions WHERE pending_totp = 1", [], |r| r.get(0)).unwrap());
    assert_eq!(attempts, 0, "session provisoire brûlée");
    // Même le bon code ne passe plus : retour au mot de passe.
    let r = d.post("/api/auth/totp", json!({"code": totp::code(&secret, current_step() + 1)})).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "unauthorized"));
    // Chaque essai audité (agrégé).
    let rows = audit_rows(&st).await;
    let n: i64 = rows.iter().filter(|r| r.0 == "login_totp_failed").map(|r| r.3).sum();
    assert!((rc_manager::api::PENDING_TOTP_TRIES..=20).contains(&n), "{n}");
}

/// Revue B-B : plafond DUR des codes faux par compte, toutes adresses (ici 11 réseaux /48
/// différents) ; le bon code lui-même est refusé jusqu'à la fin de la fenêtre, audit dédié.
#[tokio::test]
async fn plafond_dur_du_second_facteur_toutes_adresses() {
    let (app, st, mut c) = with_admin(|_| {}).await;
    let (secret, _) = enable_totp(&st, &mut c).await;
    let wrong = format!("{:06}", (totp::hotp(&secret, current_step(), 6) + 7) % 1_000_000);
    for i in 0..rc_manager::ratelimit::ACCOUNT_HARD_CAP {
        let mut d = Client::new(&app, &format!("[2001:db8:{i:x}::1]:5000"));
        assert_eq!(d.login("admin", PW).await.body["status"], "totp_required");
        assert_eq!(d.post("/api/auth/totp", json!({"code": wrong})).await.code(), "invalid_totp");
    }
    let mut d = Client::new(&app, "[2001:dbf::1]:5000");
    assert_eq!(d.login("admin", PW).await.body["status"], "totp_required");
    let r = d.post("/api/auth/totp", json!({"code": totp::code(&secret, current_step() + 1)})).await;
    assert_eq!((r.status, r.code()), (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"));
    assert!(audit_actions(&st).await.contains(&"second_factor_locked".to_string()));
}

/// Revue I1 : activer le TOTP exige le mot de passe ; activer et désactiver ferment les autres
/// sessions ; changer le mot de passe exige le code quand le TOTP est actif ; limiteur propre à la
/// ré-authentification.
#[tokio::test]
async fn reauthentification_des_actions_sensibles() {
    let (app, st, mut c) = with_admin(|_| {}).await;
    let mut other = Client::new(&app, "10.0.0.60:5000");
    assert_eq!(other.login("admin", PW).await.status, StatusCode::OK);
    c.post("/api/account/totp/setup", json!({})).await;
    let pending = decrypt_col(&st, "totp_pending");
    let code = totp::code(&pending, current_step());
    // Session volée seule : refusée (mot de passe absent ou faux).
    let r = c.post("/api/account/totp/enable", json!({"code": code})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = c.post("/api/account/totp/enable", json!({"reauth": reauth("pas le bon mdp", None), "code": code})).await;
    assert_eq!(r.code(), "invalid_credentials");
    let r = c.post("/api/account/totp/enable", json!({"reauth": reauth(PW, None), "code": code})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    // L'autre session est fermée, la courante reste.
    assert_eq!(other.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::OK);
    let secret = decrypt_col(&st, "totp_secret");

    // Mot de passe : code exigé tant que le TOTP est actif.
    let r = c.post("/api/account/password", json!({"reauth": reauth(PW, None), "new": "nouveau mot de passe"})).await;
    assert_eq!(r.code(), "invalid_totp");
    let r = c
        .post(
            "/api/account/password",
            json!({"reauth": reauth(PW, Some(totp::code(&secret, current_step() + 1))), "new": "nouveau mot de passe"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);

    // Désactivation avec un code faux : rien n'est fermé ni changé.
    let n_before = sessions(&st);
    let r = c
        .post("/api/account/totp/disable", json!({"reauth": reauth("nouveau mot de passe", Some("000000".into()))}))
        .await;
    assert_eq!(r.code(), "invalid_totp");
    assert_eq!(sessions(&st), n_before, "rien fermé sur un échec");

    // Limiteur de ré-authentification : 5 échecs puis 429, sans toucher à la connexion.
    for _ in 0..5 {
        c.post("/api/account/password", json!({"reauth": reauth("faux faux faux", None), "new": "x".repeat(12)})).await;
    }
    let r =
        c.post("/api/account/password", json!({"reauth": reauth("faux faux faux", None), "new": "x".repeat(12)})).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let mut fresh = Client::new(&app, "10.0.0.62:5000");
    assert_eq!(fresh.login("admin", "nouveau mot de passe").await.body["status"], "totp_required");
}

/// Mineur 9 : les codes de secours de la version 1 (SHA-256 salée) sont signalés et se
/// régénèrent en HMAC, derrière la ré-authentification.
#[tokio::test]
async fn codes_de_secours_anciens_regeneres() {
    let (_app, st, mut c) = with_admin(|_| {}).await;
    let (secret, _) = enable_totp(&st, &mut c).await;
    st.db.with(|db| {
        db.execute("INSERT INTO recovery_codes (user_id, code_hash, scheme) VALUES (1, x'00', 0)", []).unwrap();
    });
    assert_eq!(c.get("/api/auth/me").await.body["recovery_codes_legacy"], 1);
    let r = c.post("/api/account/recovery/regenerate", json!({})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "ré-authentification exigée");
    let r = c
        .post(
            "/api/account/recovery/regenerate",
            json!({"reauth": reauth(PW, Some(totp::code(&secret, current_step() + 1)))}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["recovery_codes"].as_array().unwrap().len(), 10);
    let me = c.get("/api/auth/me").await.body;
    assert_eq!((me["recovery_codes_legacy"].as_u64(), me["recovery_codes_left"].as_u64()), (Some(0), Some(10)));
    assert!(audit_actions(&st).await.contains(&"recovery_codes_regenerated".to_string()));
}

/// Mineur 1 : une saisie invalide est refusée AVANT la ré-authentification, sans consommer le
/// code de secours fourni.
#[tokio::test]
async fn corps_valide_avant_la_reauthentification() {
    let (_app, st, mut c) = with_admin(|_| {}).await;
    let (_, codes) = enable_totp(&st, &mut c).await;
    let r =
        c.post("/api/account/password", json!({"reauth": reauth(PW, Some(codes[0].clone())), "new": "court"})).await;
    assert_eq!((r.status, r.code()), (StatusCode::UNPROCESSABLE_ENTITY, "weak_password"));
    assert_eq!(c.get("/api/auth/me").await.body["recovery_codes_left"], 10, "code de secours brûlé pour rien");
}

#[tokio::test]
async fn desactivation_ferme_les_autres_sessions() {
    let (app, st, mut c) = with_admin(|_| {}).await;
    let (_, codes) = enable_totp(&st, &mut c).await;
    let mut other = Client::new(&app, "10.0.0.70:5000");
    other.login("admin", PW).await;
    assert_eq!(other.post("/api/auth/totp", json!({"code": codes[1]})).await.status, StatusCode::OK);
    let r = c.post("/api/account/totp/disable", json!({"reauth": reauth(PW, Some(codes[2].clone()))})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(other.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::OK);
}

#[tokio::test]
async fn csrf_refuse() {
    let (app, _st, mut c) = with_admin(|_| {}).await;
    let body = json!({"reauth": reauth(PW, None), "new": "nouveau mot de passe"});
    // Sans jeton.
    let csrf = c.csrf.take();
    let r = c.post("/api/account/password", body.clone()).await;
    assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, "csrf_rejected"));
    // Mauvais jeton.
    c.csrf = Some("faux".into());
    assert_eq!(c.post("/api/account/password", body.clone()).await.status, StatusCode::FORBIDDEN);
    c.csrf = csrf;
    // Autre origine.
    c.extra = vec![("origin", "https://evil.example".into())];
    assert_eq!(c.post("/api/account/password", body.clone()).await.status, StatusCode::FORBIDDEN);
    // Même hôte, autre schéma : refusé.
    c.extra = vec![("origin", "https://127.0.0.1:8580".into())];
    assert_eq!(c.post("/api/account/password", body.clone()).await.status, StatusCode::FORBIDDEN);
    // Type de contenu d'un formulaire (requête « simple » possible depuis un autre site).
    c.extra.clear();
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .header("content-type", "text/plain")
        .header("cookie", c.cookie.clone().unwrap())
        .header("x-csrf-token", c.csrf.clone().unwrap())
        .body(Body::from("{}"))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo("10.0.0.1:5000".parse::<SocketAddr>().unwrap()));
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
    // Même origine et bon jeton : accepté.
    c.extra = vec![("origin", "http://127.0.0.1:8580".into())];
    assert_eq!(c.post("/api/account/password", body).await.status, StatusCode::NO_CONTENT);
    let mut d = Client::new(&app, "10.0.0.9:5000");
    assert_eq!(d.login("admin", "nouveau mot de passe").await.status, StatusCode::OK);
}

/// Derrière le mandataire en HTTPS, une page `http://` du même nom ne peut rien modifier.
#[tokio::test]
async fn origine_comparee_schema_compris_derriere_le_mandataire() {
    let (app, _st, _) = with_admin(|cfg| cfg.trusted_proxies = vec![ProxySpec::parse("172.20.0.2").unwrap()]).await;
    let mut c = Client::new(&app, "172.20.0.2:4000");
    c.extra = vec![
        ("x-forwarded-proto", "https".into()),
        ("x-forwarded-host", "nas.example.org".into()),
        ("x-forwarded-for", "203.0.113.5".into()),
    ];
    assert_eq!(c.login("admin", PW).await.status, StatusCode::OK);
    c.extra.push(("origin", "http://nas.example.org".into()));
    assert_eq!(c.post("/api/auth/logout", json!({})).await.status, StatusCode::FORBIDDEN);
    c.extra.pop();
    c.extra.push(("origin", "https://nas.example.org".into()));
    assert_eq!(c.post("/api/auth/logout", json!({})).await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn attributs_du_cookie() {
    let (app, _st, token) = setup_app(|_| {});
    let mut c = Client::new(&app, "10.0.0.1:5000");
    let r = c.post("/api/setup", json!({"token": token, "username": "admin", "password": PW})).await;
    let sc = r.set_cookie();
    for attr in ["rcm_session=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(sc.contains(attr), "{attr} absent : {sc}");
    }
    assert!(!sc.contains("Secure"), "pas de Secure en HTTP simple : {sc}");
    assert!(!r.headers.contains_key("strict-transport-security"));

    // Toujours Secure si demandé (image Docker : RCM_COOKIE_SECURE=always), nom `__Host-`.
    let (_app, _st, mut c) = with_admin(|cfg| cfg.cookie_secure = CookieSecure::Always).await;
    let r = c.login("admin", PW).await;
    let sc = r.set_cookie();
    assert!(sc.starts_with("__Host-rcm_session=") && sc.contains("; Secure") && sc.contains("Path=/"), "{sc}");
    assert!(!sc.contains("Domain"), "{sc}");
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::OK);
    // Un `rcm_session` sans préfixe (posable par un sous-domaine) n'est pas lu en HTTPS.
    let v = c.cookie.clone().unwrap().replace("__Host-rcm_session=", "rcm_session=");
    c.cookie = Some(v);
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);

    // Auto : Secure et HSTS seulement si un mandataire DE CONFIANCE dit https.
    let (app, _st, _) = with_admin(|cfg| {
        cfg.trusted_proxies = vec![ProxySpec::parse("172.20.0.0/24").unwrap()];
    })
    .await;
    let mut via_proxy = Client::new(&app, "172.20.0.2:4000");
    via_proxy.extra = vec![("x-forwarded-proto", "https".into()), ("x-forwarded-for", "8.8.4.4".into())];
    let r = via_proxy.login("admin", PW).await;
    assert!(r.set_cookie().contains("; Secure"), "{}", r.set_cookie());
    assert!(r.set_cookie().starts_with("__Host-"));
    assert_eq!(r.headers["strict-transport-security"], "max-age=31536000");
    let mut direct = Client::new(&app, "10.9.9.9:4000");
    direct.extra = vec![("x-forwarded-proto", "https".into())];
    let r = direct.login("admin", PW).await;
    assert!(!r.set_cookie().contains("Secure"));
    assert!(!r.headers.contains_key("strict-transport-security"));
}

/// Revue I-C : sessions par compte bornées ; les plus anciennes partent, la nouvelle reste.
#[tokio::test]
async fn sessions_par_compte_bornees() {
    let (app, st, mut first) = with_admin(|_| {}).await;
    let max = rc_manager::api::MAX_SESSIONS_PER_USER;
    let mut last = None;
    for i in 0..max + 2 {
        let mut c = Client::new(&app, &format!("10.1.{}.1:5000", i));
        assert_eq!(c.login("admin", PW).await.status, StatusCode::OK);
        last = Some(c);
    }
    assert_eq!(sessions(&st) as usize, max);
    assert_eq!(first.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED, "la plus ancienne est fermée");
    assert_eq!(last.unwrap().get("/api/auth/me").await.status, StatusCode::OK);
}

#[tokio::test]
async fn session_expiree() {
    let (app, st, mut c) = with_admin(|_| {}).await;
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::OK);
    let idle = st.config.session_idle.as_secs() as i64;
    // Inactive trop longtemps.
    st.db.with(|db| {
        db.execute("UPDATE sessions SET last_seen = last_seen - ?1", [idle + 1]).unwrap();
    });
    assert_eq!(c.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(sessions(&st), 0, "session expirée effacée");
    // Durée maximale dépassée, même active.
    let mut d = Client::new(&app, "10.0.0.10:5000");
    d.login("admin", PW).await;
    st.db.with(|db| {
        db.execute("UPDATE sessions SET expires_at = ?1", [rc_manager::db::now() - 1]).unwrap();
    });
    assert_eq!(d.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn x_forwarded_for_non_fiable_ignore() {
    let (app, st, _) = with_admin(|_| {}).await;
    assert!(!st.xff_warned.load(std::sync::atomic::Ordering::Relaxed));
    // Aucun mandataire de confiance : changer X-Forwarded-For ne contourne pas la limite.
    let mut c = Client::new(&app, "10.0.0.20:5000");
    for i in 0..5 {
        c.extra = vec![("x-forwarded-for", format!("1.2.3.{i}"))];
        c.login("admin", "mauvais mot de passe").await;
    }
    c.extra = vec![("x-forwarded-for", "9.9.9.9".into())];
    assert_eq!(c.login("admin", PW).await.status, StatusCode::TOO_MANY_REQUESTS);
    // Signalé (une fois) dans le journal du processus.
    assert!(st.xff_warned.load(std::sync::atomic::Ordering::Relaxed));
    // L'audit garde l'adresse réelle du pair.
    let ips: Vec<String> =
        audit_rows(&st).await.into_iter().filter(|a| a.0 == "login_failed").filter_map(|a| a.2).collect();
    assert!(ips.iter().all(|ip| ip == "10.0.0.20"), "{ips:?}");
}

#[tokio::test]
async fn limite_par_client_derriere_un_mandataire_de_confiance() {
    let (app, st, _) = with_admin(|cfg| {
        cfg.trusted_proxies = vec![ProxySpec::parse("172.20.0.2").unwrap()];
    })
    .await;
    let mut a = Client::new(&app, "172.20.0.2:4000");
    a.extra = vec![("x-forwarded-for", "203.0.113.7".into())];
    for _ in 0..5 {
        a.login("admin", "mauvais mot de passe").await;
    }
    assert_eq!(a.login("admin", PW).await.status, StatusCode::TOO_MANY_REQUESTS);
    // Autre client derrière le même mandataire : pas bloqué.
    let mut b = Client::new(&app, "172.20.0.2:4001");
    b.extra = vec![("x-forwarded-for", "198.51.100.9".into())];
    assert_eq!(b.login("admin", PW).await.status, StatusCode::OK);
    // Un client qui invente une adresse à gauche reste reconnu par celle vue par le mandataire.
    let mut liar = Client::new(&app, "172.20.0.2:4002");
    liar.extra = vec![("x-forwarded-for", "198.51.100.9, 203.0.113.7".into())];
    assert_eq!(liar.login("admin", PW).await.status, StatusCode::TOO_MANY_REQUESTS);
    // Un autre conteneur du même réseau Docker n'est PAS de confiance.
    let mut neighbour = Client::new(&app, "172.20.0.9:4000");
    neighbour.extra = vec![("x-forwarded-for", "198.51.100.77".into())];
    neighbour.login("admin", "mauvais mot de passe").await;
    let ips: Vec<String> =
        audit_rows(&st).await.into_iter().filter(|a| a.0 == "login_failed").filter_map(|a| a.2).collect();
    assert!(ips.iter().all(|ip| ip == "203.0.113.7" || ip == "172.20.0.9"), "{ips:?}");
}

/// Mandataire désigné par son NOM : de confiance seulement une fois résolu.
#[tokio::test]
async fn mandataire_par_nom() {
    let (app, st, _) = with_admin(|cfg| cfg.trusted_proxies = vec![ProxySpec::parse("localhost").unwrap()]).await;
    let mut c = Client::new(&app, "127.0.0.1:4000");
    c.extra = vec![("x-forwarded-for", "203.0.113.99".into())];
    c.login("admin", "mauvais mot de passe").await;
    st.proxies.refresh().await;
    c.login("admin", "mauvais mot de passe").await;
    let ips: Vec<String> =
        audit_rows(&st).await.into_iter().filter(|a| a.0 == "login_failed").filter_map(|a| a.2).collect();
    assert!(ips.contains(&"127.0.0.1".to_string()), "refus avant résolution : {ips:?}");
    assert!(ips.contains(&"203.0.113.99".to_string()), "confiance après résolution : {ips:?}");
}

#[tokio::test]
async fn version_seulement_en_local_ou_connecte() {
    let (app, _st, mut c) = with_admin(|_| {}).await;
    let mut anon = Client::new(&app, "10.0.0.80:5000");
    let r = anon.get("/api/health").await;
    assert_eq!(r.body["ok"], true);
    assert!(r.body.get("version").is_none(), "{:?}", r.body);
    let r = anon.get("/version").await;
    assert_eq!(r.body["ui"], rc_manager::assets::UI_VERSION);
    assert!(r.body.get("version").is_none() && r.body.get("commit").is_none());
    assert_eq!(r.headers["cache-control"], "no-store");
    // Connecté : version et commit.
    assert!(c.get("/api/health").await.body["version"].is_string());
    let r = c.get("/version").await;
    assert_eq!(r.body["commit"], rc_manager::COMMIT);
    // Local (sonde de santé du conteneur, vérification du déploiement).
    let mut local = Client::new(&app, "127.0.0.1:5000");
    assert!(local.get("/api/health").await.body["version"].is_string());
    // Mineur 4 : un mandataire local non déclaré relaie des clients distants : pas « local ».
    local.extra = vec![("x-forwarded-for", "203.0.113.8".into())];
    assert!(local.get("/api/health").await.body.get("version").is_none());
    assert!(local.get("/version").await.body.get("commit").is_none());
}

#[tokio::test]
async fn en_tetes_de_securite_et_interface() {
    let (app, _st, _) = setup_app(|_| {});
    let mut c = Client::new(&app, "10.0.0.1:5000");
    let r = c.get("/").await;
    assert_eq!(r.status, StatusCode::OK);
    let csp = r.headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("'wasm-unsafe-eval'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.headers["x-frame-options"], "DENY");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(r.headers["referrer-policy"], "no-referrer");
    assert_eq!(r.headers["cross-origin-resource-policy"], "same-origin");
    let pp = r.headers["permissions-policy"].to_str().unwrap();
    for f in ["camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"] {
        assert!(pp.contains(f), "{f} : {pp}");
    }
    // Navigation de l'application : index servi pour une adresse sans extension.
    assert_eq!(c.get("/account").await.status, StatusCode::OK);
    assert_eq!(c.get("/absent.js").await.status, StatusCode::NOT_FOUND);
    let r = c.get("/api/inconnue").await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));
    assert_eq!(r.headers["cache-control"], "no-store");
    // WebSocket : session exigée, 401 avec code machine.
    let r = c.get("/api/ws").await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, "unauthorized"));
    // Corps JSON invalide : erreur propre.
    let r = c.call(Method::POST, "/api/auth/login", Some(json!({"x": 1}))).await;
    assert_eq!((r.status, r.code()), (StatusCode::BAD_REQUEST, "bad_request"));
    // Appli installable : manifeste avec son type (sinon refusé avec nosniff), service worker
    // versionné par l'empreinte de l'interface.
    if rc_manager::assets::WEB_BUILT {
        let r = c.get("/manifest.webmanifest").await;
        assert_eq!(r.headers["content-type"], "application/manifest+json");
        assert_eq!(r.body["id"], "/");
        let sw = rc_manager::assets::find("/sw.js").expect("sw.js embarqué");
        let text = std::str::from_utf8(sw.body).unwrap();
        assert!(text.contains(&format!("rcm-{}", rc_manager::assets::UI_VERSION)), "cache versionné");
        assert!(!text.contains("__RCM_UI_VERSION__"));
    }
}

/// Revue I4 : un corps qui n'arrive jamais ne tient pas la requête (408 après le délai).
#[tokio::test]
async fn corps_trop_lent_coupe() {
    let (app, _st, _) = with_admin(|cfg| cfg.request_timeout = Duration::from_millis(200)).await;
    let body = Body::from_stream(futures_never());
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("host", "127.0.0.1:8580")
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    req.extensions_mut().insert(ConnectInfo("10.0.0.90:5000".parse::<SocketAddr>().unwrap()));
    let t0 = std::time::Instant::now();
    let r = read(
        tokio::time::timeout(Duration::from_secs(5), app.oneshot(req)).await.expect("requête jamais coupée").unwrap(),
    )
    .await;
    assert_eq!((r.status, r.code()), (StatusCode::REQUEST_TIMEOUT, "request_timeout"));
    assert!(t0.elapsed() < Duration::from_secs(2));
}

/// Flux de corps qui n'envoie jamais rien.
struct Never;

impl futures_core::Stream for Never {
    type Item = Result<Vec<u8>, std::io::Error>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Pending
    }
}

fn futures_never() -> Never {
    Never
}
