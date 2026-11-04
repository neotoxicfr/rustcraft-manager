//! Passkeys sur le routeur en mémoire, avec un authentificateur logiciel (ES256, attestation
//! « none ») : ajout derrière la ré-authentification, connexion sans mot de passe, défi à usage
//! unique et à durée limitée, origine vérifiée, compteur, suppression.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use rc_manager::config::{Config, PublicUrl};
use rc_manager::db::Db;
use rc_manager::{AppState, new_state, router};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const PW: &str = "un mot de passe solide";
const ORIGIN: &str = "https://manager.example.org";
const RP: &str = "manager.example.org";
const PEER: &str = "10.0.0.1:5000";

struct Client {
    app: Router,
    cookie: Option<String>,
    csrf: Option<String>,
    peer: &'static str,
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
        req.extensions_mut().insert(ConnectInfo(self.peer.parse::<SocketAddr>().unwrap()));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        if let Some(sc) = res.headers().get("set-cookie").and_then(|v| v.to_str().ok()) {
            self.cookie = Some(sc.split(';').next().unwrap().to_string());
        }
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

async fn app(f: impl FnOnce(&mut Config)) -> (Router, Arc<AppState>, Client) {
    let mut cfg = Config::with_data_dir(std::env::temp_dir());
    cfg.public_url = Some(PublicUrl::parse(ORIGIN).unwrap());
    f(&mut cfg);
    let (st, token) = new_state(cfg, Db::open_memory().unwrap());
    let app = router(st.clone());
    let mut c = Client { app: app.clone(), cookie: None, csrf: None, peer: PEER };
    let (s, _) = c.post("/api/setup", json!({"token": token.unwrap(), "username": "admin", "password": PW})).await;
    assert_eq!(s, StatusCode::OK);
    (app, st, c)
}

// --- CBOR minimal (ce qu'il faut pour une attestation « none » et une clé COSE) -------------------

fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}
fn cbor_int(i: i64, out: &mut Vec<u8>) {
    if i >= 0 { cbor_head(0, i as u64, out) } else { cbor_head(1, (-1 - i) as u64, out) }
}
fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}
fn cbor_text(s: &str, out: &mut Vec<u8>) {
    cbor_head(3, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

fn sha256(b: &[u8]) -> Vec<u8> {
    rc_manager::crypto::sha256(b).to_vec()
}

/// Authentificateur logiciel : une clé ES256, un identifiant, un compteur.
struct Soft {
    key: SigningKey,
    cred_id: Vec<u8>,
    user_handle: Vec<u8>,
    counter: u32,
    /// Drapeau « utilisateur vérifié » (UV) posé dans les assertions.
    uv: bool,
}

impl Soft {
    fn new() -> Soft {
        let key = SigningKey::from_slice(&rc_manager::crypto::random_bytes::<32>()).unwrap();
        Soft {
            key,
            cred_id: rc_manager::crypto::random_bytes::<16>().to_vec(),
            user_handle: Vec::new(),
            counter: 0,
            uv: true,
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        let p = self.key.verifying_key().to_encoded_point(false);
        let mut out = Vec::new();
        cbor_head(5, 5, &mut out);
        cbor_int(1, &mut out);
        cbor_int(2, &mut out); // kty EC2
        cbor_int(3, &mut out);
        cbor_int(-7, &mut out); // ES256
        cbor_int(-1, &mut out);
        cbor_int(1, &mut out); // P-256
        cbor_int(-2, &mut out);
        cbor_bytes(p.x().unwrap(), &mut out);
        cbor_int(-3, &mut out);
        cbor_bytes(p.y().unwrap(), &mut out);
        out
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false}).to_string().into_bytes()
    }

    /// Réponse à `navigator.credentials.create` (forme de `toJSON()`).
    fn create(&mut self, options: &str, origin: &str) -> String {
        let o: Value = serde_json::from_str(options).unwrap();
        let pk = &o["publicKey"];
        assert_eq!(pk["rp"]["id"], RP);
        self.user_handle = B64.decode(pk["user"]["id"].as_str().unwrap()).unwrap();
        let cd = Self::client_data("webauthn.create", pk["challenge"].as_str().unwrap(), origin);
        let mut auth = sha256(RP.as_bytes());
        auth.push(0x01 | 0x04 | 0x40); // présence, vérification, données d'identifiant
        auth.extend(self.counter.to_be_bytes());
        auth.extend([0u8; 16]);
        auth.extend((self.cred_id.len() as u16).to_be_bytes());
        auth.extend(&self.cred_id);
        auth.extend(self.cose_key());
        let mut att = Vec::new();
        cbor_head(5, 3, &mut att);
        cbor_text("fmt", &mut att);
        cbor_text("none", &mut att);
        cbor_text("attStmt", &mut att);
        cbor_head(5, 0, &mut att);
        cbor_text("authData", &mut att);
        cbor_bytes(&auth, &mut att);
        json!({
            "id": B64.encode(&self.cred_id), "rawId": B64.encode(&self.cred_id), "type": "public-key",
            "response": {"attestationObject": B64.encode(att), "clientDataJSON": B64.encode(cd), "transports": ["internal"]},
            "clientExtensionResults": {}
        })
        .to_string()
    }

    /// Réponse à `navigator.credentials.get` avec le compteur `counter`.
    fn get(&self, options: &str, origin: &str, counter: u32) -> String {
        let o: Value = serde_json::from_str(options).unwrap();
        let pk = &o["publicKey"];
        assert_eq!(pk["userVerification"], "required", "vérification de l'utilisateur exigée");
        let cd = Self::client_data("webauthn.get", pk["challenge"].as_str().unwrap(), origin);
        let mut auth = sha256(RP.as_bytes());
        auth.push(if self.uv { 0x01 | 0x04 } else { 0x01 });
        auth.extend(counter.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend(sha256(&cd));
        let sig: DerSignature = self.key.sign(&signed);
        json!({
            "id": B64.encode(&self.cred_id), "rawId": B64.encode(&self.cred_id), "type": "public-key",
            "response": {
                "authenticatorData": B64.encode(&auth), "clientDataJSON": B64.encode(cd),
                "signature": B64.encode(sig.as_bytes()), "userHandle": B64.encode(&self.user_handle)
            },
            "clientExtensionResults": {}
        })
        .to_string()
    }
}

/// Ajoute une passkey au compte de `c` ; rend l'authentificateur.
async fn register(c: &mut Client) -> Soft {
    let (s, ch) = c.post("/api/account/passkeys/start", json!({"reauth": {"password": PW}, "name": "Téléphone"})).await;
    assert_eq!(s, StatusCode::OK, "{ch}");
    let mut soft = Soft::new();
    let cred = soft.create(ch["options"].as_str().unwrap(), ORIGIN);
    let (s, info) =
        c.post("/api/account/passkeys/finish", json!({"challenge_id": ch["challenge_id"], "credential": cred})).await;
    assert_eq!(s, StatusCode::OK, "{info}");
    assert_eq!(info["name"], "Téléphone");
    soft
}

async fn passkey_login(app: &Router, soft: &Soft, origin: &str, counter: u32) -> (StatusCode, Value, Client) {
    let mut c = Client { app: app.clone(), cookie: None, csrf: None, peer: PEER };
    let (s, ch) = c.post("/api/auth/passkey/start", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{ch}");
    let cred = soft.get(ch["options"].as_str().unwrap(), origin, counter);
    let (s, v) =
        c.post("/api/auth/passkey/finish", json!({"challenge_id": ch["challenge_id"], "credential": cred})).await;
    (s, v, c)
}

#[tokio::test]
async fn desactivees_sans_adresse_publique() {
    let (_app, st, mut c) = app(|cfg| cfg.public_url = None).await;
    assert!(st.passkeys.is_none());
    let (_, v) = c.call(Method::GET, "/api/setup", None).await;
    assert_eq!(v["passkeys"], false);
    let (s, v) = c.post("/api/auth/passkey/start", json!({})).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::CONFLICT, "passkeys_disabled"));
}

#[tokio::test]
async fn ajout_connexion_compteur_et_suppression() {
    let (app, st, mut c) = app(|_| {}).await;
    let (_, v) = c.call(Method::GET, "/api/setup", None).await;
    assert_eq!(v["passkeys"], true);

    // Ajout sans ré-authentification (session seule) : refusé.
    let (s, _) = c.post("/api/account/passkeys/start", json!({"name": "x"})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) =
        c.post("/api/account/passkeys/start", json!({"reauth": {"password": "pas le bon"}, "name": "x"})).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::UNAUTHORIZED, "invalid_credentials"));
    // Options : clé résidente et vérification de l'utilisateur exigées.
    let (_, ch) = c.post("/api/account/passkeys/start", json!({"reauth": {"password": PW}, "name": "Clé"})).await;
    let o: Value = serde_json::from_str(ch["options"].as_str().unwrap()).unwrap();
    let sel = &o["publicKey"]["authenticatorSelection"];
    assert_eq!((sel["residentKey"].as_str(), sel["userVerification"].as_str()), (Some("required"), Some("required")));

    let soft = register(&mut c).await;
    let (_, list) = c.call(Method::GET, "/api/account/passkeys", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["transports"], json!(["internal"]));

    // Connexion par passkey (sans mot de passe ni TOTP), compteur 1.
    let (s, v, mut d) = passkey_login(&app, &soft, ORIGIN, 1).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "logged_in");
    assert_eq!(d.call(Method::GET, "/api/auth/me", None).await.0, StatusCode::OK);
    // Compteur qui ne monte pas (clé clonée) : refusé.
    let (s, v, _) = passkey_login(&app, &soft, ORIGIN, 1).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
    let (s, _, _) = passkey_login(&app, &soft, ORIGIN, 5).await;
    assert_eq!(s, StatusCode::OK);
    let counter: i64 = st.db.with(|c| c.query_row("SELECT counter FROM passkeys", [], |r| r.get(0)).unwrap());
    assert_eq!(counter, 5);

    // Suppression : ré-authentification exigée, puis plus de connexion possible.
    let id = list[0]["id"].as_i64().unwrap();
    let (s, _) = c.post("/api/account/passkeys/delete", json!({"id": id})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = c.post("/api/account/passkeys/delete", json!({"reauth": {"password": PW}, "id": id})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, v, _) = passkey_login(&app, &soft, ORIGIN, 9).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
    st.audit.flush().await;
    let actions: Vec<String> = st.db.with(|c| {
        c.prepare("SELECT action FROM audit_log")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    });
    for a in ["passkey_added", "passkey_removed", "passkey_login_failed"] {
        assert!(actions.contains(&a.to_string()), "{a}");
    }
}

#[tokio::test]
async fn defi_a_usage_unique_et_origine_verifiee() {
    let (app, _st, mut c) = app(|_| {}).await;
    let soft = register(&mut c).await;
    // Défi rejoué : la même réponse, deux fois.
    let mut d = Client { app: app.clone(), cookie: None, csrf: None, peer: PEER };
    let (_, ch) = d.post("/api/auth/passkey/start", json!({})).await;
    let cred = soft.get(ch["options"].as_str().unwrap(), ORIGIN, 1);
    let body = json!({"challenge_id": ch["challenge_id"], "credential": cred});
    assert_eq!(d.post("/api/auth/passkey/finish", body.clone()).await.0, StatusCode::OK);
    let (s, v) = d.post("/api/auth/passkey/finish", body).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
    // Même défi, nouvelle signature valide (compteur plus haut) : refusé aussi, le défi a servi.
    let cred = soft.get(ch["options"].as_str().unwrap(), ORIGIN, 2);
    let (s, v) =
        d.post("/api/auth/passkey/finish", json!({"challenge_id": ch["challenge_id"], "credential": cred})).await;
    assert_eq!(
        (s, v["code"].as_str().unwrap_or("")),
        (StatusCode::UNAUTHORIZED, "passkey_rejected"),
        "défi à usage unique"
    );
    // Mauvaise origine (page d'un autre site qui relaie le défi) : refusée.
    let (s, v, _) = passkey_login(&app, &soft, "https://evil.example.org", 2).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
    // Défi d'enregistrement d'une autre session : refusé.
    let (_, ch) = c.post("/api/account/passkeys/start", json!({"reauth": {"password": PW}, "name": "B"})).await;
    let mut other = Client { app: app.clone(), cookie: None, csrf: None, peer: PEER };
    other.post("/api/auth/login", json!({"username": "admin", "password": PW})).await;
    let cred = Soft::new().create(ch["options"].as_str().unwrap(), ORIGIN);
    let (s, v) = other
        .post("/api/account/passkeys/finish", json!({"challenge_id": ch["challenge_id"], "credential": cred}))
        .await;
    assert_eq!((s, v["code"].as_str().unwrap_or("")), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
}

#[tokio::test]
async fn defi_expire() {
    let (app, st, mut c) = app(|cfg| cfg.passkey_challenge_ttl = Duration::from_millis(100)).await;
    let soft = register(&mut c).await;
    let mut d = Client { app: app.clone(), cookie: None, csrf: None, peer: PEER };
    let (_, ch) = d.post("/api/auth/passkey/start", json!({})).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let cred = soft.get(ch["options"].as_str().unwrap(), ORIGIN, 1);
    let (s, v) =
        d.post("/api/auth/passkey/finish", json!({"challenge_id": ch["challenge_id"], "credential": cred})).await;
    assert_eq!((s, v["code"].as_str().unwrap_or("")), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
    let _ = st;
}

/// Une rafale de défis (anonymes) ne fait pas grossir la table sans fin.
#[tokio::test]
async fn defis_bornes() {
    let (app, st, _) = app(|_| {}).await;
    let mut d = Client { app: app.clone(), cookie: None, csrf: None, peer: PEER };
    for _ in 0..1500 {
        d.post("/api/auth/passkey/start", json!({})).await;
    }
    assert!(st.passkeys.as_ref().unwrap().pending_len() <= 1024);
}

/// Revue I-B : une rafale anonyme (1 500 réseaux) n'évince pas le défi d'enregistrement d'un
/// utilisateur connecté : la table de connexion pleine refuse (503) au lieu d'évincer, et elle
/// est séparée. Un même réseau est limité (429).
#[tokio::test]
async fn defi_d_enregistrement_survit_a_une_rafale() {
    let (app, _st, mut c) = app(|_| {}).await;
    let (_, ch) = c.post("/api/account/passkeys/start", json!({"reauth": {"password": PW}, "name": "Clé"})).await;
    let mut full = 0;
    for i in 0..1500u32 {
        let peer: &'static str = Box::leak(format!("10.{}.{}.1:5000", 1 + i / 250, i % 250).into_boxed_str());
        let mut d = Client { app: app.clone(), cookie: None, csrf: None, peer };
        let (s, _) = d.post("/api/auth/passkey/start", json!({})).await;
        if s == StatusCode::SERVICE_UNAVAILABLE {
            full += 1;
        }
    }
    assert!(full > 0, "table de connexion jamais pleine : la rafale n'a rien éprouvé");
    let cred = Soft::new().create(ch["options"].as_str().unwrap(), ORIGIN);
    let (s, v) =
        c.post("/api/account/passkeys/finish", json!({"challenge_id": ch["challenge_id"], "credential": cred})).await;
    assert_eq!(s, StatusCode::OK, "défi légitime évincé : {v}");
    // Un même réseau : 30 défis par fenêtre, puis 429.
    let mut e = Client { app: app.clone(), cookie: None, csrf: None, peer: "192.0.2.9:5000" };
    let mut codes = Vec::new();
    for _ in 0..rc_manager::passkey::LOGIN_STARTS_PER_WINDOW + 1 {
        codes.push(e.post("/api/auth/passkey/start", json!({})).await.0);
    }
    assert_eq!(*codes.last().unwrap(), StatusCode::TOO_MANY_REQUESTS, "{codes:?}");
}

/// Mineur 11 : une assertion sans le drapeau « utilisateur vérifié » est refusée côté serveur.
#[tokio::test]
async fn verification_utilisateur_exigee_cote_serveur() {
    let (app, _st, mut c) = app(|_| {}).await;
    let mut soft = register(&mut c).await;
    soft.uv = false;
    let (s, v, _) = passkey_login(&app, &soft, ORIGIN, 1).await;
    assert_eq!((s, v["code"].as_str().unwrap()), (StatusCode::UNAUTHORIZED, "passkey_rejected"));
    soft.uv = true;
    assert_eq!(passkey_login(&app, &soft, ORIGIN, 2).await.0, StatusCode::OK);
}

/// Mineur 7 : dix assertions simultanées au MÊME compteur (clé clonée) : une seule passe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compteur_atomique_sous_concurrence() {
    let (app, _st, mut c) = app(|_| {}).await;
    let soft = std::sync::Arc::new(register(&mut c).await);
    let mut bodies = Vec::new();
    for i in 0..10u32 {
        let peer: &'static str = Box::leak(format!("10.7.{i}.1:5000").into_boxed_str());
        let mut d = Client { app: app.clone(), cookie: None, csrf: None, peer };
        let (_, ch) = d.post("/api/auth/passkey/start", json!({})).await;
        let cred = soft.get(ch["options"].as_str().unwrap(), ORIGIN, 3);
        bodies.push((d, json!({"challenge_id": ch["challenge_id"], "credential": cred})));
    }
    let tasks: Vec<_> = bodies
        .into_iter()
        .map(|(mut d, b)| tokio::spawn(async move { d.post("/api/auth/passkey/finish", b).await.0 }))
        .collect();
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 1, "{ok} connexions avec le même compteur");
}
