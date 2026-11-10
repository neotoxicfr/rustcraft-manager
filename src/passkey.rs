//! Passkeys (WebAuthn, `webauthn-rs`) : ajout derrière la ré-authentification, connexion sans
//! mot de passe (en remplacement du mot de passe et du TOTP), liste et suppression.
//!
//! Pièges évités :
//! - défi gardé CÔTÉ SERVEUR (jamais renvoyé au client pour qu'il le rende), à usage unique
//!   (retiré à la première lecture, réussie ou non), 5 min ;
//! - vérification de l'utilisateur exigée (code ou biométrie, pas un simple toucher) et clé
//!   résidente exigée (connexion sans nom d'utilisateur) ;
//! - origine et identifiant de domaine fixés par `RCM_PUBLIC_URL`, jamais déduits de la requête ;
//! - compteur de signature : un compteur qui recule est refusé (clé clonée), le nouveau est
//!   enregistré.
//!
//! Les clés publiques (et compteurs) sont en base, table `passkeys` ; elles ne sont pas secrètes.

use crate::AppState;
use crate::api::{ApiJson, NeedsReauth, Reauthed, open_session};
use crate::audit::Event;
use crate::db::{now, write_tx};
use crate::error::AppError;
use crate::http::{Auth, ClientInfo};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::{Extension, Json};
use rc_manager_shared::*;
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use webauthn_rs::prelude::*;

/// Défis en attente, au plus (au-delà, les plus anciens sont oubliés).
const MAX_PENDING: usize = 1024;
/// Défis d'enregistrement en attente par session (au-delà, le plus ancien DE LA SESSION part).
const MAX_REGISTER_PER_SESSION: usize = 4;
/// Défis de connexion par réseau et fenêtre de la limite de connexion (`/api/auth/passkey/start`).
pub const LOGIN_STARTS_PER_WINDOW: u32 = 30;

enum PendingState {
    Register { user_id: i64, session: [u8; 32], name: String, state: PasskeyRegistration },
    Login { state: DiscoverableAuthentication },
}

struct Pending {
    state: PendingState,
    expires: Instant,
}

/// Défis en attente, en DEUX tables (revue I-B) : la connexion (anonyme, limitée par réseau,
/// refus quand elle est pleine) ne peut jamais évincer un enregistrement (session ouverte et
/// ré-authentifiée, au plus quelques défis par session).
pub struct Passkeys {
    webauthn: Webauthn,
    ttl: Duration,
    login: Mutex<HashMap<String, Pending>>,
    register: Mutex<HashMap<String, Pending>>,
}

fn lock(m: &Mutex<HashMap<String, Pending>>) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl NeedsReauth for PasskeyRegisterRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
    fn validate(&self) -> Result<(), AppError> {
        let n = self.name.trim();
        if n.is_empty() || n.chars().count() > PASSKEY_NAME_MAX || n.chars().any(char::is_control) {
            return Err(AppError::unprocessable(ErrorCode::InvalidName));
        }
        Ok(())
    }
}
impl NeedsReauth for PasskeyDeleteRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
}

impl Passkeys {
    /// `None` sans adresse publique (passkeys désactivées).
    pub fn new(cfg: &crate::config::Config) -> Result<Option<Passkeys>, String> {
        let Some(public) = &cfg.public_url else { return Ok(None) };
        let origin = Url::parse(&public.origin).map_err(|e| format!("RCM_PUBLIC_URL : {e}"))?;
        let webauthn = WebauthnBuilder::new(&public.rp_id, &origin)
            .and_then(|b| b.rp_name("Rustcraft Manager").timeout(cfg.passkey_challenge_ttl).build())
            .map_err(|e| format!("RCM_PUBLIC_URL : passkeys impossibles ({e})"))?;
        Ok(Some(Passkeys {
            webauthn,
            ttl: cfg.passkey_challenge_ttl,
            login: Mutex::new(HashMap::new()),
            register: Mutex::new(HashMap::new()),
        }))
    }

    /// Range un défi. Table pleine de défis valides : 503 (jamais d'éviction d'un défi d'autrui).
    fn put(&self, state: PendingState) -> Result<String, AppError> {
        let id = crate::crypto::token();
        let now = Instant::now();
        let mut m = match &state {
            PendingState::Login { .. } => lock(&self.login),
            PendingState::Register { .. } => lock(&self.register),
        };
        m.retain(|_, p| p.expires > now);
        if let PendingState::Register { session, .. } = &state {
            // Une session ne garde que ses quelques derniers défis (elle seule s'évince).
            let mut mine: Vec<(String, Instant)> = m
                .iter()
                .filter(|(_, p)| matches!(&p.state, PendingState::Register { session: s, .. } if s == session))
                .map(|(k, p)| (k.clone(), p.expires))
                .collect();
            mine.sort_by_key(|(_, e)| *e);
            while mine.len() >= MAX_REGISTER_PER_SESSION {
                m.remove(&mine.remove(0).0);
            }
        }
        if m.len() >= MAX_PENDING {
            return Err(AppError::busy());
        }
        m.insert(id.clone(), Pending { state, expires: now + self.ttl });
        Ok(id)
    }

    /// Retire le défi (usage unique, même en cas d'échec ensuite) s'il n'a pas expiré.
    fn take(&self, id: &str) -> Option<PendingState> {
        let p = lock(&self.login).remove(id).or_else(|| lock(&self.register).remove(id))?;
        (p.expires > Instant::now()).then_some(p.state)
    }

    pub fn pending_len(&self) -> usize {
        lock(&self.login).len() + lock(&self.register).len()
    }
}

fn enabled(st: &AppState) -> Result<&Passkeys, AppError> {
    st.passkeys.as_ref().ok_or_else(|| AppError::conflict(ErrorCode::PasskeysDisabled))
}

fn rejected() -> AppError {
    AppError::new(StatusCode::UNAUTHORIZED, ErrorCode::PasskeyRejected)
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<String, AppError> {
    serde_json::to_string(v).map_err(|_| AppError::internal())
}

/// Clé résidente exigée : la connexion se fait sans nom d'utilisateur (identifiant découvrable).
/// `webauthn-rs` la laisse facultative pour une passkey et n'exporte pas le type : réglée dans le
/// JSON des options.
fn require_resident_key(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(pk) = v.get_mut("publicKey").and_then(|p| p.as_object_mut()) {
        let sel = pk.entry("authenticatorSelection").or_insert_with(|| serde_json::json!({}));
        if let Some(sel) = sel.as_object_mut() {
            sel.insert("residentKey".into(), "required".into());
            sel.insert("requireResidentKey".into(), true.into());
            sel.insert("userVerification".into(), "required".into());
        }
    }
    v
}

/// Identifiant WebAuthn du compte (créé au premier ajout) : 16 octets aléatoires, jamais l'id SQL.
fn user_handle(c: &rusqlite::Connection, user_id: i64) -> Result<Uuid, AppError> {
    let cur: Option<Vec<u8>> = c.query_row("SELECT webauthn_id FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
    if let Some(b) = cur {
        return Uuid::from_slice(&b).map_err(|_| AppError::internal());
    }
    let u = Uuid::from_bytes(crate::crypto::random_bytes::<16>());
    c.execute("UPDATE users SET webauthn_id = ?1 WHERE id = ?2", params![&u.as_bytes()[..], user_id])?;
    Ok(u)
}

fn stored_passkeys(c: &rusqlite::Connection, user_id: i64) -> Result<Vec<(i64, Passkey)>, AppError> {
    let mut s = c.prepare("SELECT id, data FROM passkeys WHERE user_id = ?1")?;
    let rows: Vec<(i64, String)> =
        s.query_map([user_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|(id, d)| serde_json::from_str(&d).map(|p| (id, p)).map_err(|_| AppError::internal()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Ajout (compte connecté + ré-authentification)

pub async fn register_start(
    State(st): State<Arc<AppState>>,
    Reauthed { auth, body, .. }: Reauthed<PasskeyRegisterRequest>,
) -> Result<Json<PasskeyChallenge>, AppError> {
    let pk = enabled(&st)?;
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > PASSKEY_NAME_MAX || name.chars().any(char::is_control) {
        return Err(AppError::unprocessable(ErrorCode::InvalidName));
    }
    let uid = auth.user_id;
    let (handle, exclude) = st
        .db
        .call(move |c, _| {
            let h = user_handle(c, uid)?;
            let ex: Vec<CredentialID> =
                stored_passkeys(c, uid)?.into_iter().map(|(_, p)| p.cred_id().clone()).collect();
            Ok((h, ex))
        })
        .await?;
    let (ccr, state) = pk
        .webauthn
        .start_passkey_registration(handle, &auth.username, &auth.username, Some(exclude))
        .map_err(|_| AppError::internal())?;
    let options = to_json(&require_resident_key(serde_json::to_value(&ccr).map_err(|_| AppError::internal())?))?;
    let challenge_id = pk.put(PendingState::Register { user_id: uid, session: auth.token_hash, name, state })?;
    Ok(Json(PasskeyChallenge { challenge_id, options }))
}

pub async fn register_finish(
    State(st): State<Arc<AppState>>,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    ApiJson(req): ApiJson<PasskeyFinishRequest>,
) -> Result<Json<PasskeyInfo>, AppError> {
    let pk = enabled(&st)?;
    // Le défi appartient à CETTE session : un défi volé ne sert pas depuis une autre.
    let Some(PendingState::Register { user_id, session, name, state }) = pk.take(&req.challenge_id) else {
        return Err(rejected());
    };
    if user_id != auth.user_id || session != auth.token_hash {
        return Err(rejected());
    }
    let cred: RegisterPublicKeyCredential =
        serde_json::from_str(&req.credential).map_err(|_| AppError::bad_request())?;
    let transports: Vec<String> = cred
        .response
        .transports
        .as_ref()
        .map(|t| t.iter().filter_map(|x| serde_json::to_value(x).ok()?.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let passkey = pk.webauthn.finish_passkey_registration(&cred, &state).map_err(|e| {
        tracing::info!("passkey refusée à l'enregistrement : {e}");
        rejected()
    })?;
    let data = to_json(&passkey)?;
    let cred_id = passkey.cred_id().to_vec();
    let created = now();
    let n2 = name.clone();
    let t2 = transports.clone();
    let id = st
        .db
        .call(move |c, _| {
            let tx = write_tx(c)?;
            let dup: Option<i64> =
                tx.query_row("SELECT id FROM passkeys WHERE cred_id = ?1", [&cred_id], |r| r.get(0)).optional()?;
            if dup.is_some() {
                return Err(rejected());
            }
            tx.execute(
                "INSERT INTO passkeys (user_id, cred_id, name, data, counter, transports, created_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
                params![user_id, cred_id, n2, data, t2.join(","), created],
            )?;
            let id = tx.last_insert_rowid();
            tx.commit()?;
            Ok(id)
        })
        .await?;
    st.audit.log(Event::client("passkey_added", &info).user(Some(user_id), Some(&auth.username)).detail(&name));
    Ok(Json(PasskeyInfo { id, name, created_at: created, last_used_at: None, transports }))
}

pub async fn list(State(st): State<Arc<AppState>>, auth: Auth) -> Result<Json<Vec<PasskeyInfo>>, AppError> {
    let uid = auth.user_id;
    let v = st
        .db
        .call(move |c, _| {
            let mut s = c.prepare(
                "SELECT id, name, created_at, last_used_at, transports FROM passkeys WHERE user_id = ?1 ORDER BY id",
            )?;
            let rows = s
                .query_map([uid], |r| {
                    let t: Option<String> = r.get(4)?;
                    Ok(PasskeyInfo {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        created_at: r.get(2)?,
                        last_used_at: r.get(3)?,
                        transports: t
                            .unwrap_or_default()
                            .split(',')
                            .filter(|x| !x.is_empty())
                            .map(str::to_string)
                            .collect(),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(v))
}

pub async fn delete(
    State(st): State<Arc<AppState>>,
    Reauthed { auth, info, body }: Reauthed<PasskeyDeleteRequest>,
) -> Result<StatusCode, AppError> {
    let (uid, id) = (auth.user_id, body.id);
    let n = st
        .db
        .call(move |c, _| Ok(c.execute("DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2", params![id, uid])?))
        .await?;
    if n == 0 {
        return Err(AppError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound));
    }
    st.audit.log(Event::client("passkey_removed", &info).user(Some(uid), Some(&auth.username)));
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Connexion

pub async fn login_start(
    State(st): State<Arc<AppState>>,
    Extension(info): Extension<ClientInfo>,
) -> Result<Json<PasskeyChallenge>, AppError> {
    let pk = enabled(&st)?;
    // Défis anonymes limités par réseau (IPv6 par /64, /56, /48) : une rafale ne remplit pas la table.
    drop(st.passkey_start_limiter.reserve(info.ip, "#passkey-start").map_err(AppError::refused)?);
    let (mut rcr, state) = pk.webauthn.start_discoverable_authentication().map_err(|_| AppError::internal())?;
    // Bouton « passkey » : fenêtre du navigateur, pas le remplissage automatique (conditional).
    rcr.mediation = None;
    let options = to_json(&rcr)?;
    let challenge_id = pk.put(PendingState::Login { state })?;
    Ok(Json(PasskeyChallenge { challenge_id, options }))
}

pub async fn login_finish(
    State(st): State<Arc<AppState>>,
    Extension(info): Extension<ClientInfo>,
    ApiJson(req): ApiJson<PasskeyFinishRequest>,
) -> Result<Response, AppError> {
    let pk = enabled(&st)?;
    // Même limiteur que le mot de passe : les échecs comptent par réseau.
    let attempt = st.login_limiter.reserve(info.ip, "#passkey").map_err(AppError::refused)?;
    let fail = |why: &str| {
        st.audit.log(Event::client("passkey_login_failed", &info).detail(why));
        rejected()
    };
    let Some(PendingState::Login { state }) = pk.take(&req.challenge_id) else {
        return Err(fail("challenge"));
    };
    let cred: PublicKeyCredential = serde_json::from_str(&req.credential).map_err(|_| fail("format"))?;
    let (handle, cred_id) = pk.webauthn.identify_discoverable_authentication(&cred).map_err(|_| fail("handle"))?;
    let (handle, cred_id) = (handle.as_bytes().to_vec(), cred_id.to_vec());
    let found = st
        .db
        .call(move |c, _| {
            let uid: Option<i64> =
                c.query_row("SELECT id FROM users WHERE webauthn_id = ?1", [&handle], |r| r.get(0)).optional()?;
            let Some(uid) = uid else { return Ok(None) };
            Ok(Some((uid, stored_passkeys(c, uid)?)))
        })
        .await?;
    let Some((uid, keys)) = found else { return Err(fail("user")) };
    let Some((row_id, mut passkey)) = keys.into_iter().find(|(_, p)| p.cred_id().as_slice() == cred_id.as_slice())
    else {
        return Err(fail("credential"));
    };
    let res = pk.webauthn.finish_discoverable_authentication_v2(&cred, state, &passkey).map_err(|e| {
        tracing::info!("passkey refusée à la connexion : {e}");
        fail("verify")
    })?;
    // Compteur et état de sauvegarde mis à jour (le cœur a déjà refusé un compteur qui recule).
    passkey.update_credential(&res);
    let data = to_json(&passkey)?;
    let counter = i64::from(res.counter());
    // Atomique : deux assertions simultanées au même compteur (clé clonée) ont toutes deux vu
    // l'ancien compteur ; une seule fait avancer la ligne, l'autre est refusée (mineur 7). Un
    // authentificateur sans compteur (toujours 0) reste accepté.
    let moved = st
        .db
        .call(move |c, _| {
            Ok(c.execute(
                "UPDATE passkeys SET data = ?1, counter = ?2, last_used_at = ?3
                 WHERE id = ?4 AND (counter < ?2 OR (?2 = 0 AND counter = 0))",
                params![data, counter, now(), row_id],
            )?)
        })
        .await?;
    if moved != 1 {
        return Err(fail("counter"));
    }
    attempt.success();
    open_session(&st, &info, uid, "passkey", None).await
}
