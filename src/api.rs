//! Routes de l'API (`/api/...`) de la phase 1 : premier compte, connexion, double
//! authentification, session, réglages du compte, WebSocket.
//!
//! Chaque action sensible écrit une ligne du journal d'audit (jamais de secret dedans). Toute
//! action sensible du compte passe par [`Reauthed`] (mot de passe, + TOTP s'il est actif).

use crate::AppState;
use crate::audit::Event;
use crate::crypto::{Keys, aad, base32, random_bytes, sha256, token};
use crate::db::{now, write_tx};
use crate::error::AppError;
use crate::http::{Auth, ClientInfo, lookup_session, request_token, session_cookie};
use crate::ratelimit::account_key;
use crate::totp;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequest, FromRequestParts, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rc_manager_shared::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::{Duration, Instant};

type St = State<Arc<AppState>>;

/// Durée de la session provisoire entre le mot de passe et le code TOTP.
pub const PENDING_TOTP_SECS: i64 = 300;
/// Codes faux tolérés par session provisoire : au-delà, elle est brûlée (retour au mot de passe).
pub const PENDING_TOTP_TRIES: i64 = 5;
/// Sessions ouvertes en même temps par compte (au-delà, les plus anciennes sont fermées).
pub const MAX_SESSIONS_PER_USER: usize = 10;
/// Nombre de codes de secours générés.
pub const RECOVERY_CODES: usize = 10;
/// Taille maximale d'une trame WebSocket reçue.
pub const WS_MAX_FRAME: usize = 64 * 1024;
/// Ping du WebSocket et revérification de la session.
pub const WS_PING: Duration = Duration::from_secs(30);

/// Corps JSON ; toute erreur de forme rend `bad_request` (pas de message interne).
pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = AppError;
    async fn from_request(req: Request, state: &S) -> Result<Self, AppError> {
        Json::<T>::from_request(req, state).await.map(|Json(v)| ApiJson(v)).map_err(|_| AppError::bad_request())
    }
}

/// La requête vient-elle d'un client local ou d'une session ouverte ? (Version affichée.)
async fn trusted_viewer(st: &AppState, info: &ClientInfo, headers: &HeaderMap) -> bool {
    if info.is_local() {
        return true;
    }
    match request_token(st, info, headers) {
        Some(t) => matches!(lookup_session(st, &t).await, Ok(Some(_))),
        None => false,
    }
}

pub async fn health(State(st): St, Extension(info): Extension<ClientInfo>, headers: HeaderMap) -> Json<Health> {
    let version = trusted_viewer(&st, &info, &headers).await.then(|| env!("CARGO_PKG_VERSION").to_string());
    Json(Health { ok: true, version })
}

/// `GET /version` : empreinte de l'interface pour tous ; version et commit pour un client local
/// ou connecté (vérification du commit servi après un déploiement).
pub async fn version(State(st): St, Extension(info): Extension<ClientInfo>, headers: HeaderMap) -> Response {
    let full = trusted_viewer(&st, &info, &headers).await;
    let body = VersionInfo {
        ui: crate::assets::UI_VERSION.to_string(),
        version: full.then(|| env!("CARGO_PKG_VERSION").to_string()),
        commit: full.then(|| crate::COMMIT.to_string()),
    };
    let mut res = Json(body).into_response();
    res.headers_mut().insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    res
}

// ---------------------------------------------------------------------------------------------
// Sessions

/// Ouvre une session (jeton neuf à chaque fois : pas de fixation de session). Purge au passage
/// les sessions expirées.
fn create_session(
    c: &Connection,
    st: &AppState,
    user_id: i64,
    pending: bool,
) -> rusqlite::Result<(String, String, i64)> {
    let now = now();
    c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
    let tok = token();
    let csrf = token();
    let ttl = if pending { PENDING_TOTP_SECS } else { st.config.session_max.as_secs() as i64 };
    c.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf, pending_totp, created_at, last_seen, expires_at, seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, (SELECT coalesce(max(seq), 0) + 1 FROM sessions))",
        params![&sha256(tok.as_bytes())[..], user_id, csrf, pending, now, now + ttl],
    )?;
    // Sessions par compte bornées (complètes et provisoires séparément) : les plus anciennes
    // (ordre de création) partent, la nouvelle reste (revue I-C).
    c.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND pending_totp = ?2 AND token_hash != ?3
         AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id = ?1 AND pending_totp = ?2
                                AND token_hash != ?3 ORDER BY seq DESC LIMIT ?4)",
        params![user_id, pending, &sha256(tok.as_bytes())[..], (MAX_SESSIONS_PER_USER - 1) as i64],
    )?;
    Ok((tok, csrf, ttl))
}

fn load_me(c: &Connection, user_id: i64, csrf: String) -> rusqlite::Result<Me> {
    let (username, is_admin, totp_enabled, theme): (String, bool, bool, Option<String>) = c.query_row(
        "SELECT username, is_admin, totp_secret_enc IS NOT NULL, theme FROM users WHERE id = ?1",
        [user_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let (left, legacy): (u32, u32) = c.query_row(
        "SELECT count(*), coalesce(sum(scheme = 0), 0) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
        [user_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Me {
        username,
        is_admin,
        totp_enabled,
        recovery_codes_left: left,
        recovery_codes_legacy: legacy,
        csrf_token: csrf,
        theme: theme.and_then(|t| serde_json::from_str::<ThemeSettings>(&t).ok()).filter(ThemeSettings::valid),
    })
}

fn with_cookie(cookie: axum::http::HeaderValue, body: impl IntoResponse) -> Response {
    let mut res = body.into_response();
    res.headers_mut().append(header::SET_COOKIE, cookie);
    res
}

/// Session complète ouverte, réponse `LoggedIn` avec le cookie.
pub(crate) async fn open_session(
    st: &Arc<AppState>,
    info: &ClientInfo,
    user_id: i64,
    method: &'static str,
    drop_pending: Option<[u8; 32]>,
) -> Result<Response, AppError> {
    let st2 = st.clone();
    let (tok, me, ttl) = st
        .db
        .call(move |c, _| {
            let tx = write_tx(c)?;
            if let Some(h) = drop_pending {
                tx.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h[..]])?;
            }
            let (tok, csrf, ttl) = create_session(&tx, &st2, user_id, false)?;
            let me = load_me(&tx, user_id, csrf)?;
            tx.commit()?;
            Ok((tok, me, ttl))
        })
        .await?;
    st.audit.log(Event::client("login", info).user(Some(user_id), Some(&me.username)).detail(method));
    Ok(with_cookie(session_cookie(st, info, &tok, ttl as u64), Json(LoginResponse::LoggedIn { me })))
}

/// Nom tenté gardé dans l'audit seulement s'il a la forme d'un nom (sinon ce peut être un mot de
/// passe tapé dans le mauvais champ, ou n'importe quoi).
fn audit_name(name: &str) -> Option<&str> {
    username_valid(name).then_some(name)
}

/// Mot de passe démesuré : remplacé par une chaîne vide (refusé sans hacher de mégaoctets, mais
/// après la même attente qu'un échec).
fn bounded_password(pw: String) -> String {
    if pw.chars().count() <= PASSWORD_MAX { pw } else { String::new() }
}

/// Réservation refusée : 429 ; le plafond dur d'un compte (second facteur, ré-authentification)
/// est audité à part (`second_factor_locked`).
fn refused(st: &AppState, info: &ClientInfo, account: &str, r: crate::ratelimit::Refusal) -> AppError {
    if matches!(r, crate::ratelimit::Refusal::Locked(_)) {
        st.audit.log(Event::client("second_factor_locked", info).user(None, audit_name(account)));
    }
    AppError::refused(r)
}

// ---------------------------------------------------------------------------------------------
// Premier compte

pub async fn setup_status(State(st): St) -> Result<Json<SetupStatus>, AppError> {
    let n: i64 = st.db.call(|c, _| Ok(c.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?)).await?;
    Ok(Json(SetupStatus { needed: n == 0, passkeys: st.passkeys.is_some() }))
}

pub async fn setup(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    ApiJson(req): ApiJson<SetupRequest>,
) -> Result<Response, AppError> {
    let attempt = st.login_limiter.reserve(info.ip, "#setup").map_err(AppError::refused)?;
    // Verrou tenu pendant toute la création : deux assistants simultanés ne créent pas deux
    // administrateurs, et le jeton n'est consommé qu'une fois le compte écrit.
    let mut guard = st.setup_token.lock().await;
    let Some(expected) = *guard else {
        attempt.cancel();
        let n: i64 = st.db.call(|c, _| Ok(c.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?)).await?;
        return Err(if n > 0 {
            AppError::conflict(ErrorCode::SetupNotNeeded)
        } else {
            AppError::new(StatusCode::FORBIDDEN, ErrorCode::InvalidSetupToken)
        });
    };
    if !crate::crypto::ct_eq(&sha256(req.token.trim().as_bytes()), &expected) {
        st.audit.log(Event::client("setup_bad_token", &info));
        return Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::InvalidSetupToken));
    }
    // Jeton bon : la tentative n'est pas un échec, même si la saisie est invalide (une faute de
    // frappe ne brûle pas le jeton).
    attempt.success();
    if !username_valid(&req.username) {
        return Err(AppError::unprocessable(ErrorCode::InvalidUsername));
    }
    if !password_valid(&req.password) {
        return Err(AppError::unprocessable(ErrorCode::WeakPassword));
    }
    let phc = st.hasher.hash(req.password).await?;
    let username = req.username.clone();
    let uid = st
        .db
        .call(move |c, _| {
            let tx = write_tx(c)?;
            let n: i64 = tx.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
            if n > 0 {
                return Err(AppError::conflict(ErrorCode::SetupNotNeeded));
            }
            tx.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?1, ?2, 1, ?3)",
                params![username, phc, now()],
            )?;
            let uid = tx.last_insert_rowid();
            tx.commit()?;
            Ok(uid)
        })
        .await?;
    *guard = None;
    drop(guard);
    st.audit.log(Event::client("setup_admin_created", &info).user(Some(uid), Some(&req.username)));
    tracing::info!("premier compte administrateur créé ; jeton de création consommé");
    open_session(&st, &info, uid, "setup", None).await
}

// ---------------------------------------------------------------------------------------------
// Connexion

pub async fn login(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    ApiJson(req): ApiJson<LoginRequest>,
) -> Result<Response, AppError> {
    // Place réservée (comptée comme un échec) AVANT tout travail : des requêtes simultanées ne
    // passent pas toutes (revue B1).
    let attempt = st.login_limiter.reserve(info.ip, &account_key(&req.username)).map_err(AppError::refused)?;
    attempt.wait().await;
    let uname = req.username.clone();
    let user = if username_valid(&uname) {
        st.db
            .call(move |c, _| {
                Ok(c.query_row(
                    "SELECT id, password_hash, totp_secret_enc IS NOT NULL FROM users WHERE username = ?1",
                    [&uname],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, bool>(2)?)),
                )
                .optional()?)
            })
            .await?
    } else {
        None
    };
    let ok = match st.hasher.verify(bounded_password(req.password), user.as_ref().map(|u| u.1.clone())).await {
        Ok(ok) => ok,
        Err(e) => {
            attempt.cancel();
            return Err(e);
        }
    };
    let Some((uid, _, totp_on)) = user.filter(|_| ok) else {
        st.audit.log(Event::client("login_failed", &info).user(None, audit_name(&req.username)));
        return Err(AppError::invalid_credentials());
    };
    attempt.success();
    if !totp_on {
        return open_session(&st, &info, uid, "password", None).await;
    }
    let st2 = st.clone();
    let (tok, ttl) = st
        .db
        .call(move |c, _| {
            let (tok, _, ttl) = create_session(c, &st2, uid, true)?;
            Ok((tok, ttl))
        })
        .await?;
    st.audit.log(Event::client("login_password_ok_totp_pending", &info).user(Some(uid), None));
    Ok(with_cookie(session_cookie(&st, &info, &tok, ttl as u64), Json(LoginResponse::TotpRequired)))
}

/// Alphabet des codes de secours : 32 symboles sans les caractères ambigus à la recopie (ni 0/O,
/// ni 1/I). 32 divise 256 : `octet % 32` est uniforme.
const RECOVERY_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
/// 12 symboles = 60 bits, affichés `XXXX-XXXX-XXXX`.
pub const RECOVERY_LEN: usize = 12;

fn new_recovery_code() -> String {
    let raw = random_bytes::<RECOVERY_LEN>();
    let mut s = String::with_capacity(RECOVERY_LEN + 2);
    for (i, b) in raw.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(RECOVERY_ALPHABET[(b % 32) as usize] as char);
    }
    s
}

/// Code de secours : majuscules, tirets et espaces ignorés ; saisie démesurée = vide.
fn normalize_recovery(code: &str) -> String {
    if code.len() > 64 {
        return String::new();
    }
    code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// Empreinte historique (schéma 0, base de la version 1) : SHA-256 salée par le compte. Les codes
/// créés depuis sont en HMAC (schéma 1, clé dérivée de la clé de chiffrement).
fn legacy_recovery_hash(user_id: i64, normalized: &str) -> [u8; 32] {
    sha256(format!("rcm-recovery:{user_id}:{normalized}").as_bytes())
}

/// Secret TOTP actif, déchiffré (échec fermé : erreur interne, jamais de repli).
fn totp_secret(c: &Connection, keys: &Keys, user_id: i64) -> Result<Option<Vec<u8>>, AppError> {
    let enc: Option<String> =
        c.query_row("SELECT totp_secret_enc FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
    enc.map(|e| {
        keys.decrypt(&aad("users", "totp_secret", user_id), &e).map_err(|_| {
            tracing::error!("secret TOTP du compte {user_id} indéchiffrable");
            AppError::internal()
        })
    })
    .transpose()
}

/// Vérifie un code TOTP (pas strictement plus récent que le dernier accepté, enregistré de façon
/// atomique) ou un code de secours (consommé). Rend la méthode reconnue.
fn check_second_factor(
    c: &Connection,
    keys: &Keys,
    user_id: i64,
    input: &str,
) -> Result<Option<&'static str>, AppError> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() == totp::DIGITS as usize && digits.bytes().all(|b| b.is_ascii_digit()) {
        let Some(secret) = totp_secret(c, keys, user_id)? else {
            return Ok(None);
        };
        let last: Option<i64> =
            c.query_row("SELECT totp_last_step FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
        let now_step = totp::step_at(now() as u64);
        let Some(step) = totp::verify(&secret, &digits, now_step, last.map(|l| l as u64)) else {
            return Ok(None);
        };
        // Le pas n'est accepté que s'il avance encore au moment d'écrire (deux requêtes
        // simultanées avec le même code : une seule passe).
        let n = c.execute(
            "UPDATE users SET totp_last_step = ?1 WHERE id = ?2 AND (totp_last_step IS NULL OR totp_last_step < ?1)",
            params![step as i64, user_id],
        )?;
        return Ok((n == 1).then_some("totp"));
    }
    let norm = normalize_recovery(input);
    if norm.len() != RECOVERY_LEN {
        return Ok(None);
    }
    let n = c.execute(
        "UPDATE recovery_codes SET used_at = ?1 WHERE user_id = ?2 AND used_at IS NULL
         AND ((scheme = 1 AND code_hash = ?3) OR (scheme = 0 AND code_hash = ?4))",
        params![now(), user_id, &keys.recovery_mac(user_id, &norm)[..], &legacy_recovery_hash(user_id, &norm)[..]],
    )?;
    Ok((n == 1).then_some("recovery_code"))
}

/// Issue d'un code saisi sur une session provisoire.
enum PendingCheck {
    /// Session inconnue, expirée ou brûlée.
    Gone,
    Bad,
    Ok(i64, &'static str),
}

pub async fn login_totp(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<TotpLoginRequest>,
) -> Result<Response, AppError> {
    let tok = request_token(&st, &info, &headers).ok_or_else(AppError::unauthorized)?;
    let h = sha256(tok.as_bytes());
    let name: Option<String> = st
        .db
        .call(move |c, _| {
            Ok(c.query_row(
                "SELECT u.username FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1 AND s.pending_totp = 1 AND s.expires_at > ?2",
                params![&h[..], now()],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await?;
    let name = name.ok_or_else(AppError::unauthorized)?;
    // Réservée avant la vérification, comme le mot de passe (codes de secours compris).
    let attempt =
        st.second_factor_limiter.reserve(info.ip, &account_key(&name)).map_err(|r| refused(&st, &info, &name, r))?;
    attempt.wait().await;
    let code = req.code;
    let r = st
        .db
        .call(move |c, keys| {
            // Essai compté AVANT la vérification et de façon atomique : N requêtes simultanées sur
            // la même session provisoire n'en font pas plus de PENDING_TOTP_TRIES.
            let n = c.execute(
                "UPDATE sessions SET totp_failures = totp_failures + 1
                 WHERE token_hash = ?1 AND pending_totp = 1 AND expires_at > ?2 AND totp_failures < ?3",
                params![&h[..], now(), PENDING_TOTP_TRIES],
            )?;
            if n == 0 {
                c.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h[..]])?;
                return Ok(PendingCheck::Gone);
            }
            let (uid, tries): (i64, i64) = c.query_row(
                "SELECT user_id, totp_failures FROM sessions
                 WHERE token_hash = ?1",
                [&h[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            match check_second_factor(c, keys, uid, &code)? {
                Some(m) => Ok(PendingCheck::Ok(uid, m)),
                None => {
                    if tries >= PENDING_TOTP_TRIES {
                        // Dernier essai raté : la session provisoire est brûlée.
                        c.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h[..]])?;
                    }
                    Ok(PendingCheck::Bad)
                }
            }
        })
        .await?;
    match r {
        PendingCheck::Gone => {
            st.audit.log(Event::client("login_totp_failed", &info).user(None, Some(&name)));
            Err(AppError::unauthorized())
        }
        PendingCheck::Bad => {
            st.audit.log(Event::client("login_totp_failed", &info).user(None, Some(&name)));
            Err(AppError::invalid_totp())
        }
        PendingCheck::Ok(uid, method) => {
            attempt.success();
            open_session(&st, &info, uid, method, Some(h)).await
        }
    }
}

pub async fn logout(State(st): St, Extension(info): Extension<ClientInfo>, auth: Auth) -> Result<Response, AppError> {
    let h = auth.token_hash;
    st.db
        .call(move |c, _| {
            c.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h[..]])?;
            Ok(())
        })
        .await?;
    st.audit.log(Event::client("logout", &info).user(Some(auth.user_id), Some(&auth.username)));
    Ok(with_cookie(session_cookie(&st, &info, "", 0), StatusCode::NO_CONTENT))
}

pub async fn me(State(st): St, auth: Auth) -> Result<Json<Me>, AppError> {
    let me = st.db.call(move |c, _| Ok(load_me(c, auth.user_id, auth.csrf)?)).await?;
    Ok(Json(me))
}

// ---------------------------------------------------------------------------------------------
// Ré-authentification

/// Requête d'une action sensible : porte une [`Reauth`].
pub trait NeedsReauth {
    fn reauth(&self) -> &Reauth;
    /// Contrôle du reste du corps AVANT la ré-authentification : une saisie invalide ne doit
    /// pas consommer un code TOTP ou de secours pour rien (mineur 1 de la seconde revue).
    fn validate(&self) -> Result<(), AppError> {
        Ok(())
    }
}

impl NeedsReauth for PasswordChangeRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
    fn validate(&self) -> Result<(), AppError> {
        if password_valid(&self.new) { Ok(()) } else { Err(AppError::unprocessable(ErrorCode::WeakPassword)) }
    }
}
impl NeedsReauth for TotpEnableRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
}
impl NeedsReauth for TotpDisableRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
}
impl NeedsReauth for RecoveryRegenerateRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
}

/// Nouveaux codes de secours (HMAC) à la place des anciens, derrière la ré-authentification
/// (mot de passe + code). Proposé par l'interface quand il reste des codes au format de la
/// version 1 (SHA-256 salée, mineur 9 de la seconde revue).
pub async fn recovery_regenerate(
    State(st): St,
    Reauthed { auth, info, .. }: Reauthed<RecoveryRegenerateRequest>,
) -> Result<Json<TotpEnableResponse>, AppError> {
    let uid = auth.user_id;
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    let c2 = codes.clone();
    let on = st
        .db
        .call(move |c, keys| {
            let tx = write_tx(c)?;
            let on: bool =
                tx.query_row("SELECT totp_secret_enc IS NOT NULL FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
            if on {
                tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [uid])?;
                for code in &c2 {
                    tx.execute(
                        "INSERT INTO recovery_codes (user_id, code_hash, scheme) VALUES (?1, ?2, 1)",
                        params![uid, &keys.recovery_mac(uid, &normalize_recovery(code))[..]],
                    )?;
                }
            }
            tx.commit()?;
            Ok(on)
        })
        .await?;
    if !on {
        return Err(AppError::conflict(ErrorCode::TotpNotEnabled));
    }
    st.audit.log(Event::client("recovery_codes_regenerated", &info).user(Some(uid), Some(&auth.username)));
    Ok(Json(TotpEnableResponse { recovery_codes: codes }))
}

/// Extracteur unique des actions sensibles : session ouverte + CSRF ([`Auth`]), corps JSON, puis
/// mot de passe actuel et, si la double authentification est active, code TOTP ou de secours.
/// Son propre limiteur (réservé avant Argon2), échecs audités `reauth_failed`. Une session volée
/// seule ne suffit donc plus à changer le mot de passe ni le TOTP (revue I1).
pub struct Reauthed<T> {
    pub auth: Auth,
    pub info: ClientInfo,
    pub body: T,
}

impl<T: DeserializeOwned + NeedsReauth + Send> FromRequest<Arc<AppState>> for Reauthed<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, st: &Arc<AppState>) -> Result<Self, AppError> {
        reauthed_checked(req, st, |_| Ok(())).await
    }
}

/// Comme l'extracteur [`Reauthed`], avec un contrôle de plus sur le corps (qui dépend de l'état,
/// par exemple le nom du serveur à recopier) fait AVANT la ré-authentification.
pub async fn reauthed_checked<T: DeserializeOwned + NeedsReauth + Send>(
    req: Request,
    st: &Arc<AppState>,
    check: impl FnOnce(&T) -> Result<(), AppError>,
) -> Result<Reauthed<T>, AppError> {
    let (mut parts, body) = req.into_parts();
    let auth = Auth::from_request_parts(&mut parts, st).await?;
    let info = parts.extensions.get::<ClientInfo>().cloned().ok_or_else(AppError::internal)?;
    let ApiJson(body) = ApiJson::<T>::from_request(Request::from_parts(parts, body), st).await?;
    body.validate()?;
    check(&body)?;
    verify_reauth(st, &info, &auth, body.reauth()).await?;
    Ok(Reauthed { auth, info, body })
}

async fn verify_reauth(st: &Arc<AppState>, info: &ClientInfo, auth: &Auth, r: &Reauth) -> Result<(), AppError> {
    let attempt = st
        .reauth_limiter
        .reserve(info.ip, &account_key(&auth.username))
        .map_err(|r| refused(st, info, &auth.username, r))?;
    attempt.wait().await;
    let uid = auth.user_id;
    let (phc, totp_on): (String, bool) = st
        .db
        .call(move |c, _| {
            Ok(c.query_row("SELECT password_hash, totp_secret_enc IS NOT NULL FROM users WHERE id = ?1", [uid], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?)
        })
        .await?;
    let ok = match st.hasher.verify(bounded_password(r.password.clone()), Some(phc)).await {
        Ok(ok) => ok,
        Err(e) => {
            attempt.cancel();
            return Err(e);
        }
    };
    let fail = |what: &str| {
        st.audit.log(Event::client("reauth_failed", info).user(Some(uid), Some(&auth.username)).detail(what));
    };
    if !ok {
        fail("password");
        return Err(AppError::invalid_credentials());
    }
    if totp_on {
        let code = r.code.clone().unwrap_or_default();
        let m = st.db.call(move |c, keys| check_second_factor(c, keys, uid, &code)).await?;
        if m.is_none() {
            fail("totp");
            return Err(AppError::invalid_totp());
        }
    }
    attempt.success();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Compte

pub async fn change_password(
    State(st): St,
    Reauthed { auth, info, body }: Reauthed<PasswordChangeRequest>,
) -> Result<StatusCode, AppError> {
    if !password_valid(&body.new) {
        return Err(AppError::unprocessable(ErrorCode::WeakPassword));
    }
    let new_phc = st.hasher.hash(body.new).await?;
    let uid = auth.user_id;
    let h = auth.token_hash;
    st.db
        .call(move |c, _| {
            let tx = write_tx(c)?;
            tx.execute("UPDATE users SET password_hash = ?1 WHERE id = ?2", params![new_phc, uid])?;
            // Les autres sessions de ce compte sont fermées, la courante reste.
            tx.execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", params![uid, &h[..]])?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    st.audit.log(Event::client("password_changed", &info).user(Some(uid), Some(&auth.username)));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn totp_setup(State(st): St, auth: Auth) -> Result<Json<TotpSetupResponse>, AppError> {
    let secret = random_bytes::<{ totp::SECRET_LEN }>();
    let uid = auth.user_id;
    let enabled = st
        .db
        .call(move |c, keys| {
            let enabled: bool =
                c.query_row("SELECT totp_secret_enc IS NOT NULL FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
            if !enabled {
                let enc = keys.encrypt(&aad("users", "totp_pending", uid), &secret);
                c.execute("UPDATE users SET totp_pending_enc = ?1 WHERE id = ?2", params![enc, uid])?;
            }
            Ok(enabled)
        })
        .await?;
    if enabled {
        return Err(AppError::conflict(ErrorCode::TotpAlreadyEnabled));
    }
    let b32 = base32(&secret);
    let uri = totp::otpauth_uri(&b32, &auth.username);
    let qr_svg = totp::qr_svg(&uri);
    Ok(Json(TotpSetupResponse { secret: b32, otpauth_uri: uri, qr_svg }))
}

pub async fn totp_enable(
    State(st): St,
    Reauthed { auth, info, body }: Reauthed<TotpEnableRequest>,
) -> Result<Json<TotpEnableResponse>, AppError> {
    let attempt = st
        .second_factor_limiter
        .reserve(info.ip, &account_key(&auth.username))
        .map_err(|r| refused(&st, &info, &auth.username, r))?;
    let uid = auth.user_id;
    let h = auth.token_hash;
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    let codes2 = codes.clone();
    let res = st
        .db
        .call(move |c, keys| {
            let (secret, pending): (Option<String>, Option<String>) =
                c.query_row("SELECT totp_secret_enc, totp_pending_enc FROM users WHERE id = ?1", [uid], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            if secret.is_some() {
                return Err(AppError::conflict(ErrorCode::TotpAlreadyEnabled));
            }
            let Some(pending) = pending else {
                return Err(AppError::conflict(ErrorCode::TotpSetupMissing));
            };
            let pending =
                keys.decrypt(&aad("users", "totp_pending", uid), &pending).map_err(|_| AppError::internal())?;
            let Some(step) = totp::verify(&pending, &body.code, totp::step_at(now() as u64), None) else {
                return Ok(false);
            };
            let tx = write_tx(c)?;
            // Le pas du code d'activation est enregistré : il ne resservira pas à la connexion.
            tx.execute(
                "UPDATE users SET totp_secret_enc = ?1, totp_pending_enc = NULL, totp_last_step = ?2 WHERE id = ?3",
                params![keys.encrypt(&aad("users", "totp_secret", uid), &pending), step as i64, uid],
            )?;
            tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [uid])?;
            for code in &codes2 {
                tx.execute(
                    "INSERT INTO recovery_codes (user_id, code_hash, scheme) VALUES (?1, ?2, 1)",
                    params![uid, &keys.recovery_mac(uid, &normalize_recovery(code))[..]],
                )?;
            }
            // Les autres sessions sont fermées : une session volée ne survit pas à l'activation.
            tx.execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", params![uid, &h[..]])?;
            tx.commit()?;
            Ok(true)
        })
        .await?;
    if !res {
        return Err(AppError::invalid_totp());
    }
    attempt.success();
    st.audit.log(Event::client("totp_enabled", &info).user(Some(uid), Some(&auth.username)));
    Ok(Json(TotpEnableResponse { recovery_codes: codes }))
}

pub async fn totp_disable(
    State(st): St,
    Reauthed { auth, info, .. }: Reauthed<TotpDisableRequest>,
) -> Result<StatusCode, AppError> {
    // Mot de passe ET code déjà vérifiés par `Reauthed` (le TOTP est actif : code exigé).
    let uid = auth.user_id;
    let h = auth.token_hash;
    let was_on = st
        .db
        .call(move |c, _| {
            let tx = write_tx(c)?;
            let n = tx.execute(
                "UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_last_step = NULL
                 WHERE id = ?1 AND totp_secret_enc IS NOT NULL",
                [uid],
            )?;
            tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [uid])?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", params![uid, &h[..]])?;
            tx.commit()?;
            Ok(n == 1)
        })
        .await?;
    if !was_on {
        return Err(AppError::conflict(ErrorCode::TotpNotEnabled));
    }
    st.audit.log(Event::client("totp_disabled", &info).user(Some(uid), Some(&auth.username)));
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// WebSocket

/// Place d'un WebSocket dans le plafond de sa session ; rendue en sortant de portée.
pub struct WsSlot {
    st: Arc<AppState>,
    key: [u8; 32],
}

impl WsSlot {
    fn take(st: &Arc<AppState>, key: [u8; 32]) -> Option<WsSlot> {
        let mut m = st.ws_open.lock().unwrap_or_else(|p| p.into_inner());
        let n = m.entry(key).or_insert(0);
        if *n >= st.config.ws_per_session {
            return None;
        }
        *n += 1;
        Some(WsSlot { st: st.clone(), key })
    }
}

impl Drop for WsSlot {
    fn drop(&mut self) {
        let mut m = self.st.ws_open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Canal poussé par le serveur : message d'accueil, liste des serveurs (à l'ouverture puis à chaque
/// changement), console, joueurs et mesures du serveur suivi (`watch`) ; ping et revérification de
/// la session toutes les 30 s ; session expirée ou
/// client muet trop longtemps : le canal se ferme. Trames de 64 Kio au plus, quelques canaux par
/// session au plus.
pub async fn ws(
    State(st): St,
    conn: Option<Extension<crate::server::ConnSlot>>,
    auth: Auth,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Some(slot) = WsSlot::take(&st, auth.token_hash) else {
        return AppError::new(StatusCode::TOO_MANY_REQUESTS, ErrorCode::Busy).into_response();
    };
    // La place de connexion TCP part avec le canal : hyper la rendrait à l'upgrade (revue I-C).
    let conn = conn.map(|Extension(c)| c);
    upgrade
        .max_frame_size(WS_MAX_FRAME)
        .max_message_size(WS_MAX_FRAME)
        .on_upgrade(move |socket| ws_loop(socket, st, auth, (slot, conn)))
}

async fn ws_loop(
    mut socket: WebSocket,
    st: Arc<AppState>,
    auth: Auth,
    _held: (WsSlot, Option<crate::server::ConnSlot>),
) {
    let mut closing = st.closing.subscribe();
    let hello = WsServerMessage::Hello { version: env!("CARGO_PKG_VERSION").into() };
    let Ok(text) = serde_json::to_string(&hello) else { return };
    if socket.send(Message::Text(text.into())).await.is_err() {
        return;
    }
    let mut tick = tokio::time::interval(WS_PING);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    let idle = st.config.ws_idle_timeout;
    let mut last_rx = Instant::now();
    // Liste des serveurs à l'ouverture puis à chaque changement (le `watch` regroupe les rafales).
    let mut changed = st.servers.changed.subscribe();
    changed.borrow_and_update();
    if !send_json(&mut socket, &WsServerMessage::Servers { servers: st.servers.list() }).await {
        return;
    }
    // Serveur suivi : console, joueurs, mesures (échantillonnées tant qu'il est suivi).
    let mut watching: Option<Watching> = None;
    loop {
        let deadline = tokio::time::Instant::from_std(last_rx + idle);
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Text(t))) => {
                    last_rx = Instant::now();
                    if let Ok(WsClientMessage::Watch { server }) = serde_json::from_str(&t) {
                        watching = None;
                        if let Some(srv) = server.and_then(crate::paths::ServerId::from_db).and_then(|id| st.servers.get(id)) {
                            let rx = srv.events.subscribe();
                            let guard = st.servers.watch(&srv);
                            let players = WsServerMessage::Players { server: srv.id.get(), players: srv.players() };
                            if !send_json(&mut socket, &players).await {
                                break;
                            }
                            watching = Some(Watching { id: srv.id.get(), rx, _guard: guard });
                        }
                    }
                }
                Some(Ok(_)) => last_rx = Instant::now(),
            },
            r = changed.changed() => {
                if r.is_err() || !send_json(&mut socket, &WsServerMessage::Servers { servers: st.servers.list() }).await {
                    break;
                }
            }
            ev = next_event(&mut watching) => {
                let Some(w) = watching.as_mut() else { continue };
                let msg = match ev {
                    Ok(crate::servers::ServerEvent::Line(l)) => {
                        // Lignes déjà arrivées regroupées en une trame (256 kio au plus).
                        let mut lines = vec![(*l).clone()];
                        let mut size = l.text.len();
                        while size < 256 * 1024 {
                            match w.rx.try_recv() {
                                Ok(crate::servers::ServerEvent::Line(l)) => {
                                    size += l.text.len();
                                    lines.push((*l).clone());
                                }
                                Ok(_) | Err(_) => break,
                            }
                        }
                        WsServerMessage::Console { server: w.id, lines }
                    }
                    Ok(crate::servers::ServerEvent::Players(p)) => WsServerMessage::Players { server: w.id, players: (*p).clone() },
                    Ok(crate::servers::ServerEvent::Stats(s)) => WsServerMessage::Stats { server: w.id, stats: s },
                    // En retard : l'interface relit l'historique ; serveur supprimé : plus suivi.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        watching = None;
                        continue;
                    }
                };
                if !send_json(&mut socket, &msg).await {
                    break;
                }
            }
            _ = tick.tick() => {
                if !session_alive(&st, auth.token_hash).await
                    || socket.send(Message::Ping(Vec::new().into())).await.is_err()
                {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            _ = closing.changed() => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
        }
    }
}

/// Serveur suivi par un WebSocket.
struct Watching {
    id: i64,
    rx: tokio::sync::broadcast::Receiver<crate::servers::ServerEvent>,
    _guard: crate::servers::WatchGuard,
}

async fn next_event(
    w: &mut Option<Watching>,
) -> Result<crate::servers::ServerEvent, tokio::sync::broadcast::error::RecvError> {
    match w {
        Some(w) => w.rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn send_json(socket: &mut WebSocket, msg: &WsServerMessage) -> bool {
    let Ok(text) = serde_json::to_string(msg) else { return false };
    socket.send(Message::Text(text.into())).await.is_ok()
}

async fn session_alive(st: &AppState, h: [u8; 32]) -> bool {
    let idle = st.config.session_idle.as_secs() as i64;
    st.db
        .call(move |c, _| {
            let n = now();
            Ok(c
                .query_row(
                    "SELECT 1 FROM sessions WHERE token_hash = ?1 AND pending_totp = 0 AND expires_at > ?2 AND ?2 - last_seen < ?3",
                    params![&h[..], n, idle],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_de_secours_sans_ambiguite() {
        for _ in 0..200 {
            let c = new_recovery_code();
            assert_eq!(c.len(), RECOVERY_LEN + 2);
            assert_eq!(c.as_bytes()[4], b'-');
            assert_eq!(c.as_bytes()[9], b'-');
            assert!(!c.contains(['0', 'O', '1', 'I']), "{c}");
            let n = normalize_recovery(&c.to_lowercase().replace('-', " "));
            assert_eq!(n, c.replace('-', ""));
        }
        assert_eq!(normalize_recovery(&"A".repeat(65)), "");
    }
}
