//! Routes des serveurs (`/api/servers…`, `/api/catalog…`, `/api/java`) et du thème du compte.
//!
//! Toute route qui modifie passe par la session et le jeton CSRF ([`Auth`]) et écrit une ligne
//! d'audit ; la suppression d'un serveur exige en plus la ré-authentification ([`Reauthed`]) et
//! le nom recopié. Les identifiants de serveur sont validés par [`ServerId::parse`] (404 sinon).

use crate::AppState;
use crate::api::{ApiJson, NeedsReauth, Reauthed, reauthed_checked};
use crate::audit::Event;
use crate::error::AppError;
use crate::http::{Auth, ClientInfo};
use crate::paths::ServerId;
use crate::servers::Server;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use rc_manager_shared::*;
use serde::Deserialize;
use std::sync::Arc;

type St = State<Arc<AppState>>;

fn not_found() -> AppError {
    AppError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound)
}

/// Serveur désigné par l'adresse (identifiant validé, existant).
pub(crate) fn server(st: &AppState, id: &str) -> Result<Arc<Server>, AppError> {
    let sid = ServerId::parse(id).ok_or_else(not_found)?;
    st.servers.get(sid).ok_or_else(not_found)
}

pub(crate) fn audit(st: &AppState, action: &'static str, info: &ClientInfo, auth: &Auth, detail: String) {
    st.audit.log(Event::client(action, info).user(Some(auth.user_id), Some(&auth.username)).detail(&detail));
}

pub(crate) async fn is_admin(st: &AppState, user_id: i64) -> Result<bool, AppError> {
    st.db.call(move |c, _| Ok(c.query_row("SELECT is_admin FROM users WHERE id = ?1", [user_id], |r| r.get(0))?)).await
}

pub async fn catalog(State(st): St, _auth: Auth, Path(sw): Path<String>) -> Result<Json<Vec<GameVersion>>, AppError> {
    let sw = Software::from_code(&sw).ok_or_else(not_found)?;
    let list = st.servers.catalog.versions(sw).await.map_err(|e| {
        tracing::warn!("versions de {} : {e}", sw.code());
        AppError::new(StatusCode::BAD_GATEWAY, e.code())
    })?;
    Ok(Json(list.as_ref().clone()))
}

pub async fn java(State(st): St, _auth: Auth) -> Json<Vec<JavaInfo>> {
    let tmp = st.servers.tmp();
    let _ = std::fs::create_dir_all(&tmp);
    Json(crate::java::detect(&st.servers.data, &tmp).await)
}

pub async fn list(State(st): St, _auth: Auth) -> Json<Vec<ServerInfo>> {
    Json(st.servers.list())
}

pub async fn create(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    ApiJson(req): ApiJson<CreateServerRequest>,
) -> Result<(StatusCode, Json<ServerInfo>), AppError> {
    let admin = is_admin(&st, auth.user_id).await?;
    let eula = req.accept_eula;
    let s = st.servers.create(req, auth.user_id, admin).await?;
    audit(&st, "server_created", &info, &auth, format!("{} {} {}", s.id, s.software.code(), s.version));
    if eula {
        audit(&st, "eula_accepted", &info, &auth, s.id.to_string());
    }
    Ok((StatusCode::ACCEPTED, Json(s)))
}

pub async fn get(State(st): St, _auth: Auth, Path(id): Path<String>) -> Result<Json<ServerInfo>, AppError> {
    Ok(Json(server(&st, &id)?.info()))
}

/// Corps vide `{}` des actions sans paramètre (le JSON est exigé pour toute modification).
#[derive(Deserialize)]
pub struct Empty {}

macro_rules! action {
    ($name:ident, $method:ident, $audit:literal) => {
        pub async fn $name(
            State(st): St,
            Extension(info): Extension<ClientInfo>,
            auth: Auth,
            Path(id): Path<String>,
            ApiJson(_): ApiJson<Empty>,
        ) -> Result<(StatusCode, Json<ServerInfo>), AppError> {
            let srv = server(&st, &id)?;
            st.servers.$method(&srv)?;
            audit(&st, $audit, &info, &auth, srv.id.to_string());
            Ok((StatusCode::ACCEPTED, Json(srv.info())))
        }
    };
}

action!(start, start, "server_start");
action!(stop, stop, "server_stop");
action!(restart, restart, "server_restart");
action!(install, reinstall, "server_install");

pub async fn eula(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<EulaRequest>,
) -> Result<Json<ServerInfo>, AppError> {
    let srv = server(&st, &id)?;
    // Seule une case cochée par l'utilisateur vaut acceptation.
    if !req.accept {
        return Err(AppError::unprocessable(ErrorCode::EulaRequired));
    }
    st.servers.accept_eula(&srv, auth.user_id).await?;
    audit(&st, "eula_accepted", &info, &auth, srv.id.to_string());
    Ok(Json(srv.info()))
}

pub async fn settings(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ServerSettingsRequest>,
) -> Result<Json<ServerInfo>, AppError> {
    let srv = server(&st, &id)?;
    let admin = is_admin(&st, auth.user_id).await?;
    let s = st.servers.update(&srv, req, admin).await?;
    audit(&st, "server_settings", &info, &auth, srv.id.to_string());
    Ok(Json(s))
}

impl NeedsReauth for DeleteServerRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
    fn validate(&self) -> Result<(), AppError> {
        if self.confirm_name.trim().is_empty() { Err(AppError::unprocessable(ErrorCode::NameMismatch)) } else { Ok(()) }
    }
}

/// Suppression : session + CSRF + nom du serveur recopié exactement (vérifié d'abord : une faute
/// de frappe ne consomme pas de code) + ré-authentification (mot de passe, + code TOTP s'il est
/// actif).
pub async fn delete(
    State(st): St,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Result<StatusCode, AppError> {
    let srv = server(&st, &id)?;
    let name = srv.row().name;
    let Reauthed { auth, info, .. } = reauthed_checked::<DeleteServerRequest>(req, &st, |b| {
        if b.confirm_name.trim() == name.trim() {
            Ok(())
        } else {
            Err(AppError::unprocessable(ErrorCode::NameMismatch))
        }
    })
    .await?;
    st.servers.delete(&srv)?;
    audit(&st, "server_deleted", &info, &auth, srv.id.to_string());
    Ok(StatusCode::ACCEPTED)
}

pub async fn command(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<CommandRequest>,
) -> Result<StatusCode, AppError> {
    let srv = server(&st, &id)?;
    st.servers.command(&srv, &auth.username, &req.command).await?;
    let shown: String = req.command.trim().chars().take(200).collect();
    audit(&st, "server_command", &info, &auth, format!("{} {shown}", srv.id));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ConsoleQuery {
    before: Option<u64>,
}

pub async fn console(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ConsoleQuery>,
) -> Result<Json<ConsoleHistory>, AppError> {
    let srv = server(&st, &id)?;
    Ok(Json(ConsoleHistory { lines: srv.history(500, q.before), players: srv.players() }))
}

#[derive(Deserialize)]
pub struct SuggestQuery {
    #[serde(default)]
    q: String,
}

pub async fn suggest_items(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<SuggestQuery>,
) -> Result<Json<Vec<ItemSuggestion>>, AppError> {
    let srv = server(&st, &id)?;
    if q.q.len() > 64 {
        return Ok(Json(Vec::new()));
    }
    let row = srv.row();
    let idx = st.servers.languages.items(&st.servers.catalog, &st.servers.data, &row.version, &srv.dir).await;
    Ok(Json(idx.map(|i| i.search(&q.q)).unwrap_or_default()))
}

pub async fn suggest_players(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<SuggestQuery>,
) -> Result<Json<Vec<PlayerSuggestion>>, AppError> {
    let srv = server(&st, &id)?;
    if q.q.len() > 64 {
        return Ok(Json(Vec::new()));
    }
    let online: Vec<String> = srv.players().into_iter().map(|p| p.name).collect();
    let dir = srv.dir.clone();
    let res = tokio::task::spawn_blocking(move || crate::lang::players(&dir, &online, &q.q)).await.unwrap_or_default();
    Ok(Json(res))
}

pub async fn favorites(State(st): St, auth: Auth, Path(id): Path<String>) -> Result<Json<Vec<Favorite>>, AppError> {
    let srv = server(&st, &id)?;
    Ok(Json(st.servers.favorites(srv.id, auth.user_id).await?))
}

pub async fn favorite_add(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FavoriteRequest>,
) -> Result<Json<Favorite>, AppError> {
    let srv = server(&st, &id)?;
    let f = st.servers.add_favorite(srv.id, auth.user_id, req).await?;
    audit(&st, "favorite_added", &info, &auth, srv.id.to_string());
    Ok(Json(f))
}

pub async fn favorite_delete(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FavoriteDeleteRequest>,
) -> Result<StatusCode, AppError> {
    let srv = server(&st, &id)?;
    if !st.servers.delete_favorite(srv.id, auth.user_id, req.id).await? {
        return Err(not_found());
    }
    audit(&st, "favorite_deleted", &info, &auth, srv.id.to_string());
    Ok(StatusCode::NO_CONTENT)
}

/// Thème du compte (`POST /api/account/theme`) : couleurs `#rrggbb` validées, stocké en base.
pub async fn theme(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    ApiJson(req): ApiJson<ThemeSettings>,
) -> Result<StatusCode, AppError> {
    if !req.valid() {
        return Err(AppError::unprocessable(ErrorCode::InvalidTheme));
    }
    let json = serde_json::to_string(&req).map_err(|_| AppError::internal())?;
    let uid = auth.user_id;
    st.db
        .call(move |c, _| {
            c.execute("UPDATE users SET theme = ?1 WHERE id = ?2", rusqlite::params![json, uid])?;
            Ok(())
        })
        .await?;
    st.audit.log(Event::client("theme_changed", &info).user(Some(auth.user_id), Some(&auth.username)));
    Ok(StatusCode::NO_CONTENT)
}
