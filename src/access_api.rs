//! Routes des listes d'accès (`/api/servers/{id}/access…`, onglet « Joueurs »).
//!
//! Lecture : session. Actions : session + CSRF ([`Auth`] sur un POST), bornes de chaque valeur,
//! ligne d'audit. Serveur en marche : la commande de console équivalente (immédiat, et le jeu
//! réécrit lui-même son fichier) ; arrêté : écriture atomique du fichier, sans perte, avec la
//! version précédente dans l'historique des réglages (restaurable en mode JSON). Démarrage ou
//! arrêt en cours : refus (le jeu lit ou écrit ces fichiers à ce moment-là).

use crate::AppState;
use crate::access::{self, ListError};
use crate::api::ApiJson;
use crate::configs_api::{SAVE_LOCK, keep_version};
use crate::error::AppError;
use crate::http::{Auth, ClientInfo};
use crate::servers::Server;
use crate::servers_api::{audit, server};
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use rc_manager_shared::*;
use serde::Deserialize;
use std::sync::Arc;

type St = State<Arc<AppState>>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, AppError> {
    tokio::task::spawn_blocking(f).await.map_err(|_| AppError::internal())
}

fn busy(s: &Server) -> bool {
    matches!(s.state(), ServerState::Starting | ServerState::Stopping) || s.info().op.is_some()
}

fn invalid() -> AppError {
    AppError::unprocessable(ErrorCode::InvalidValue)
}

/// État des listes : lecture seule (une liste absente s'ouvre vide en mode JSON, voir
/// `configs_api::read`).
pub async fn get(State(st): St, _auth: Auth, Path(id): Path<String>) -> Result<Json<AccessState>, AppError> {
    let srv = server(&st, &id)?;
    let dir = srv.dir.clone();
    Ok(Json(blocking(move || access::state(&dir)).await?))
}

#[derive(Deserialize)]
pub struct ResolveQuery {
    name: String,
}

/// UUID d'un joueur : déjà venu (`usercache.json`), sinon Mojang (`online-mode=true`), sinon UUID
/// hors ligne calculé.
async fn resolve_player(st: &AppState, srv: &Server, name: &str, online: bool) -> Result<ResolvedPlayer, AppError> {
    if !crate::console::player_name_ok(name) {
        return Err(invalid());
    }
    if !online {
        return Ok(ResolvedPlayer { name: name.to_string(), uuid: access::offline_uuid(name), offline: true });
    }
    let (dir, n) = (srv.dir.clone(), name.to_string());
    if let Some(p) = blocking(move || access::from_usercache(&dir, &n)).await? {
        return Ok(p);
    }
    match access::mojang(&st.servers.catalog.http, name).await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(AppError::unprocessable(ErrorCode::UnknownPlayer)),
        Err(access::LookupError::Failed) => {
            Err(AppError::new(axum::http::StatusCode::BAD_GATEWAY, ErrorCode::LookupFailed))
        }
        Err(access::LookupError::Limited(s)) => Err(AppError::too_many(s)),
    }
}

pub async fn resolve(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<ResolveQuery>,
) -> Result<Json<ResolvedPlayer>, AppError> {
    let srv = server(&st, &id)?;
    let dir = srv.dir.clone();
    let online = blocking(move || access::state(&dir).online_mode).await?;
    Ok(Json(resolve_player(&st, &srv, q.name.trim(), online).await?))
}

/// Écrit une liste modifiée (arrêté) : lecture, modification, écriture atomique, historique.
async fn write_list(
    st: &AppState,
    srv: &Arc<Server>,
    auth: &Auth,
    l: AccessList,
    edit: impl FnOnce(&mut Vec<serde_json::Value>) -> bool + Send + 'static,
) -> Result<bool, AppError> {
    let lock = SAVE_LOCK.lock().await;
    if busy(srv) || srv.state() == ServerState::Running {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    let dir = srv.dir.clone();
    // Verrou tenu par le fil jusqu'à la fin de l'écriture, puis pendant l'historique.
    let (res, _lock) = crate::configs_api::blocking_held(false, lock, move || -> Result<Option<Vec<u8>>, ListError> {
        let (mut list, original) = access::read_raw(&dir, l)?;
        if !edit(&mut list) {
            return Ok(None);
        }
        let bytes = access::render(&list, original.as_deref());
        crate::fsutil::write_atomic(&dir.join(l.file()), &bytes).map_err(|_| ListError::Io)?;
        Ok(Some(original.unwrap_or_default()))
    })
    .await?;
    match res {
        Ok(Some(old)) => {
            keep_version(st, srv.id.get(), auth.user_id, l.file(), old).await;
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(ListError::Unreadable) => Err(AppError::unprocessable(ErrorCode::ConfigInvalid)),
        Err(ListError::Io) => Err(AppError::internal()),
    }
}

pub async fn add(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AccessAddRequest>,
) -> Result<Json<AccessApplied>, AppError> {
    let srv = server(&st, &id)?;
    let l = req.list;
    // Bornes de chaque valeur, avant tout.
    let target = if l == AccessList::BannedIps {
        access::ip_ok(&req.target).ok_or_else(invalid)?
    } else {
        let t = req.target.trim().to_string();
        if !crate::console::player_name_ok(&t) {
            return Err(invalid());
        }
        t
    };
    if req.reason.as_deref().is_some_and(|r| !access::reason_ok(r))
        || req.level.is_some_and(|n| !OP_LEVELS.contains(&n))
        || req.expires.is_some_and(|e| e <= crate::db::now() || e > crate::db::now() + 100 * 365 * 86_400)
    {
        return Err(invalid());
    }
    if busy(&srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    let dir = srv.dir.clone();
    let acc = blocking(move || access::state(&dir)).await?;
    let detail = |how: &str| format!("{} {} {target} ({how})", srv.id, l.code());
    if srv.state() == ServerState::Running {
        // La console ne règle ni le niveau, ni la limite, ni l'expiration.
        let extra = req.level.is_some_and(|n| n != acc.default_op_level)
            || req.bypasses_player_limit == Some(true)
            || req.expires.is_some();
        if extra {
            return Err(AppError::conflict(ErrorCode::StopFirst));
        }
        let cmd = access::command_add(l, &target, req.reason.as_deref());
        st.servers.command(&srv, &auth.username, &cmd).await?;
        audit(&st, "access_added", &info, &auth, detail("console"));
        return Ok(Json(AccessApplied { by_console: true, restart_needed: false, entry: None }));
    }
    let (name, uuid) = if l == AccessList::BannedIps {
        (target.clone(), String::new())
    } else {
        let p = resolve_player(&st, &srv, &target, acc.online_mode).await?;
        (p.name, p.uuid)
    };
    let fields = access::fields(l, &name, &uuid, &req, acc.default_op_level, crate::db::now());
    let entry = access::to_entry(&serde_json::Value::Object(fields.clone()));
    let (n2, u2) = (name.clone(), uuid.clone());
    write_list(&st, &srv, &auth, l, move |list| {
        let uuid = (!u2.is_empty()).then_some(u2.as_str());
        access::upsert(list, l, &n2, uuid, fields);
        true
    })
    .await?;
    audit(&st, "access_added", &info, &auth, detail("fichier"));
    Ok(Json(AccessApplied { by_console: false, restart_needed: false, entry: Some(entry) }))
}

pub async fn remove(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AccessRemoveRequest>,
) -> Result<Json<AccessApplied>, AppError> {
    let srv = server(&st, &id)?;
    let l = req.list;
    let target = if l == AccessList::BannedIps {
        access::ip_ok(&req.target).ok_or_else(invalid)?
    } else {
        let t = req.target.trim().to_string();
        // Entrée écrite à la main avec un pseudo hors norme : retirée par son UUID.
        if !crate::console::player_name_ok(&t) && access::dashed(&t).is_none() {
            return Err(invalid());
        }
        t
    };
    if busy(&srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    let detail = |how: &str| format!("{} {} {target} ({how})", srv.id, l.code());
    if srv.state() == ServerState::Running {
        // La console désigne un joueur par son pseudo (une entrée sans pseudo valide : arrêté).
        if l != AccessList::BannedIps && !crate::console::player_name_ok(&target) {
            return Err(AppError::conflict(ErrorCode::StopFirst));
        }
        let cmd = access::command_remove(l, &target);
        st.servers.command(&srv, &auth.username, &cmd).await?;
        audit(&st, "access_removed", &info, &auth, detail("console"));
        return Ok(Json(AccessApplied { by_console: true, restart_needed: false, entry: None }));
    }
    let t2 = target.clone();
    let found = write_list(&st, &srv, &auth, l, move |list| access::remove(list, l, &t2)).await?;
    if !found {
        return Err(AppError::new(axum::http::StatusCode::NOT_FOUND, ErrorCode::NotFound));
    }
    audit(&st, "access_removed", &info, &auth, detail("fichier"));
    Ok(Json(AccessApplied { by_console: false, restart_needed: false, entry: None }))
}

/// Interrupteurs de la liste blanche : `white-list` (commande `whitelist on|off` en marche) et
/// `enforce-whitelist` (lu au démarrage seulement : serveur arrêté).
pub async fn whitelist_mode(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<WhitelistModeRequest>,
) -> Result<Json<AccessApplied>, AppError> {
    let srv = server(&st, &id)?;
    if busy(&srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    let dir = srv.dir.clone();
    let acc = blocking(move || access::state(&dir)).await?;
    let detail = format!("{} white-list={} enforce-whitelist={}", srv.id, req.enabled, req.enforce);
    if srv.state() == ServerState::Running {
        if req.enforce != acc.enforce_whitelist {
            return Err(AppError::conflict(ErrorCode::StopFirst));
        }
        if req.enabled != acc.white_list {
            let cmd = if req.enabled { "whitelist on" } else { "whitelist off" };
            st.servers.command(&srv, &auth.username, cmd).await?;
        }
        audit(&st, "access_whitelist_mode", &info, &auth, detail);
        return Ok(Json(AccessApplied { by_console: true, restart_needed: false, entry: None }));
    }
    let lock = SAVE_LOCK.lock().await;
    if busy(&srv) || srv.state() == ServerState::Running {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    let p = srv.dir.join("server.properties");
    let (en, enf) = (req.enabled.to_string(), req.enforce.to_string());
    let (old, _lock) = crate::configs_api::blocking_held(false, lock, move || -> std::io::Result<Vec<u8>> {
        let old = match crate::fsutil::read_bounded(&p, CONFIG_MAX_BYTES as u64) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        crate::props::patch_file(&p, &[("white-list", en), ("enforce-whitelist", enf)])?;
        Ok(old)
    })
    .await?;
    let old = old.map_err(|_| AppError::internal())?;
    keep_version(&st, srv.id.get(), auth.user_id, "server.properties", old).await;
    audit(&st, "access_whitelist_mode", &info, &auth, detail);
    Ok(Json(AccessApplied { by_console: false, restart_needed: false, entry: None }))
}
