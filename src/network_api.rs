//! Routes de l'adresse publique d'un serveur (`/api/servers/{id}/address…`).
//!
//! Lecture, aperçu et test : tout compte connecté. Application (écrit dans la zone DNS) :
//! administrateurs seulement, après un aperçu dont l'empreinte est renvoyée ; session, CSRF
//! et audit comme partout.

use crate::AppState;
use crate::api::ApiJson;
use crate::error::AppError;
use crate::http::{Auth, ClientInfo};
use crate::servers_api::{is_admin, server};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use rc_manager_shared::*;
use std::sync::Arc;

type St = State<Arc<AppState>>;

pub async fn get(State(st): St, _auth: Auth, Path(id): Path<String>) -> Result<Json<AddressView>, AppError> {
    let srv = server(&st, &id)?;
    Ok(Json(st.network.view(&st.servers, srv.id)))
}

pub async fn preview(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AddressRequest>,
) -> Result<Json<AddressPreview>, AppError> {
    let srv = server(&st, &id)?;
    let next = req.address.as_ref().map(|s| st.network.validate(&st.servers, srv.id, s)).transpose()?;
    Ok(Json(st.network.preview(&st.servers, srv.id, next.as_ref()).await?))
}

pub async fn apply(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AddressRequest>,
) -> Result<Json<AddressApplied>, AppError> {
    let srv = server(&st, &id)?;
    if !is_admin(&st, auth.user_id).await? {
        return Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden));
    }
    Ok(Json(st.network.apply(&st, srv.id, &req, (auth.user_id, &auth.username, &info)).await?))
}

pub async fn test(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    ApiJson(_): ApiJson<crate::servers_api::Empty>,
) -> Result<Json<ReachTest>, AppError> {
    let srv = server(&st, &id)?;
    Ok(Json(st.network.test(&st.servers, srv.id).await?))
}
