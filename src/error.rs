//! Erreur des routes : un statut HTTP et un code stable (`rc_manager_shared::ErrorCode`) que
//! l'interface traduit. Aucun détail interne n'est renvoyé au client.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rc_manager_shared::{ApiError, ErrorCode};

#[derive(Debug, PartialEq)]
pub struct AppError {
    pub status: StatusCode,
    pub code: ErrorCode,
    pub retry_after: Option<u64>,
}

impl AppError {
    pub fn new(status: StatusCode, code: ErrorCode) -> Self {
        AppError { status, code, retry_after: None }
    }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal)
    }
    pub fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized)
    }
    pub fn invalid_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials)
    }
    pub fn invalid_totp() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::InvalidTotp)
    }
    pub fn csrf() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::CsrfRejected)
    }
    pub fn conflict(code: ErrorCode) -> Self {
        Self::new(StatusCode::CONFLICT, code)
    }
    pub fn unprocessable(code: ErrorCode) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code)
    }
    pub fn too_many(retry_after: u64) -> Self {
        AppError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: ErrorCode::TooManyAttempts,
            retry_after: Some(retry_after),
        }
    }
    /// Réservation refusée par un limiteur.
    pub fn refused(r: crate::ratelimit::Refusal) -> Self {
        Self::too_many(r.retry_after())
    }
    /// Plus de place de hachage à temps : 503, réessayer dans une seconde.
    pub fn busy() -> Self {
        AppError { status: StatusCode::SERVICE_UNAVAILABLE, code: ErrorCode::Busy, retry_after: Some(1) }
    }
    pub fn timeout() -> Self {
        Self::new(StatusCode::REQUEST_TIMEOUT, ErrorCode::RequestTimeout)
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        // Message SQLite seulement : les requêtes passent leurs valeurs en paramètres, aucun secret
        // ne peut s'y trouver.
        tracing::error!("base : {e}");
        AppError::internal()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ApiError { code: self.code, retry_after_secs: self.retry_after };
        let mut res = (self.status, axum::Json(body)).into_response();
        if let Some(s) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&s.to_string())
        {
            res.headers_mut().insert(header::RETRY_AFTER, v);
        }
        res
    }
}
