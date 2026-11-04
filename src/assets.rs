//! Fichiers de l'interface embarqués dans le binaire (générés par `build.rs`) : version gzip
//! précalculée servie quand le navigateur l'accepte, ETag, cache long pour les fichiers dont le
//! nom porte l'empreinte du contenu. Toute adresse inconnue hors `/api` et sans extension rend
//! `index.html` (navigation de l'application à page unique).

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

pub struct Asset {
    pub path: &'static str,
    pub mime: &'static str,
    pub body: &'static [u8],
    pub gzip: Option<&'static [u8]>,
    pub etag: &'static str,
    /// ETag de la version gzip (représentation différente : ETag différent, RFC 9110 § 8.8.3).
    pub etag_gz: &'static str,
    pub immutable: bool,
}

include!(concat!(env!("OUT_DIR"), "/assets_gen.rs"));

pub fn find(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.path == path)
}

/// Taille totale embarquée (brute, gzip), pour le journal de démarrage et les mesures.
pub fn sizes() -> (usize, usize) {
    ASSETS.iter().fold((0, 0), |(r, z), a| (r + a.body.len(), z + a.gzip.map_or(a.body.len(), <[u8]>::len)))
}

pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return crate::error::AppError::new(StatusCode::NOT_FOUND, rc_manager_shared::ErrorCode::NotFound)
            .into_response();
    }
    let wanted = if path == "/" { "/index.html" } else { path };
    let asset = match find(wanted) {
        Some(a) => a,
        None => {
            let last = path.rsplit('/').next().unwrap_or("");
            if last.contains('.') {
                return StatusCode::NOT_FOUND.into_response();
            }
            match find("/index.html") {
                Some(a) => a,
                None => return StatusCode::NOT_FOUND.into_response(),
            }
        }
    };
    let cache = if asset.immutable { "public, max-age=31536000, immutable" } else { "no-cache" };
    let gzip_ok = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim().starts_with("gzip")));
    let gz = asset.gzip.filter(|_| gzip_ok);
    let etag = if gz.is_some() { asset.etag_gz } else { asset.etag };
    let mut res_headers = HeaderMap::new();
    res_headers.insert(header::ETAG, HeaderValue::from_static(etag));
    res_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    res_headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    if not_modified {
        return (StatusCode::NOT_MODIFIED, res_headers).into_response();
    }
    res_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.mime));
    match gz {
        Some(z) => {
            res_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            (res_headers, z).into_response()
        }
        _ => (res_headers, asset.body).into_response(),
    }
}
