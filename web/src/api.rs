//! Appels à l'API du gestionnaire par `fetch` (même origine : le cookie de session part seul).
//! Les requêtes POST portent le jeton anti-CSRF de la session.

use rc_manager_shared::{ApiError, CSRF_HEADER, ErrorCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

#[derive(Clone, Debug, PartialEq)]
pub enum ApiErr {
    Api(ErrorCode),
    Network,
}

impl ApiErr {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, ApiErr::Api(ErrorCode::Unauthorized))
    }
}

async fn send(method: &str, path: &str, body: Option<String>, csrf: Option<&str>) -> Result<(u16, String), ApiErr> {
    let init = RequestInit::new();
    init.set_method(method);
    let headers = web_sys::Headers::new().map_err(|_| ApiErr::Network)?;
    if let Some(b) = &body {
        headers.set("content-type", "application/json").map_err(|_| ApiErr::Network)?;
        init.set_body(&JsValue::from_str(b));
    }
    if let Some(t) = csrf {
        headers.set(CSRF_HEADER, t).map_err(|_| ApiErr::Network)?;
    }
    init.set_headers(&headers);
    let req = Request::new_with_str_and_init(path, &init).map_err(|_| ApiErr::Network)?;
    let window = web_sys::window().ok_or(ApiErr::Network)?;
    let resp: Response = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|_| ApiErr::Network)?
        .dyn_into()
        .map_err(|_| ApiErr::Network)?;
    let status = resp.status();
    let text = match resp.text() {
        Ok(p) => JsFuture::from(p).await.ok().and_then(|v| v.as_string()).unwrap_or_default(),
        Err(_) => String::new(),
    };
    if (200..300).contains(&status) {
        Ok((status, text))
    } else {
        let code = serde_json::from_str::<ApiError>(&text).map(|e| e.code).unwrap_or(if status == 401 {
            ErrorCode::Unauthorized
        } else {
            ErrorCode::Internal
        });
        Err(ApiErr::Api(code))
    }
}

pub async fn get<T: DeserializeOwned>(path: &str) -> Result<T, ApiErr> {
    let (_, text) = send("GET", path, None, None).await?;
    serde_json::from_str(&text).map_err(|_| ApiErr::Network)
}

pub async fn post<B: Serialize, T: DeserializeOwned>(path: &str, body: &B, csrf: Option<&str>) -> Result<T, ApiErr> {
    let json = serde_json::to_string(body).map_err(|_| ApiErr::Network)?;
    let (_, text) = send("POST", path, Some(json), csrf).await?;
    serde_json::from_str(&text).map_err(|_| ApiErr::Network)
}

/// POST sans corps de réponse (204).
pub async fn post_empty<B: Serialize>(path: &str, body: &B, csrf: Option<&str>) -> Result<(), ApiErr> {
    let json = serde_json::to_string(body).map_err(|_| ApiErr::Network)?;
    send("POST", path, Some(json), csrf).await.map(|_| ())
}
