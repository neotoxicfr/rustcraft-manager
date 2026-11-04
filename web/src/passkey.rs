//! Passkeys côté navigateur : `PublicKeyCredential.parse{Creation,Request}OptionsFromJSON`,
//! `navigator.credentials.create/get`, puis `credential.toJSON()` (WebAuthn niveau 3 : Chrome 129+,
//! Safari 18+, Firefox 119+). Les binaires voyagent en base64url, comme l'attend le serveur.

use js_sys::{Function, JSON, Object, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// Échec côté navigateur.
pub enum Failure {
    /// API absente (navigateur trop ancien, contexte non sûr).
    Unsupported,
    /// Annulé par l'utilisateur, délai dépassé, aucune passkey.
    Cancelled,
}

fn get(o: &JsValue, k: &str) -> Result<JsValue, Failure> {
    Reflect::get(o, &JsValue::from_str(k)).map_err(|_| Failure::Unsupported)
}

fn func(o: &JsValue, k: &str) -> Result<Function, Failure> {
    get(o, k)?.dyn_into::<Function>().map_err(|_| Failure::Unsupported)
}

/// Passkeys utilisables ici ?
pub fn supported() -> bool {
    let Some(w) = web_sys::window() else { return false };
    w.is_secure_context()
        && get(&w, "PublicKeyCredential").ok().is_some_and(|p| {
            func(&p, "parseRequestOptionsFromJSON").is_ok() && func(&p, "parseCreationOptionsFromJSON").is_ok()
        })
}

/// `create = true` : nouvelle passkey ; sinon connexion. `options` : JSON rendu par le serveur.
/// Rend `credential.toJSON()` sérialisé.
pub async fn run(create: bool, options: &str) -> Result<String, Failure> {
    let w = web_sys::window().ok_or(Failure::Unsupported)?;
    if !supported() {
        return Err(Failure::Unsupported);
    }
    let pkc = get(&w, "PublicKeyCredential")?;
    let parsed = JSON::parse(options).map_err(|_| Failure::Unsupported)?;
    let public_key_json = get(&parsed, "publicKey")?;
    let parse = func(&pkc, if create { "parseCreationOptionsFromJSON" } else { "parseRequestOptionsFromJSON" })?;
    let public_key = parse.call1(&pkc, &public_key_json).map_err(|_| Failure::Unsupported)?;
    let arg = Object::new();
    Reflect::set(&arg, &JsValue::from_str("publicKey"), &public_key).map_err(|_| Failure::Unsupported)?;
    let creds = get(&w.navigator(), "credentials")?;
    let call = func(&creds, if create { "create" } else { "get" })?;
    let promise: Promise =
        call.call1(&creds, &arg).map_err(|_| Failure::Cancelled)?.dyn_into().map_err(|_| Failure::Unsupported)?;
    let cred = JsFuture::from(promise).await.map_err(|_| Failure::Cancelled)?;
    if cred.is_null() || cred.is_undefined() {
        return Err(Failure::Cancelled);
    }
    let obj = func(&cred, "toJSON")?.call0(&cred).map_err(|_| Failure::Unsupported)?;
    JSON::stringify(&obj).ok().and_then(|s| s.as_string()).ok_or(Failure::Unsupported)
}
