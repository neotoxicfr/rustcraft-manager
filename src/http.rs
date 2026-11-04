//! Couche HTTP commune : adresse réelle du client (mandataires de confiance), contrôles anti-CSRF
//! des requêtes qui modifient, délai par requête, en-têtes de sécurité, cookie et extracteur de
//! session.

use crate::AppState;
use crate::config::CookieSecure;
use crate::crypto::{ct_eq, sha256};
use crate::db::now;
use crate::error::AppError;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rc_manager_shared::{CSRF_HEADER, SESSION_COOKIE, SESSION_COOKIE_HOST};
use rusqlite::OptionalExtension;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proxies::TrustedProxies;

/// Ce que l'on sait du client, posé dans les extensions de la requête par [`guard`].
#[derive(Clone, Debug)]
pub struct ClientInfo {
    /// Adresse du client réel (celle du pair, ou `X-Forwarded-For` derrière un mandataire de
    /// confiance).
    pub ip: IpAddr,
    /// Requête arrivée en HTTPS (vu par le mandataire de confiance).
    pub https: bool,
    /// `User-Agent` borné à [`MAX_USER_AGENT`] octets (journal d'audit, chiffré en base). Lu
    /// seulement pour l'API.
    pub user_agent: Option<Arc<str>>,
    /// La requête porte un en-tête de relais (`X-Forwarded-*`, `Forwarded`, `X-Real-IP`).
    pub forwarded: bool,
}

/// Un en-tête posé par un mandataire est-il présent ?
fn relayed(headers: &HeaderMap) -> bool {
    ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip"]
        .iter()
        .any(|h| headers.contains_key(*h))
}

/// Longueur gardée du `User-Agent` (un en-tête de plusieurs Kio par ligne
/// d'audit gonflait la base).
pub const MAX_USER_AGENT: usize = 512;

fn user_agent(headers: &HeaderMap) -> Option<Arc<str>> {
    let ua = headers.get(header::USER_AGENT)?.to_str().ok()?.trim();
    if ua.is_empty() {
        return None;
    }
    let mut end = ua.len().min(MAX_USER_AGENT);
    while !ua.is_char_boundary(end) {
        end -= 1;
    }
    Some(Arc::from(&ua[..end]))
}

impl ClientInfo {
    pub fn ip_text(&self) -> String {
        crate::config::canonical_ip(self.ip).to_string()
    }
    /// Client sur la machine même : boucle locale ET aucun en-tête de relais (un mandataire local
    /// non déclaré relaie des clients distants : pas « local », mineur 4 de la seconde revue).
    pub fn is_local(&self) -> bool {
        crate::config::canonical_ip(self.ip).is_loopback() && !self.forwarded
    }
}

/// Client réel derrière une chaîne de mandataires : on lit `X-Forwarded-For` de droite à gauche
/// (chaque mandataire AJOUTE l'adresse qu'il voit) et on garde la première adresse qui n'est pas un
/// mandataire de confiance ; ce qui est plus à gauche a pu être écrit par le client lui-même.
fn forwarded_client(headers: &HeaderMap, proxies: &TrustedProxies) -> Option<IpAddr> {
    let mut last = None;
    for v in headers.get_all("x-forwarded-for").iter().rev() {
        let s = v.to_str().ok()?;
        for part in s.rsplit(',') {
            let ip: IpAddr = parse_forwarded_ip(part.trim())?;
            if !proxies.contains(ip) {
                return Some(ip);
            }
            last = Some(ip);
        }
    }
    last
}

/// `1.2.3.4`, `1.2.3.4:5678`, `::1` ou `[::1]:5678`.
fn parse_forwarded_ip(s: &str) -> Option<IpAddr> {
    if let Ok(ip) = s.parse() {
        return Some(ip);
    }
    s.parse::<SocketAddr>().ok().map(|a| a.ip())
}

/// Dernière valeur d'un en-tête à valeurs séparées par des virgules.
fn last_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let v = headers.get_all(name).iter().next_back()?.to_str().ok()?;
    Some(v.rsplit(',').next()?.trim().to_ascii_lowercase())
}

/// Schéma vu par le client derrière le mandataire. Traefik annonce `wss` (et non `https`) pour
/// une poignée de main WebSocket : sans ce cas, l'Origin `https://…` du canal en direct était
/// jugée d'un autre schéma et le canal refusé (liste des serveurs jamais reçue).
fn forwarded_https(headers: &HeaderMap) -> bool {
    matches!(last_value(headers, "x-forwarded-proto").as_deref(), Some("https" | "wss"))
}

pub fn client_info(st: &AppState, peer: IpAddr, headers: &HeaderMap) -> ClientInfo {
    if st.proxies.contains(peer) {
        ClientInfo {
            ip: forwarded_client(headers, &st.proxies).unwrap_or(peer),
            https: forwarded_https(headers),
            user_agent: None,
            forwarded: relayed(headers),
        }
    } else {
        // Un mandataire non déclaré (ou un client qui invente l'en-tête) : ignoré, signalé une
        // fois (sinon la limite de tentatives compte tous les clients comme le mandataire).
        if headers.contains_key("x-forwarded-for") && !st.xff_warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "X-Forwarded-For reçu de {peer}, qui n'est pas dans trusted_proxies : en-tête ignoré. \
                 Derrière un mandataire, déclarez-le (son nom d'hôte, par exemple « traefik », ou son IP)"
            );
        }
        ClientInfo { ip: peer, https: false, user_agent: None, forwarded: relayed(headers) }
    }
}

/// Hôte vu par le client (pour comparer à `Origin`).
fn effective_host(st: &AppState, peer: IpAddr, headers: &HeaderMap) -> Option<String> {
    if st.proxies.contains(peer)
        && let Some(h) = last_value(headers, "x-forwarded-host")
    {
        return Some(h);
    }
    headers.get(header::HOST)?.to_str().ok().map(|h| h.trim().to_ascii_lowercase())
}

/// Hôte sans le port par défaut du schéma.
fn strip_default_port(host: &str, https: bool) -> &str {
    host.strip_suffix(if https { ":443" } else { ":80" }).unwrap_or(host)
}

/// `Origin` (s'il est présent) doit être EXACTEMENT `<schéma>://<hôte>` de la requête, schéma
/// compris (une page `http://` du même nom ne peut pas agir sur le site `https://`).
fn origin_ok(origin: &HeaderValue, host: Option<&str>, https: bool) -> bool {
    let (Ok(o), Some(host)) = (origin.to_str(), host) else {
        return false;
    };
    let o = o.trim().to_ascii_lowercase();
    let scheme = if https { "https://" } else { "http://" };
    let Some(rest) = o.strip_prefix(scheme) else {
        return false;
    };
    strip_default_port(rest, https) == strip_default_port(host, https)
}

/// Politique de sécurité du contenu : scripts du même site seulement (plus l'amorce en ligne de
/// `trunk`, autorisée par son empreinte), WebAssembly permis, aucun style en ligne, aucun cadre.
pub fn csp() -> String {
    format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'{}; style-src 'self'; \
         img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        crate::assets::CSP_SCRIPT_HASHES
    )
}

/// Fonctions du navigateur dont l'interface n'a pas besoin, refusées à la page et à tout cadre.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), display-capture=(), \
    geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), \
    publickey-credentials-get=(self), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()";

/// Intergiciel posé sur toutes les routes.
pub async fn guard(State(st): State<Arc<AppState>>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let mut info = client_info(&st, peer, req.headers());
    let path = req.uri().path();
    let is_api = path.starts_with("/api/");
    if is_api {
        // Seulement pour l'API (audit) : rien à copier pour les fichiers de l'interface.
        info.user_agent = user_agent(req.headers());
    }
    if is_api {
        let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
        // Envoi de fichier : corps brut (`application/octet-stream`), protégé comme le reste par
        // l'en-tête anti-CSRF (qu'un formulaire d'un autre site ne peut pas poser) et l'Origin.
        let upload = is_upload(path);
        if mutating && upload && !content_type_is(req.headers(), "application/octet-stream") {
            return with_security_headers(AppError::csrf().into_response(), info.https, true);
        }
        let ws = path == "/api/ws";
        if (mutating || ws)
            && let Some(origin) = req.headers().get(header::ORIGIN)
            && !origin_ok(origin, effective_host(&st, peer, req.headers()).as_deref(), info.https)
        {
            return with_security_headers(AppError::csrf().into_response(), info.https, true);
        }
        // Un formulaire d'un autre site ne peut pas envoyer de JSON sans requête préalable CORS
        // (que nous ne servons pas) : exiger ce type ferme la porte aux CSRF « simples ».
        if mutating && !upload {
            let json = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("application/json"));
            if !json {
                return with_security_headers(AppError::csrf().into_response(), info.https, true);
            }
        }
    }
    let https = info.https;
    req.extensions_mut().insert(info);
    // Délai total (corps compris) : un client qui envoie son corps octet par octet ne tient pas
    // une connexion indéfiniment. Le WebSocket rend sa réponse 101 tout de suite : non concerné.
    // Fichiers de l'interface : aucun corps lu, réponse immédiate depuis la mémoire ; pas de
    // minuterie par requête (travail évité ; l'écart mesuré se perd dans le bruit, docs/perf.md).
    // Envoi de fichier : pas de délai total (des Gio peuvent prendre longtemps), la route coupe
    // après 60 s sans rien recevoir.
    let res = if is_api && !is_upload(req.uri().path()) {
        match tokio::time::timeout(st.config.request_timeout, next.run(req)).await {
            Ok(r) => r,
            Err(_) => AppError::timeout().into_response(),
        }
    } else {
        next.run(req).await
    };
    with_security_headers(res, https, is_api)
}

/// Route d'envoi de fichier (`/api/servers/{id}/files/upload`).
fn is_upload(path: &str) -> bool {
    path.strip_prefix("/api/servers/")
        .and_then(|r| r.split_once('/'))
        .is_some_and(|(id, rest)| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && rest == "files/upload")
}

fn content_type_is(h: &HeaderMap, want: &str) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case(want))
}

fn with_security_headers(mut res: Response, https: bool, api: bool) -> Response {
    let h = res.headers_mut();
    // Calculée une fois (l'interface est embarquée : ses empreintes ne changent pas).
    static CSP: std::sync::LazyLock<HeaderValue> =
        std::sync::LazyLock::new(|| HeaderValue::from_str(&csp()).expect("CSP ASCII"));
    h.insert("content-security-policy", CSP.clone());
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static(PERMISSIONS_POLICY));
    if https {
        h.insert("strict-transport-security", HeaderValue::from_static("max-age=31536000"));
    }
    if api && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// Le cookie de session est-il `Secure` pour cette requête ?
pub fn cookie_secure(st: &AppState, info: &ClientInfo) -> bool {
    match st.config.cookie_secure {
        CookieSecure::Always => true,
        CookieSecure::Never => false,
        CookieSecure::Auto => info.https,
    }
}

/// Nom du cookie : `__Host-rcm_session` quand il est `Secure`.
pub fn cookie_name(secure: bool) -> &'static str {
    if secure { SESSION_COOKIE_HOST } else { SESSION_COOKIE }
}

/// Valeur du cookie de session dans `Cookie`. En HTTPS, seul `__Host-rcm_session` est lu : un
/// `rcm_session` posé par un sous-domaine (cookie « lancé ») est ignoré.
pub fn session_token(headers: &HeaderMap, secure: bool) -> Option<String> {
    let name = cookie_name(secure);
    for v in headers.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k == name
                && !v.is_empty()
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Jeton de session de la requête (nom du cookie selon HTTPS).
pub fn request_token(st: &AppState, info: &ClientInfo, headers: &HeaderMap) -> Option<String> {
    session_token(headers, cookie_secure(st, info))
}

/// En-tête `Set-Cookie` de la session (`max_age` = 0 : effacement).
pub fn session_cookie(st: &AppState, info: &ClientInfo, token: &str, max_age: u64) -> HeaderValue {
    let secure = cookie_secure(st, info);
    let v = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        cookie_name(secure),
        if secure { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&v).expect("cookie ASCII")
}

/// Session ouverte (double authentification passée). Extraire `Auth` sur une route qui modifie
/// impose aussi le jeton anti-CSRF.
#[derive(Clone, Debug)]
pub struct Auth {
    pub user_id: i64,
    pub username: String,
    pub token_hash: [u8; 32],
    pub csrf: String,
}

/// Session complète valide pour ce jeton (inactivité et durée maximale vérifiées, `last_seen`
/// rafraîchi au plus une fois par minute).
pub async fn lookup_session(st: &AppState, token: &str) -> Result<Option<Auth>, AppError> {
    let token_hash = sha256(token.as_bytes());
    let idle = st.config.session_idle.as_secs() as i64;
    st.db
        .call(move |c, _| {
            let now = now();
            let row = c
                .query_row(
                    "SELECT s.user_id, u.username, s.csrf, s.last_seen, s.expires_at
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ?1 AND s.pending_totp = 0",
                    [&token_hash[..]],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, i64>(3)?,
                            r.get::<_, i64>(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((user_id, username, csrf, last_seen, expires_at)) = row else {
                return Ok(None);
            };
            if now >= expires_at || now - last_seen >= idle {
                c.execute("DELETE FROM sessions WHERE token_hash = ?1", [&token_hash[..]])?;
                return Ok(None);
            }
            // Une écriture par minute au plus, pas une par requête.
            if now - last_seen >= 60 {
                c.execute(
                    "UPDATE sessions SET last_seen = ?1 WHERE token_hash = ?2",
                    rusqlite::params![now, &token_hash[..]],
                )?;
            }
            Ok(Some(Auth { user_id, username, token_hash, csrf }))
        })
        .await
}

impl FromRequestParts<Arc<AppState>> for Auth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &Arc<AppState>) -> Result<Self, AppError> {
        let info = parts.extensions.get::<ClientInfo>().cloned().ok_or_else(AppError::internal)?;
        let token = request_token(st, &info, &parts.headers).ok_or_else(AppError::unauthorized)?;
        let auth = lookup_session(st, &token).await?.ok_or_else(AppError::unauthorized)?;
        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let sent = parts.headers.get(CSRF_HEADER).map(|v| v.as_bytes()).unwrap_or_default();
            if !ct_eq(sent, auth.csrf.as_bytes()) {
                return Err(AppError::csrf());
            }
        }
        Ok(auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxySpec;

    #[test]
    fn x_forwarded_for_de_droite_a_gauche() {
        let proxies = TrustedProxies::new(&[ProxySpec::parse("10.0.0.0/8").unwrap()]);
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4, 10.0.0.7".parse().unwrap());
        // 6.6.6.6 a pu être inventé par le client : on s'arrête au premier non fiable en partant
        // de la droite.
        assert_eq!(forwarded_client(&h, &proxies), Some("1.2.3.4".parse().unwrap()));
        h.insert("x-forwarded-for", "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(forwarded_client(&h, &proxies), Some("2001:db8::1".parse().unwrap()));
        h.insert("x-forwarded-for", "n'importe quoi".parse().unwrap());
        assert_eq!(forwarded_client(&h, &proxies), None);
    }

    #[test]
    fn schema_du_mandataire_websocket_compris() {
        let mut h = HeaderMap::new();
        for (proto, https) in [("https", true), ("wss", true), ("WSS", true), ("http", false), ("ws", false)] {
            h.insert("x-forwarded-proto", proto.parse().unwrap());
            assert_eq!(forwarded_https(&h), https, "{proto}");
        }
        h.remove("x-forwarded-proto");
        assert!(!forwarded_https(&h));
    }

    #[test]
    fn origine_schema_compris() {
        let o = HeaderValue::from_static("https://nas.example.org");
        assert!(origin_ok(&o, Some("nas.example.org"), true));
        assert!(origin_ok(&o, Some("nas.example.org:443"), true));
        assert!(!origin_ok(&o, Some("autre.example.org"), true));
        assert!(!origin_ok(&HeaderValue::from_static("null"), Some("nas.example.org"), true));
        assert!(!origin_ok(&o, None, true));
        // Même hôte, autre schéma : refusé dans les deux sens.
        assert!(!origin_ok(&HeaderValue::from_static("http://nas.example.org"), Some("nas.example.org"), true));
        assert!(!origin_ok(&o, Some("nas.example.org"), false));
        // Préfixe trompeur : refusé (pas de `starts_with`).
        assert!(!origin_ok(&HeaderValue::from_static("https://nas.example.org.evil"), Some("nas.example.org"), true));
        assert!(origin_ok(&HeaderValue::from_static("http://127.0.0.1:8580"), Some("127.0.0.1:8580"), false));
        assert!(!origin_ok(&HeaderValue::from_static("http://127.0.0.1:8581"), Some("127.0.0.1:8580"), false));
    }

    #[test]
    fn cookie_dans_l_en_tete() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; rcm_session=abc; b=2".parse().unwrap());
        assert_eq!(session_token(&h, false).as_deref(), Some("abc"));
        // En HTTPS, le nom sans préfixe (posable par un sous-domaine) n'est pas lu.
        assert_eq!(session_token(&h, true), None);
        h.insert(header::COOKIE, "rcm_session=x; __Host-rcm_session=def".parse().unwrap());
        assert_eq!(session_token(&h, true).as_deref(), Some("def"));
        h.insert(header::COOKIE, "rcm_session=".parse().unwrap());
        assert_eq!(session_token(&h, false), None);
    }
}
