//! Client de l'API DNS de Cloudflare (v4), limité à une zone.
//!
//! Jeton porté en `Authorization: Bearer`, jamais journalisé (`ApiToken` masqué, erreurs
//! réseau sans adresse) ; aucune redirection suivie (l'en-tête secret ne part nulle part
//! ailleurs) ; délais de connexion et total ; réponses bornées lues en entier avant analyse ;
//! enregistrements écrits toujours en nuage gris (`proxied: false`), avec le commentaire du
//! gestionnaire.

use super::dns::{Existing, comment_for, srv_content};
use crate::config::ApiToken;
use rc_manager_shared::{DnsRecord, DnsType};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub const API: &str = "https://api.cloudflare.com/client/v4";
/// Réponse lue au plus.
const MAX_BODY: usize = 8 * 1024 * 1024;
/// Pages de 500 enregistrements lues au plus (5 000 enregistrements).
const MAX_PAGES: u32 = 10;
const PER_PAGE: u32 = 500;
const TOTAL: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Réseau, délai.
    Network(String),
    /// Réponse HTTP en erreur, ou `success: false` (codes de Cloudflare).
    Api(u16, String),
    /// Réponse illisible ou démesurée.
    Parse(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Network(e) => write!(f, "réseau : {e}"),
            DnsError::Api(s, e) => write!(f, "HTTP {s} : {e}"),
            DnsError::Parse(e) => write!(f, "réponse illisible : {e}"),
        }
    }
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsError>> + Send + 'a>>;

/// Fournisseur DNS : liste, création, mise à jour, suppression (Cloudflare ou simulation).
pub trait DnsApi: Send + Sync {
    fn list(&self) -> BoxFut<'_, Vec<Existing>>;
    fn create<'a>(&'a self, r: &'a DnsRecord) -> BoxFut<'a, ()>;
    fn update<'a>(&'a self, id: &'a str, r: &'a DnsRecord) -> BoxFut<'a, ()>;
    fn delete<'a>(&'a self, id: &'a str) -> BoxFut<'a, ()>;
}

pub struct Cloudflare {
    client: reqwest::Client,
    base: String,
    zone: String,
    token: ApiToken,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ApiMessage {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct ResultInfo {
    #[serde(default)]
    total_pages: u32,
}

#[derive(Deserialize)]
struct SrvData {
    #[serde(default)]
    priority: u16,
    #[serde(default)]
    weight: u16,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    target: String,
}

#[derive(Deserialize)]
struct Raw {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    data: Option<SrvData>,
    #[serde(default)]
    priority: Option<u16>,
}

impl Raw {
    fn into_existing(self) -> Existing {
        let content = match (self.kind.as_str(), &self.data) {
            ("SRV", Some(d)) => srv_content(self.priority.unwrap_or(d.priority), d.weight, d.port, &d.target),
            _ => self.content,
        };
        Existing {
            id: self.id,
            kind: self.kind,
            name: self.name.to_ascii_lowercase(),
            content,
            proxied: self.proxied,
            comment: self.comment,
        }
    }
}

/// Corps d'écriture : nuage gris, TTL automatique, commentaire du gestionnaire.
pub fn body(r: &DnsRecord) -> serde_json::Value {
    let comment = comment_for(r);
    match r.kind {
        DnsType::Srv => {
            let mut it = r.content.split(' ');
            let mut n = || it.next().and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
            let (priority, weight, port) = (n(), n(), n());
            let target = r.content.rsplit(' ').next().unwrap_or("");
            serde_json::json!({
                "type": "SRV", "name": r.name, "ttl": 1, "comment": comment,
                "data": { "priority": priority, "weight": weight, "port": port, "target": target },
            })
        }
        _ => serde_json::json!({
            "type": r.kind.code(), "name": r.name, "content": r.content, "ttl": 1, "proxied": false, "comment": comment,
        }),
    }
}

impl Cloudflare {
    pub fn new(token: ApiToken, zone_id: &str) -> Cloudflare {
        Self::with_base(token, zone_id, API, true)
    }

    /// Adresse de l'API remplacée (tests : faux Cloudflare en HTTP local).
    #[doc(hidden)]
    pub fn with_base(token: ApiToken, zone_id: &str, base: &str, https_only: bool) -> Cloudflare {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(15))
            .user_agent(concat!("rustcraft-manager/", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .build()
            .expect("client HTTP");
        Cloudflare { client, base: base.trim_end_matches('/').to_string(), zone: zone_id.to_string(), token }
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        json: Option<serde_json::Value>,
    ) -> Result<Envelope<T>, DnsError> {
        let url = format!("{}/zones/{}/dns_records{path}", self.base, self.zone);
        let fut = async {
            let mut req = self.client.request(method, &url).bearer_auth(self.token.expose());
            if let Some(j) = json {
                req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(j.to_string());
            }
            let mut res = req.send().await.map_err(net)?;
            let status = res.status().as_u16();
            let mut out = Vec::new();
            while let Some(chunk) = res.chunk().await.map_err(net)? {
                if out.len() + chunk.len() > MAX_BODY {
                    return Err(DnsError::Parse("réponse trop grande".into()));
                }
                out.extend_from_slice(&chunk);
            }
            let env: Envelope<T> = serde_json::from_slice(&out).map_err(|e| {
                if (200..300).contains(&status) {
                    DnsError::Parse(e.to_string())
                } else {
                    DnsError::Api(status, String::new())
                }
            })?;
            if !(200..300).contains(&status) || !env.success {
                let msg =
                    env.errors.iter().map(|e| format!("{} {}", e.code, e.message)).collect::<Vec<_>>().join(" ; ");
                // Le message de Cloudflare ne recopie pas le jeton ; borné quand même.
                return Err(DnsError::Api(status, msg.chars().take(300).collect()));
            }
            Ok(env)
        };
        tokio::time::timeout(TOTAL, fut).await.map_err(|_| DnsError::Network("délai dépassé".into()))?
    }
}

fn net(e: reqwest::Error) -> DnsError {
    DnsError::Network(e.without_url().to_string())
}

impl DnsApi for Cloudflare {
    fn list(&self) -> BoxFut<'_, Vec<Existing>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let mut page = 1;
            loop {
                let env: Envelope<Vec<Raw>> =
                    self.call(reqwest::Method::GET, &format!("?per_page={PER_PAGE}&page={page}"), None).await?;
                out.extend(env.result.unwrap_or_default().into_iter().map(Raw::into_existing));
                let total = env.result_info.map_or(1, |i| i.total_pages);
                if page >= total {
                    return Ok(out);
                }
                if page >= MAX_PAGES {
                    return Err(DnsError::Parse(format!("zone de plus de {} enregistrements", MAX_PAGES * PER_PAGE)));
                }
                page += 1;
            }
        })
    }
    fn create<'a>(&'a self, r: &'a DnsRecord) -> BoxFut<'a, ()> {
        Box::pin(
            async move { self.call::<serde_json::Value>(reqwest::Method::POST, "", Some(body(r))).await.map(|_| ()) },
        )
    }
    fn update<'a>(&'a self, id: &'a str, r: &'a DnsRecord) -> BoxFut<'a, ()> {
        Box::pin(async move {
            check_id(id)?;
            self.call::<serde_json::Value>(reqwest::Method::PUT, &format!("/{id}"), Some(body(r))).await.map(|_| ())
        })
    }
    fn delete<'a>(&'a self, id: &'a str) -> BoxFut<'a, ()> {
        Box::pin(async move {
            check_id(id)?;
            self.call::<serde_json::Value>(reqwest::Method::DELETE, &format!("/{id}"), None).await.map(|_| ())
        })
    }
}

/// Identifiant d'enregistrement lu chez Cloudflare (32 chiffres hexadécimaux) : rien d'autre
/// n'entre dans le chemin.
fn check_id(id: &str) -> Result<(), DnsError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(DnsError::Parse("identifiant d'enregistrement invalide".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corps_gris_et_commente() {
        let a = DnsRecord { kind: DnsType::A, name: "survie.example.com".into(), content: "203.0.113.7".into() };
        let b = body(&a);
        assert_eq!(b["proxied"], false);
        assert_eq!(b["ttl"], 1);
        assert!(b["comment"].as_str().unwrap().starts_with("rustcraft-manager "));
        let s = DnsRecord {
            kind: DnsType::Srv,
            name: "_minecraft._tcp.survie.example.com".into(),
            content: "0 5 25570 survie.example.com".into(),
        };
        let b = body(&s);
        assert_eq!(b["data"]["port"], 25570);
        assert_eq!(b["data"]["weight"], 5);
        assert_eq!(b["data"]["target"], "survie.example.com");
        assert!(b.get("proxied").is_none());
        // Relu depuis Cloudflare : même contenu, donc même empreinte (intact).
        let raw: Raw = serde_json::from_value(serde_json::json!({
            "id": "x", "type": "SRV", "name": "_minecraft._tcp.Survie.example.com", "content": "5 25570 survie.example.com",
            "priority": 0, "proxied": false, "comment": b["comment"],
            "data": { "priority": 0, "weight": 5, "port": 25570, "target": "survie.example.com" },
        }))
        .unwrap();
        assert!(raw.into_existing().ours_intact());
        assert!(check_id("0123456789abcdef0123456789abcdef").is_ok());
        for bad in ["", "../zones", "a/b", "a?b", &"a".repeat(65)] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
        assert_eq!(format!("{:?}", ApiToken::parse(&"t".repeat(40)).unwrap()), "ApiToken(masqué)");
    }
}
