//! IP publiques du gestionnaire : fixées par la configuration, sinon demandées au service de
//! trace de Cloudflare (`/cdn-cgi/trace`) joint par son adresse IP (IPv4 `1.1.1.1`, IPv6
//! `2606:4700:4700::1111`) : la famille de l'adresse vue est celle de la connexion, sans
//! dépendre du résolveur. HTTPS (certificat vérifié, adresses IP comprises), sans redirection,
//! réponse de 4 Kio au plus, 10 s au plus. Une adresse non publique (privée, CGNAT, locale) est
//! écartée : elle ne joindrait rien depuis Internet.

use std::net::IpAddr;
use std::time::Duration;

const V4_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const V6_URL: &str = "https://[2606:4700:4700::1111]/cdn-cgi/trace";
const MAX: usize = 4096;

/// Adresse joignable depuis Internet : ni privée, ni partagée (CGNAT 100.64/10), ni locale, ni
/// réservée ou de documentation ; IPv6 globale (2000::/3).
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if let Some(m) = v.to_ipv4_mapped() {
                return ip_is_public(IpAddr::V4(m));
            }
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// Ligne `ip=` de la réponse de trace, de la bonne famille et publique.
pub fn parse_trace(body: &str, v6: bool) -> Option<IpAddr> {
    let ip: IpAddr = body.lines().find_map(|l| l.strip_prefix("ip="))?.trim().parse().ok()?;
    (ip.is_ipv6() == v6 && ip_is_public(ip)).then_some(ip)
}

pub struct Detector {
    client: reqwest::Client,
}

impl Detector {
    pub fn new() -> Detector {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("rustcraft-manager/", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .build()
            .expect("client HTTP");
        Detector { client }
    }

    /// IP vue par Internet pour une famille (`None` : pas de connectivité ou adresse écartée).
    pub async fn detect(&self, v6: bool) -> Option<IpAddr> {
        let url = if v6 { V6_URL } else { V4_URL };
        let mut res = self.client.get(url).send().await.ok()?;
        if !res.status().is_success() {
            return None;
        }
        let mut out = Vec::new();
        while let Some(chunk) = res.chunk().await.ok()? {
            if out.len() + chunk.len() > MAX {
                return None;
            }
            out.extend_from_slice(&chunk);
        }
        parse_trace(&String::from_utf8_lossy(&out), v6)
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_publiques() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for ok in ["203.0.114.7", "8.8.8.8", "1.1.1.1", "2a01:e0a::1", "2606:4700::1", "::ffff:8.8.8.8"] {
            assert!(ip_is_public(ip(ok)), "{ok}");
        }
        for bad in [
            "10.0.0.1",
            "192.168.1.2",
            "172.16.0.1",
            "100.64.0.1",
            "100.127.255.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "203.0.113.7",
            "198.18.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!ip_is_public(ip(bad)), "{bad}");
        }
    }

    #[test]
    fn trace_lue() {
        let body = "fl=1\nh=1.1.1.1\nip=8.8.4.4\nts=1\n";
        assert_eq!(parse_trace(body, false), Some("8.8.4.4".parse().unwrap()));
        assert_eq!(parse_trace(body, true), None);
        assert_eq!(parse_trace("ip=10.0.0.2\n", false), None);
        assert_eq!(parse_trace("ip=2a01:e0a::5\n", true), Some("2a01:e0a::5".parse().unwrap()));
        assert_eq!(parse_trace("rien", false), None);
    }
}
