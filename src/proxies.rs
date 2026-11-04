//! Mandataires inverses de confiance : réseaux fixes (IP, CIDR) et noms d'hôte (`traefik`)
//! résolus toutes les [`REFRESH`] secondes.
//!
//! Un nom évite de faire confiance à tout un sous-réseau Docker (`172.16.0.0/12` : n'importe quel
//! conteneur de l'hôte pourrait alors écrire `X-Forwarded-For`). Refus par défaut : tant qu'un nom
//! n'est pas résolu, ou si sa résolution échoue, aucune adresse ne lui est accordée.
//!
//! Parades d'un nom court (mineur 3 de la seconde revue) : seules les adresses PRIVÉES résolues
//! sont retenues (boucle locale, RFC 1918, IPv6 locale unique ou de lien) — un nom qui partirait
//! vers un DNS public (domaine de recherche) ne donne jamais une adresse d'Internet ; la
//! résolution est refaite toutes les 5 s, ce qui borne la fenêtre où une adresse rendue par
//! Traefik et réattribuée à un autre conteneur reste de confiance. Limite connue : le réseau
//! Docker partagé avec Traefik doit lui être réservé (documenté dans le README).

use crate::config::{Cidr, ProxySpec, canonical_ip};
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Duration;

/// Période de résolution des noms (le conteneur Traefik peut changer d'adresse au redémarrage).
pub const REFRESH: Duration = Duration::from_secs(5);

/// Adresse acceptable pour un mandataire désigné par son nom : privée seulement.
pub fn private_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub struct TrustedProxies {
    nets: Vec<Cidr>,
    names: Vec<String>,
    resolved: RwLock<Vec<IpAddr>>,
}

impl TrustedProxies {
    pub fn new(specs: &[ProxySpec]) -> Self {
        let mut nets = Vec::new();
        let mut names = Vec::new();
        for s in specs {
            match s {
                ProxySpec::Net(c) => nets.push(*c),
                ProxySpec::Host(h) => names.push(h.clone()),
            }
        }
        TrustedProxies { nets, names, resolved: RwLock::new(Vec::new()) }
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty() && self.names.is_empty()
    }

    pub fn has_names(&self) -> bool {
        !self.names.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.nets.iter().any(|c| c.contains(ip))
            || self.resolved.read().unwrap_or_else(|p| p.into_inner()).iter().any(|a| canonical_ip(*a) == ip)
    }

    /// Résout chaque nom ; un nom qui ne se résout pas ne donne aucune adresse (refus par défaut).
    pub async fn refresh(&self) {
        let mut all = Vec::new();
        for name in &self.names {
            match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((name.as_str(), 0))).await {
                Ok(Ok(addrs)) => {
                    for ip in addrs.map(|a| a.ip()) {
                        if private_ip(ip) {
                            all.push(ip);
                        } else {
                            tracing::warn!("mandataire « {name} » : adresse publique {ip} ignorée");
                        }
                    }
                }
                _ => tracing::warn!("mandataire de confiance « {name} » : résolution impossible, refusé"),
            }
        }
        all.sort();
        all.dedup();
        *self.resolved.write().unwrap_or_else(|p| p.into_inner()) = all;
    }

    /// Réseaux plus larges qu'un /24 (IPv4) ou un /64 (IPv6) : à signaler au démarrage.
    pub fn broad_nets(&self) -> Vec<String> {
        self.nets.iter().filter(|c| c.prefix_len() < if c.is_ipv4() { 24 } else { 64 }).map(|c| c.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noms_resolus_refus_par_defaut() {
        let p = TrustedProxies::new(&[
            ProxySpec::parse("localhost").unwrap(),
            ProxySpec::parse("nexiste-pas.invalid").unwrap(),
            ProxySpec::parse("10.0.0.0/8").unwrap(),
        ]);
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(p.contains("10.1.2.3".parse().unwrap()));
        // Avant résolution : refusé.
        assert!(!p.contains(lo));
        p.refresh().await;
        assert!(p.contains(lo) || p.contains("::1".parse().unwrap()), "localhost résolu");
        assert!(!p.contains("192.168.1.1".parse().unwrap()));
        // Plus de nom résolu (le nom a disparu) : de nouveau refusé.
        let q = TrustedProxies::new(&[ProxySpec::parse("nexiste-pas.invalid").unwrap()]);
        q.refresh().await;
        assert!(!q.contains(lo));
    }

    /// Un nom ne peut désigner qu'une adresse privée (jamais une adresse d'Internet).
    #[test]
    fn noms_vers_adresses_privees_seulement() {
        for ok in ["127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.1.9", "::1", "fd12::1", "fe80::1", "::ffff:10.0.0.1"]
        {
            assert!(private_ip(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["8.8.8.8", "203.0.113.5", "172.32.0.1", "2001:db8::1", "2a01::1"] {
            assert!(!private_ip(bad.parse().unwrap()), "{bad}");
        }
        assert!(REFRESH <= Duration::from_secs(5));
    }

    #[test]
    fn reseaux_trop_larges_signales() {
        let p = TrustedProxies::new(&[
            ProxySpec::parse("172.16.0.0/12").unwrap(),
            ProxySpec::parse("172.20.0.0/24").unwrap(),
            ProxySpec::parse("10.0.0.2").unwrap(),
        ]);
        assert_eq!(p.broad_nets().len(), 1);
    }
}
