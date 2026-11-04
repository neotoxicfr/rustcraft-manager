//! Limite des tentatives (connexion, code TOTP, ré-authentification, jeton du premier compte), en
//! mémoire, RÉSERVÉE AVANT le travail coûteux.
//!
//! Chaque tentative réserve d'abord sa place ([`RateLimiter::reserve`]) : elle est comptée comme un
//! échec AVANT Argon2 et pardonnée au succès ([`Attempt::success`]). Contrôler puis compter après
//! (version précédente) laissait passer toutes les requêtes lancées en même temps : 50 000 requêtes
//! simultanées voyaient toutes un compteur à zéro (revue B1).
//!
//! Compteurs (revue B2) :
//! - (réseau, compte) : `max` échecs par fenêtre ;
//! - réseau seul : `4 × max` (essais sur beaucoup de comptes) ;
//! - IPv6 agrégée en plus par /56 (`16 × max`) et /48 (`64 × max`) : un /48 contient 65 536 /64,
//!   compter par /64 seulement laissait un abonné essayer des centaines de milliers de codes ;
//! - compte, toutes adresses : au-delà de [`ACCOUNT_SLOW_AFTER`] échecs, les essais passent UN PAR
//!   UN, espacés de plus en plus (jusqu'à [`MAX_SLOWDOWN`]) par un échéancier propre au compte :
//!   des requêtes simultanées reçoivent des créneaux successifs, pas la même attente (des `sleep`
//!   parallèles ne bornaient pas le débit, revue B-B) ; au-delà de [`MAX_QUEUE`] d'attente, refus ;
//! - plafond DUR par compte (second facteur, ré-authentification : [`ACCOUNT_HARD_CAP`]) : au-delà,
//!   plus aucun essai pour ce compte jusqu'à la fin de la fenêtre, d'où qu'il vienne (la passkey
//!   reste une issue). Le mot de passe n'a pas de plafond dur (pas de verrouillage de
//!   l'administrateur par un tiers), seulement l'échéancier ;
//! - requêtes en cours par réseau : au plus `inflight` (le reste : 429 immédiat).
//!
//! Réseau = adresse IPv4 (une IPv4 vue en IPv6 est ramenée en IPv4), ou préfixe /64 pour IPv6
//! (un abonné en reçoit au moins un /64 entier : compter par adresse exacte ne limiterait rien).
//! Compte = nom valide en minuscules, sinon `#invalid` (une seule clé pour tout ce qui n'est pas
//! un nom). Tables bornées : au-delà de `cap` entrées, les expirées sont purgées puis les plus
//! anciennes évincées.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Échecs tolérés sur un compte (toutes adresses) avant de ralentir.
pub const ACCOUNT_SLOW_AFTER: u32 = 10;
/// Attente maximale imposée par le ralentissement d'un compte.
pub const MAX_SLOWDOWN: Duration = Duration::from_secs(8);
/// Entrées par table, par défaut.
pub const DEFAULT_CAP: usize = 10_000;
/// Attente maximale dans l'échéancier d'un compte : au-delà, refus immédiat (429).
pub const MAX_QUEUE: Duration = Duration::from_secs(30);
/// Plafond dur d'échecs par compte et fenêtre, toutes adresses (second facteur, ré-auth).
pub const ACCOUNT_HARD_CAP: u32 = 10;

/// Préfixes /56 et /48 d'une IPv6 (rien pour une IPv4).
fn wide_of(net: Net) -> Option<(u64, u64)> {
    match net {
        Net::V6(p64) => Some((p64 >> 8, p64 >> 16)),
        Net::V4(_) => None,
    }
}

/// Réseau d'un client : IPv4, ou les 64 premiers bits d'une IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Net {
    V4(u32),
    V6(u64),
}

pub fn net_of(ip: IpAddr) -> Net {
    match crate::config::canonical_ip(ip) {
        IpAddr::V4(v4) => Net::V4(u32::from(v4)),
        IpAddr::V6(v6) => Net::V6((u128::from(v6) >> 64) as u64),
    }
}

/// Clé de compte : nom valide en minuscules, sinon `#invalid`.
pub fn account_key(name: &str) -> String {
    if rc_manager_shared::username_valid(name) { name.to_ascii_lowercase() } else { "#invalid".into() }
}

#[derive(Clone, Copy)]
struct Counter {
    failures: u32,
    since: Instant,
    touched: Instant,
}

impl Counter {
    fn fresh(now: Instant) -> Counter {
        Counter { failures: 0, since: now, touched: now }
    }
}

/// Table bornée de compteurs à fenêtre.
struct Table<K> {
    map: HashMap<K, Counter>,
}

impl<K: Eq + Hash + Clone> Table<K> {
    fn new() -> Self {
        Table { map: HashMap::new() }
    }

    fn get(&self, k: &K, now: Instant, window: Duration) -> u32 {
        self.map.get(k).filter(|c| now.duration_since(c.since) < window).map_or(0, |c| c.failures)
    }

    fn since(&self, k: &K) -> Option<Instant> {
        self.map.get(k).map(|c| c.since)
    }

    fn add(&mut self, k: K, now: Instant, window: Duration, cap: usize) -> u32 {
        if !self.map.contains_key(&k) && self.map.len() >= cap {
            self.make_room(now, window, cap);
        }
        let c = self.map.entry(k).or_insert_with(|| Counter::fresh(now));
        if now.duration_since(c.since) >= window {
            *c = Counter::fresh(now);
        }
        c.failures = c.failures.saturating_add(1);
        c.touched = now;
        c.failures
    }

    fn forgive(&mut self, k: &K) {
        if let Some(c) = self.map.get_mut(k) {
            c.failures = c.failures.saturating_sub(1);
        }
    }

    fn remove(&mut self, k: &K) {
        self.map.remove(k);
    }

    /// Purge des entrées expirées, puis éviction du plus ancien dixième si la table reste pleine.
    fn make_room(&mut self, now: Instant, window: Duration, cap: usize) {
        self.map.retain(|_, c| now.duration_since(c.since) < window);
        if self.map.len() < cap {
            return;
        }
        let mut ages: Vec<Instant> = self.map.values().map(|c| c.touched).collect();
        let cut = (cap / 10).max(1).min(ages.len() - 1);
        let (_, nth, _) = ages.select_nth_unstable(cut);
        let threshold = *nth;
        self.map.retain(|_, c| c.touched > threshold);
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

struct Inner {
    pairs: Table<(Net, String)>,
    nets: Table<Net>,
    nets56: Table<u64>,
    nets48: Table<u64>,
    accounts: Table<String>,
    /// Prochain créneau libre de chaque compte ralenti.
    slots: HashMap<String, Instant>,
    inflight: HashMap<Net, u32>,
}

pub struct RateLimiter {
    inner: Mutex<Inner>,
    max: u32,
    window: Duration,
    cap: usize,
    inflight_max: u32,
    /// Plafond dur d'échecs par compte (toutes adresses), s'il y en a un.
    account_cap: Option<u32>,
}

/// Refus d'une réservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Limite d'échecs atteinte : secondes avant de réessayer.
    TooMany(u64),
    /// Plafond dur du compte atteint (toutes adresses) : secondes avant la fin de la fenêtre.
    Locked(u64),
    /// Trop de requêtes en cours depuis ce réseau.
    Busy,
}

impl Refusal {
    pub fn retry_after(self) -> u64 {
        match self {
            Refusal::TooMany(s) | Refusal::Locked(s) => s,
            Refusal::Busy => 1,
        }
    }
}

/// Tentative réservée : comptée comme un échec tant que [`Attempt::success`] n'est pas appelé ;
/// libère sa place « en cours » en sortant de portée.
pub struct Attempt<'a> {
    lim: &'a RateLimiter,
    net: Net,
    account: String,
    delay: Duration,
}

impl Attempt<'_> {
    /// Attente imposée par le ralentissement du compte (à faire avant le travail coûteux).
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Attend le ralentissement s'il y en a un. Aucune minuterie sinon : un `sleep(0)` attend le
    /// prochain tic de l'horloge (jusqu'à ≈ 15 ms sous Windows ; mesuré : p99 de la connexion
    /// 19,6 → 31 ms).
    pub async fn wait(&self) {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
    }

    /// Succès : la paire (réseau, compte) repart de zéro ; pour le réseau et le compte, seul cet
    /// essai est pardonné (sinon un compte connu permettrait d'essayer les autres sans limite).
    pub fn success(self) {
        let mut g = self.lim.lock();
        g.pairs.remove(&(self.net, self.account.clone()));
        g.nets.forgive(&self.net);
        g.accounts.forgive(&self.account);
    }

    /// Tentative qui n'a pas eu lieu (serveur occupé, erreur interne) : rien n'est compté.
    pub fn cancel(self) {
        let mut g = self.lim.lock();
        g.pairs.forgive(&(self.net, self.account.clone()));
        g.nets.forgive(&self.net);
        g.accounts.forgive(&self.account);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let mut g = self.lim.lock();
        if let Some(n) = g.inflight.get_mut(&self.net) {
            *n -= 1;
            if *n == 0 {
                g.inflight.remove(&self.net);
            }
        }
    }
}

/// Attente imposée au n-ième échec d'un compte : rien jusqu'au seuil, puis 250 ms doublées à
/// chaque échec, plafonnées.
pub fn slowdown(account_failures: u32) -> Duration {
    if account_failures <= ACCOUNT_SLOW_AFTER {
        return Duration::ZERO;
    }
    let exp = (account_failures - ACCOUNT_SLOW_AFTER - 1).min(10);
    (Duration::from_millis(250) * (1u32 << exp)).min(MAX_SLOWDOWN)
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration, inflight_max: u32) -> Self {
        Self::with_cap(max, window, inflight_max, DEFAULT_CAP)
    }

    pub fn with_cap(max: u32, window: Duration, inflight_max: u32, cap: usize) -> Self {
        RateLimiter {
            inner: Mutex::new(Inner {
                pairs: Table::new(),
                nets: Table::new(),
                nets56: Table::new(),
                nets48: Table::new(),
                accounts: Table::new(),
                slots: HashMap::new(),
                inflight: HashMap::new(),
            }),
            max,
            window,
            cap: cap.max(2),
            inflight_max: inflight_max.max(1),
            account_cap: None,
        }
    }

    /// Ajoute un plafond dur d'échecs par compte, toutes adresses.
    pub fn with_account_cap(mut self, cap: u32) -> Self {
        self.account_cap = Some(cap.max(1));
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Réserve une tentative pour (adresse, clé de compte) : contrôle ET compte en une seule
    /// section critique. `account` vient de [`account_key`] (ou une clé interne `#…`).
    pub fn reserve(&self, ip: IpAddr, account: &str) -> Result<Attempt<'_>, Refusal> {
        let net = net_of(ip);
        let now = Instant::now();
        let (w, cap) = (self.window, self.cap);
        let mut g = self.lock();
        let pair = (net, account.to_string());
        let left = |since: Option<Instant>| since.map(|s| w.saturating_sub(now.duration_since(s)).as_secs().max(1));
        // Clés internes (`#passkey`, `#setup`…) : pas un compte, pas d'échéancier ni de plafond
        // communs (sinon un anonyme bloquerait tout le monde).
        let per_account = !account.starts_with('#');
        if per_account
            && let Some(cap_n) = self.account_cap
            && g.accounts.get(&account.to_string(), now, w) >= cap_n
        {
            return Err(Refusal::Locked(left(g.accounts.since(&account.to_string())).unwrap_or(1)));
        }
        let wide = wide_of(net);
        let mut wait = 0u64;
        let mut checks = vec![
            (g.pairs.get(&pair, now, w), g.pairs.since(&pair), self.max),
            (g.nets.get(&net, now, w), g.nets.since(&net), self.max.saturating_mul(4)),
        ];
        if let Some((p56, p48)) = wide {
            checks.push((g.nets56.get(&p56, now, w), g.nets56.since(&p56), self.max.saturating_mul(16)));
            checks.push((g.nets48.get(&p48, now, w), g.nets48.since(&p48), self.max.saturating_mul(64)));
        }
        for (count, since, max) in checks {
            if count >= max
                && let Some(s) = left(since)
            {
                wait = wait.max(s);
            }
        }
        if wait > 0 {
            return Err(Refusal::TooMany(wait));
        }
        // Échéancier du compte : créneau suivant, espacé de l'intervalle de ralentissement.
        let interval = if per_account {
            slowdown(g.accounts.get(&account.to_string(), now, w).saturating_add(1))
        } else {
            Duration::ZERO
        };
        let mut delay = Duration::ZERO;
        if !interval.is_zero() {
            let start = g.slots.get(account).copied().filter(|t| *t > now).unwrap_or(now);
            delay = start - now;
            if delay > MAX_QUEUE {
                return Err(Refusal::TooMany(delay.as_secs().max(1)));
            }
        }
        let inflight = g.inflight.get(&net).copied().unwrap_or(0);
        if inflight >= self.inflight_max {
            return Err(Refusal::Busy);
        }
        if !g.inflight.contains_key(&net) && g.inflight.len() >= cap {
            // Autant de réseaux en cours que la table en admet : refus plutôt que croissance.
            return Err(Refusal::Busy);
        }
        g.pairs.add(pair, now, w, cap);
        g.nets.add(net, now, w, cap);
        if let Some((p56, p48)) = wide {
            g.nets56.add(p56, now, w, cap);
            g.nets48.add(p48, now, w, cap);
        }
        g.accounts.add(account.to_string(), now, w, cap);
        if !interval.is_zero() {
            if !g.slots.contains_key(account) && g.slots.len() >= cap {
                g.slots.retain(|_, t| *t > now);
                if g.slots.len() >= cap {
                    return Err(Refusal::Busy);
                }
            }
            g.slots.insert(account.to_string(), now + delay + interval);
        }
        *g.inflight.entry(net).or_insert(0) += 1;
        Ok(Attempt { lim: self, net, account: account.to_string(), delay })
    }

    /// Entrées des tables (mesures, tests).
    pub fn sizes(&self) -> (usize, usize, usize) {
        let g = self.lock();
        (g.pairs.len(), g.nets.len(), g.accounts.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn limite_par_paire_puis_par_reseau() {
        let l = RateLimiter::new(3, Duration::from_secs(60), 100);
        for _ in 0..3 {
            l.reserve(ip("10.0.0.1"), "admin").unwrap();
        }
        let Err(Refusal::TooMany(wait)) = l.reserve(ip("10.0.0.1"), "admin") else { panic!("limite attendue") };
        assert!((1..=60).contains(&wait));
        // Autre adresse, même compte : pas bloquée (pas de verrouillage du compte).
        assert!(l.reserve(ip("10.0.0.2"), "admin").is_ok());
        // Même adresse, autres comptes : bloquée après 4 × 3 échecs au total.
        for i in 0..9 {
            assert!(l.reserve(ip("10.0.0.1"), &format!("u{i}")).is_ok(), "{i}");
        }
        assert!(l.reserve(ip("10.0.0.1"), "u-neuf").is_err());
    }

    /// Réservation AVANT le travail : N tentatives lancées en même temps (aucune encore finie)
    /// ne passent pas toutes ; au plus `max` (B1).
    #[test]
    fn reservation_avant_le_travail() {
        let l = RateLimiter::new(5, Duration::from_secs(60), 1000);
        let held: Vec<_> = (0..50).filter_map(|_| l.reserve(ip("10.0.0.9"), "admin").ok()).collect();
        assert_eq!(held.len(), 5);
    }

    #[test]
    fn requetes_en_cours_bornees_par_reseau() {
        let l = RateLimiter::new(1000, Duration::from_secs(60), 4);
        let held: Vec<_> = (0..4).map(|i| l.reserve(ip("10.0.0.1"), &format!("u{i}")).unwrap()).collect();
        assert_eq!(l.reserve(ip("10.0.0.1"), "u9").err(), Some(Refusal::Busy));
        // Un autre réseau n'est pas gêné.
        assert!(l.reserve(ip("10.0.0.2"), "u9").is_ok());
        drop(held);
        assert!(l.reserve(ip("10.0.0.1"), "u9").is_ok(), "places rendues en sortant de portée");
    }

    #[test]
    fn ipv6_par_64_et_ipv4_vue_en_ipv6() {
        let l = RateLimiter::new(2, Duration::from_secs(60), 100);
        l.reserve(ip("2001:db8:1:2::1"), "admin").unwrap();
        l.reserve(ip("2001:db8:1:2:ffff::9"), "admin").unwrap();
        assert!(l.reserve(ip("2001:db8:1:2::abcd"), "admin").is_err(), "même /64");
        assert!(l.reserve(ip("2001:db8:1:3::1"), "admin").is_ok(), "autre /64");
        l.reserve(ip("10.1.1.1"), "admin").unwrap();
        l.reserve(ip("::ffff:10.1.1.1"), "admin").unwrap();
        assert!(l.reserve(ip("10.1.1.1"), "admin").is_err(), "IPv4 vue en IPv6 = même adresse");
        assert_eq!(account_key("Admin"), "admin");
        assert_eq!(account_key("<script>"), "#invalid");
        assert_eq!(account_key(&"a".repeat(100)), "#invalid");
    }

    #[test]
    fn pardon_au_succes() {
        let l = RateLimiter::new(2, Duration::from_secs(60), 100);
        l.reserve(ip("10.0.0.1"), "admin").unwrap();
        l.reserve(ip("10.0.0.1"), "admin").unwrap().success();
        // Paire remise à zéro par le succès : deux nouveaux essais possibles.
        l.reserve(ip("10.0.0.1"), "admin").unwrap();
        l.reserve(ip("10.0.0.1"), "admin").unwrap();
        assert!(l.reserve(ip("10.0.0.1"), "admin").is_err());
    }

    #[test]
    fn fenetre_expiree() {
        let l = RateLimiter::new(1, Duration::from_millis(30), 100);
        l.reserve(ip("::1"), "x").unwrap();
        assert!(l.reserve(ip("::1"), "x").is_err());
        std::thread::sleep(Duration::from_millis(40));
        assert!(l.reserve(ip("::1"), "x").is_ok());
    }

    /// Revue B-B : l'échéancier du compte borne vraiment le débit. Des essais simultanés depuis
    /// des adresses toutes différentes reçoivent des créneaux SUCCESSIFS (jamais la même attente),
    /// espacés d'au moins l'intervalle de ralentissement ; au-delà de MAX_QUEUE, refus.
    #[test]
    fn echeancier_par_compte_borne_le_debit() {
        let l = RateLimiter::new(5, Duration::from_secs(3600), 100);
        let mut held = Vec::new();
        for i in 0..ACCOUNT_SLOW_AFTER {
            let a = l.reserve(ip(&format!("10.{i}.0.1")), "admin").unwrap();
            assert!(a.delay().is_zero());
            held.push(a);
        }
        let mut slots = Vec::new();
        let mut refused = false;
        for i in 0..200u32 {
            match l.reserve(ip(&format!("10.{}.{}.1", 100 + i / 200, i % 200)), "admin") {
                Ok(a) => {
                    slots.push(a.delay());
                    held.push(a);
                }
                Err(Refusal::TooMany(_)) => {
                    refused = true;
                    break;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert!(refused, "file du compte sans fin");
        assert!(slots.len() >= 2);
        for w in slots.windows(2) {
            assert!(w[1] >= w[0] + Duration::from_millis(240), "créneaux non espacés : {slots:?}");
        }
        assert!(*slots.last().unwrap() <= MAX_QUEUE);
        // Le mot de passe n'est jamais verrouillé (pas de plafond dur) ; les autres comptes ne
        // sont pas ralentis.
        assert!(l.reserve(ip("10.250.0.1"), "autre").unwrap().delay().is_zero());
    }

    /// Plafond dur par compte, toutes adresses (second facteur, ré-authentification).
    #[test]
    fn plafond_dur_par_compte() {
        let l = RateLimiter::new(5, Duration::from_secs(900), 100).with_account_cap(ACCOUNT_HARD_CAP);
        for i in 0..ACCOUNT_HARD_CAP {
            l.reserve(ip(&format!("2001:db8:{i:x}::1")), "admin").unwrap();
        }
        let r = l.reserve(ip("2001:db9::1"), "admin");
        assert!(matches!(r, Err(Refusal::Locked(s)) if s > 0), "{:?}", r.err());
        // Autre compte : libre.
        assert!(l.reserve(ip("2001:db9::1"), "autre").is_ok());
        // Sans plafond (mot de passe) : jamais Locked.
        let p = RateLimiter::new(5, Duration::from_secs(900), 100);
        for i in 0..30u32 {
            assert!(!matches!(p.reserve(ip(&format!("2001:db8:{i:x}::1")), "admin"), Err(Refusal::Locked(_))));
        }
    }

    /// IPv6 agrégée aussi par /56 et /48 : changer de /64 dans le même /56 ne remet pas à zéro.
    #[test]
    fn ipv6_par_56_et_48() {
        let l = RateLimiter::new(1, Duration::from_secs(900), 100);
        // /56 : 16 × max = 16 essais, chacun depuis un /64 neuf et pour un compte neuf.
        for i in 0..16u32 {
            l.reserve(ip(&format!("2001:db8:0:{i:x}::1")), &format!("u{i}")).unwrap();
        }
        assert!(l.reserve(ip("2001:db8:0:ff::1"), "neuf").is_err(), "même /56");
        // /48 : 64 essais au plus, répartis sur des /56 différents.
        let l = RateLimiter::new(1, Duration::from_secs(900), 100);
        for i in 0..64u32 {
            l.reserve(ip(&format!("2001:db8:0:{:x}::1", i * 256)), &format!("u{i}")).unwrap();
        }
        assert!(l.reserve(ip("2001:db8:0:ff00::1"), "neuf").is_err(), "même /48");
        assert!(l.reserve(ip("2001:db8:1::1"), "neuf").is_ok(), "autre /48");
    }

    /// Tables bornées : 10 000 réseaux distincts n'en gardent pas plus que la capacité.
    #[test]
    fn tables_bornees() {
        let l = RateLimiter::with_cap(5, Duration::from_secs(600), 100, 64);
        for i in 0..10_000u32 {
            let _ = l.reserve(IpAddr::V4(i.into()), &format!("u{}", i % 500));
        }
        let (p, n, a) = l.sizes();
        assert!(p <= 64 && n <= 64 && a <= 64, "{p} {n} {a}");
    }
}
