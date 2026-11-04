//! Journal d'audit écrit par une seule tâche, en lots (une transaction par lot), champs bornés.
//!
//! Les échecs (mot de passe, code TOTP, ré-authentification, jeton de création) sont AGRÉGÉS :
//! une ligne par (action, compte, adresse) et par minute, avec leur nombre (`count`), et au plus
//! [`MAX_FAILURE_KEYS`] clés distinctes par minute (le reste dans une ligne de débordement). Sans
//! cela, 50 000 essais par seconde écriraient des millions de lignes par jour. La rétention
//! (`audit_retention_days`) est appliquée par la purge horaire ([`crate::db::purge`]).
//!
//! L'envoi ne bloque jamais une requête : canal borné, événement compté puis abandonné s'il est
//! plein (signalé une fois dans le journal du processus).

use crate::db::{Db, now, write_tx};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Actions agrégées (échecs répétables à volonté par un attaquant).
pub const AGGREGATED: &[&str] = &[
    "login_failed",
    "login_totp_failed",
    "reauth_failed",
    "setup_bad_token",
    "passkey_login_failed",
    "second_factor_locked",
];
/// Clés d'échecs distinctes gardées par période d'agrégation.
pub const MAX_FAILURE_KEYS: usize = 64;
/// Bornes des champs (caractères).
pub const MAX_USERNAME: usize = 64;
pub const MAX_DETAIL: usize = 256;
pub const MAX_IP: usize = 64;
/// Taille d'un lot et cadence d'écriture.
const BATCH: usize = 64;
const TICK: Duration = Duration::from_secs(1);
/// Période d'agrégation des échecs.
pub const FAILURE_PERIOD: Duration = Duration::from_secs(60);
/// Capacité du canal.
const CHANNEL: usize = 4096;

#[derive(Debug, Clone)]
pub struct Event {
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub action: &'static str,
    pub detail: Option<String>,
    /// Adresse du client (chiffrée en base).
    pub ip: String,
    /// `User-Agent` (chiffré en base).
    pub user_agent: Option<String>,
}

impl Event {
    pub fn new(action: &'static str, ip: &str) -> Event {
        Event { user_id: None, username: None, action, detail: None, ip: ip.to_string(), user_agent: None }
    }
    /// Événement d'une requête : adresse réelle et `User-Agent` du client.
    pub fn client(action: &'static str, info: &crate::http::ClientInfo) -> Event {
        let mut e = Self::new(action, &info.ip_text());
        e.user_agent = info.user_agent.as_deref().map(str::to_string);
        e
    }
    pub fn user(mut self, id: Option<i64>, name: Option<&str>) -> Event {
        self.user_id = id;
        self.username = name.map(str::to_string);
        self
    }
    pub fn detail(mut self, d: &str) -> Event {
        self.detail = Some(d.to_string());
        self
    }
}

enum Msg {
    Event(i64, Event),
    Flush(oneshot::Sender<()>),
}

pub struct Audit {
    tx: mpsc::Sender<Msg>,
    dropped: Arc<AtomicU64>,
}

fn bound(s: Option<String>, max: usize) -> Option<String> {
    s.map(|s| if s.chars().count() > max { s.chars().take(max).collect() } else { s })
}

impl Audit {
    /// Lance la tâche d'écriture (doit être appelé dans le moteur tokio).
    pub fn spawn(db: Db) -> Audit {
        let (tx, rx) = mpsc::channel(CHANNEL);
        tokio::spawn(writer(db, rx));
        Audit { tx, dropped: Arc::new(AtomicU64::new(0)) }
    }

    /// Enregistre un événement (jamais de secret dedans : mot de passe, jeton, code).
    pub fn log(&self, ev: Event) {
        if self.tx.try_send(Msg::Event(now(), ev)).is_err() && self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!("journal d'audit saturé : événements abandonnés (compteur dans les mesures)");
        }
    }

    /// Événements perdus faute de place.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Écrit tout ce qui attend, échecs agrégés compris (arrêt, tests).
    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Msg::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

type FailKey = (&'static str, Option<String>, String);

/// Échecs agrégés d'une clé : premier instant, compte, nombre, premier `User-Agent`.
type FailAgg = (i64, Option<i64>, i64, Option<String>);

#[derive(Default)]
struct Pending {
    rows: Vec<(i64, Event, i64)>,
    failures: HashMap<FailKey, FailAgg>,
}

impl Pending {
    fn push(&mut self, ts: i64, mut ev: Event) {
        ev.username = bound(ev.username.take(), MAX_USERNAME);
        ev.detail = bound(ev.detail.take(), MAX_DETAIL);
        ev.ip = bound(Some(std::mem::take(&mut ev.ip)), MAX_IP).unwrap_or_default();
        ev.user_agent = bound(ev.user_agent.take(), crate::http::MAX_USER_AGENT);
        if !AGGREGATED.contains(&ev.action) {
            self.rows.push((ts, ev, 1));
            return;
        }
        let mut key = (ev.action, ev.username.clone(), ev.ip.clone());
        if !self.failures.contains_key(&key) && self.failures.len() >= MAX_FAILURE_KEYS {
            // Débordement : une ligne par action, sans compte ni adresse.
            key = (ev.action, None, "*".into());
        }
        let e = self.failures.entry(key).or_insert((ts, ev.user_id, 0, ev.user_agent));
        e.2 += 1;
    }

    fn take_rows(&mut self, with_failures: bool) -> Vec<(i64, Event, i64)> {
        let mut out = std::mem::take(&mut self.rows);
        if with_failures {
            for ((action, username, ip), (ts, user_id, count, user_agent)) in self.failures.drain() {
                out.push((ts, Event { user_id, username, action, detail: None, ip, user_agent }, count));
            }
        }
        out
    }
}

/// Valeur chiffrée d'un champ de l'audit (données associées « audit_log:<colonne>:<id> »).
/// L'adresse et le `User-Agent` ne sont jamais écrits en clair (jamais de repli en clair sur
/// échec de chiffrement) ; `Keys::encrypt` ne peut pas échouer sur ces tailles.
pub fn seal(keys: &crate::crypto::Keys, column: &str, id: i64, value: &str) -> String {
    keys.encrypt(&crate::crypto::aad("audit_log", column, id), value.as_bytes())
}

/// Lit un champ chiffré de l'audit (`None` si absent ou indéchiffrable : échec fermé).
pub fn open(keys: &crate::crypto::Keys, column: &str, id: i64, stored: Option<&str>) -> Option<String> {
    let plain = keys.decrypt(&crate::crypto::aad("audit_log", column, id), stored?).ok()?;
    String::from_utf8(plain).ok()
}

async fn write(db: &Db, rows: Vec<(i64, Event, i64)>) {
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    let r = db
        .call(move |c, keys| {
            let tx = write_tx(c)?;
            {
                // Identifiants choisis ici (seule tâche qui écrit l'audit, verrou d'écriture tenu
                // par BEGIN IMMEDIATE) : ils entrent dans les données associées du chiffrement.
                let mut id: i64 = tx.query_row("SELECT coalesce(max(id), 0) FROM audit_log", [], |r| r.get(0))?;
                let mut s = tx.prepare_cached(
                    "INSERT INTO audit_log (id, ts, user_id, username, action, detail, ip, user_agent, count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )?;
                for (ts, e, count) in &rows {
                    id += 1;
                    let ip = seal(keys, "ip", id, &e.ip);
                    let ua = e.user_agent.as_deref().map(|u| seal(keys, "user_agent", id, u));
                    s.execute(rusqlite::params![id, ts, e.user_id, e.username, e.action, e.detail, ip, ua, count])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await;
    if r.is_err() {
        tracing::error!("journal d'audit : lot de {n} lignes non écrit");
    }
}

/// Tâche d'écriture. Aucune minuterie tant que rien n'attend (pas de réveil au repos) : une
/// échéance est posée au premier événement en attente (1 s pour les lignes ordinaires, 60 s pour
/// les échecs agrégés).
async fn writer(db: Db, mut rx: mpsc::Receiver<Msg>) {
    use tokio::time::Instant;
    let mut p = Pending::default();
    let mut rows_due: Option<Instant> = None;
    let mut fails_due: Option<Instant> = None;
    loop {
        let next = match (rows_due, fails_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        tokio::select! {
            m = rx.recv() => match m {
                Some(Msg::Event(ts, ev)) => {
                    let failure = AGGREGATED.contains(&ev.action);
                    p.push(ts, ev);
                    if failure {
                        fails_due.get_or_insert_with(|| Instant::now() + FAILURE_PERIOD);
                    } else {
                        rows_due.get_or_insert_with(|| Instant::now() + TICK);
                    }
                    if p.rows.len() >= BATCH {
                        write(&db, p.take_rows(false)).await;
                        rows_due = None;
                    }
                }
                Some(Msg::Flush(done)) => {
                    write(&db, p.take_rows(true)).await;
                    (rows_due, fails_due) = (None, None);
                    let _ = done.send(());
                }
                None => {
                    write(&db, p.take_rows(true)).await;
                    return;
                }
            },
            _ = tokio::time::sleep_until(next.unwrap_or_else(Instant::now)), if next.is_some() => {
                let now = Instant::now();
                let fails = fails_due.is_some_and(|d| d <= now);
                write(&db, p.take_rows(fails)).await;
                rows_due = None;
                if fails {
                    fails_due = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lignes de l'audit, adresse déchiffrée (et vérifiée chiffrée en base).
    fn rows(db: &Db) -> Vec<(String, Option<String>, String, i64)> {
        let raw: Vec<(i64, String, Option<String>, String, i64)> = db.with(|c| {
            let mut s = c.prepare("SELECT id, action, username, ip, count FROM audit_log ORDER BY id").unwrap();
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        });
        raw.into_iter()
            .map(|(id, a, u, ip, n)| {
                assert!(ip.starts_with("v1:"), "adresse en clair dans l'audit : {ip}");
                (a, u, open(db.keys(), "ip", id, Some(&ip)).expect("adresse déchiffrable"), n)
            })
            .collect()
    }

    /// Adresse et User-Agent chiffrés, liés à leur ligne et à leur colonne.
    #[tokio::test]
    async fn adresse_et_user_agent_chiffres() {
        let db = Db::open_memory().unwrap();
        let a = Audit::spawn(db.clone());
        let mut e = Event::new("login", "203.0.113.9").user(Some(1), Some("admin"));
        e.user_agent = Some(format!("Mozilla/5.0 {}", "x".repeat(2000)));
        a.log(e);
        a.flush().await;
        let (id, ip, ua): (i64, String, String) = db.with(|c| {
            c.query_row("SELECT id, ip, user_agent FROM audit_log", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
        });
        assert!(ip.starts_with("v1:") && !ip.contains("203.0.113.9"));
        assert!(ua.starts_with("v1:") && !ua.contains("Mozilla"));
        assert_eq!(open(db.keys(), "ip", id, Some(&ip)).as_deref(), Some("203.0.113.9"));
        let ua = open(db.keys(), "user_agent", id, Some(&ua)).unwrap();
        assert!(ua.starts_with("Mozilla/5.0") && ua.len() == crate::http::MAX_USER_AGENT, "{}", ua.len());
        // Recopié sur une autre ligne ou dans une autre colonne : refusé.
        assert_eq!(open(db.keys(), "ip", id + 1, Some(&ip)), None);
        assert_eq!(open(db.keys(), "user_agent", id, Some(&ip)), None);
    }

    /// 50 000 échecs depuis 10 000 adresses : quelques dizaines de lignes, pas 50 000.
    #[tokio::test]
    async fn echecs_agreges_et_bornes() {
        let db = Db::open_memory().unwrap();
        let a = Audit::spawn(db.clone());
        for i in 0..50_000u32 {
            a.log(
                Event::new("login_failed", &format!("10.0.{}.{}", (i % 10_000) / 256, i % 256))
                    .user(None, Some("admin")),
            );
            if i % 500 == 0 {
                tokio::task::yield_now().await;
            }
        }
        a.flush().await;
        let lost = a.dropped() as i64;
        a.log(Event::new("login", "10.0.0.1").user(Some(1), Some(&"x".repeat(500))).detail(&"d".repeat(900)));
        a.flush().await;
        let r = rows(&db);
        let total: i64 = r.iter().filter(|x| x.0 == "login_failed").map(|x| x.3).sum();
        assert_eq!(total + lost, 50_000, "chaque échec compté ou signalé perdu");
        assert!(r.len() <= MAX_FAILURE_KEYS + 2, "{} lignes", r.len());
        assert!(r.iter().any(|x| x.2 == "*"), "ligne de débordement");
        let login = r.iter().find(|x| x.0 == "login").unwrap();
        assert_eq!(login.1.as_ref().unwrap().chars().count(), MAX_USERNAME);
        let detail: String =
            db.with(|c| c.query_row("SELECT detail FROM audit_log WHERE action = 'login'", [], |r| r.get(0)).unwrap());
        assert_eq!(detail.chars().count(), MAX_DETAIL);
    }

    #[tokio::test]
    async fn evenements_ordinaires_un_par_ligne() {
        let db = Db::open_memory().unwrap();
        let a = Audit::spawn(db.clone());
        for _ in 0..3 {
            a.log(Event::new("logout", "::1").user(Some(1), Some("admin")));
        }
        a.flush().await;
        assert_eq!(rows(&db).len(), 3);
    }
}
