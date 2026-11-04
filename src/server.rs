//! Boucle d'acceptation : hyper HTTP/1.1 avec minuterie (axum::serve n'en pose aucune).
//!
//! - en-têtes : [`Config::header_read_timeout`] (hyper démarre ce délai dès qu'il attend une
//!   tête, donc il borne aussi l'inactivité d'une connexion gardée ouverte, lu dans hyper 1.12
//!   `proto/h1/conn.rs`) ;
//! - corps et traitement : [`Config::request_timeout`] (intergiciel [`crate::http::guard`]) ;
//! - WebSocket : ping et fermeture après [`Config::ws_idle_timeout`] sans rien reçu ;
//! - plafond de connexions TCP simultanées : au-delà, la connexion est fermée à l'acceptation.
//!
//! [`Config::header_read_timeout`]: crate::config::Config::header_read_timeout
//! [`Config::request_timeout`]: crate::config::Config::request_timeout
//! [`Config::ws_idle_timeout`]: crate::config::Config::ws_idle_timeout

use crate::AppState;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tower::ServiceExt;

/// Attente des connexions en cours à l'arrêt.
const DRAIN: Duration = Duration::from_secs(10);

struct SlotInner {
    _permit: OwnedSemaphorePermit,
    ip: Option<IpAddr>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SlotInner {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            let mut m = self.per_ip.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(n) = m.get_mut(&ip) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&ip);
                }
            }
        }
    }
}

/// Place d'une connexion TCP (plafond global et par adresse), posée dans les extensions de
/// chaque requête : un WebSocket la garde pour toute sa durée.
#[derive(Clone)]
pub struct ConnSlot {
    _held: Arc<SlotInner>,
}

/// Sert jusqu'à `shutdown`. Tâches de fond : purge horaire (sessions expirées, rétention de
/// l'audit), résolution des mandataires désignés par nom. À l'arrêt : connexions terminées
/// proprement (10 s au plus), journal d'audit vidé.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let mut background = Vec::new();
    let db = state.db.clone();
    let retention = state.config.audit_retention_days;
    background.push(tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(3600));
        loop {
            t.tick().await;
            let _ = db.call(move |c, _| Ok(crate::db::purge(c, crate::db::now(), retention)?)).await;
        }
    }));
    if state.proxies.has_names() {
        // Première résolution avant d'accepter : refus par défaut d'ici là.
        state.proxies.refresh().await;
        let st = state.clone();
        background.push(tokio::spawn(async move {
            let mut t = tokio::time::interval(crate::proxies::REFRESH);
            t.tick().await;
            loop {
                t.tick().await;
                st.proxies.refresh().await;
            }
        }));
    }

    let app = crate::router(state.clone());
    let max = state.config.max_connections;
    let slots = Arc::new(Semaphore::new(max));
    let refused = Arc::new(AtomicU64::new(0));
    let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let per_ip_max = state.config.max_connections_per_ip;
    let (closing_tx, closing_rx) = watch::channel(false);
    let header_timeout = state.config.header_read_timeout;
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    // Plus de descripteurs (EMFILE…) : souffler un peu plutôt que boucler.
                    tracing::warn!("acceptation : {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if refused.fetch_add(1, Ordering::Relaxed).is_power_of_two() {
                tracing::warn!("plafond de {max} connexions atteint : connexion de {peer} fermée");
            }
            drop(stream);
            continue;
        };
        // Plafond par adresse (sauf mandataires de confiance, par qui passent tous les clients).
        let ip = crate::config::canonical_ip(peer.ip());
        let ip_slot = if state.proxies.contains(ip) {
            None
        } else {
            let mut m = per_ip.lock().unwrap_or_else(|p| p.into_inner());
            let n = m.entry(ip).or_insert(0);
            if *n >= per_ip_max {
                drop(m);
                if refused.fetch_add(1, Ordering::Relaxed).is_power_of_two() {
                    tracing::warn!("plafond de {per_ip_max} connexions par adresse atteint : {ip}");
                }
                drop(stream);
                continue;
            }
            *n += 1;
            Some(ip)
        };
        // La place vit tant que la connexion OU le WebSocket qui en est issu vit : hyper rend la
        // main à l'upgrade, le canal garde une copie de `ConnSlot` (revue I-C).
        let slot = ConnSlot { _held: Arc::new(SlotInner { _permit: permit, ip: ip_slot, per_ip: per_ip.clone() }) };
        let _ = stream.set_nodelay(true);
        let app = app.clone();
        let mut closing = closing_rx.clone();
        tokio::spawn(async move {
            let s2 = slot.clone();
            let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                let mut req = req.map(axum::body::Body::new);
                req.extensions_mut().insert(ConnectInfo(peer));
                req.extensions_mut().insert(s2.clone());
                app.clone().oneshot(req)
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.timer(TokioTimer::new()).header_read_timeout(header_timeout).keep_alive(true);
            let conn = builder.serve_connection(TokioIo::new(stream), svc).with_upgrades();
            tokio::pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = closing.changed() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
            }
            drop(slot);
        });
    }
    // Serveurs Minecraft : `save-all` puis `stop` (état voulu gardé en base pour la reprise),
    // avant de fermer les connexions, les tâches, l'audit et la base.
    state.servers.shutdown().await;
    let _ = closing_tx.send(true);
    // Les WebSocket ouverts se ferment aussi (ils tiennent leur place de connexion).
    let _ = state.closing.send(true);
    let _ = tokio::time::timeout(DRAIN, slots.acquire_many(max as u32)).await;
    for t in background {
        t.abort();
    }
    state.audit.flush().await;
    Ok(())
}
