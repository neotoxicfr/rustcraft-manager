//! Adresse publique des serveurs : nom (FQDN) et mode, enregistrements DNS attendus,
//! synchronisation avec Cloudflare (aperçu, application, reprise au démarrage, sans jamais
//! écraser ce qui a été posé ou retouché à la main), IP publiques, aiguilleur, test de
//! joignabilité.
//!
//! Sans jeton Cloudflare, rien n'est écrit chez personne : l'interface montre les
//! enregistrements exacts à créer à la main.

pub mod cloudflare;
pub mod dns;
pub mod handshake;
pub mod publicip;
pub mod router;

pub use publicip::ip_is_public;

use crate::AppState;
use crate::audit::Event;
use crate::db::{Db, now, write_tx};
use crate::error::AppError;
use crate::paths::ServerId;
use crate::servers::Manager;
use axum::http::StatusCode;
use cloudflare::DnsApi;
use rc_manager_shared::*;
use rusqlite::params;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

/// IP publiques redemandées à cet intervalle (une IP de box change) ; synchronisation seulement
/// si les enregistrements attendus changent.
pub const IP_REFRESH: Duration = Duration::from_secs(15 * 60);
/// Tests de joignabilité simultanés, au plus.
const TESTS: usize = 2;
const TEST_STEP: Duration = Duration::from_secs(5);

type Addresses = Arc<RwLock<BTreeMap<ServerId, AddressSetting>>>;

pub struct Network {
    zone: Option<String>,
    router_port: Option<u16>,
    fixed_v4: Option<Ipv4Addr>,
    fixed_v6: Option<Ipv6Addr>,
    detect: bool,
    dns: RwLock<Option<Arc<dyn DnsApi>>>,
    detector: publicip::Detector,
    ips: RwLock<(Option<PublicIp>, Option<PublicIp>)>,
    addresses: Addresses,
    /// Une synchronisation (ou application) à la fois.
    sync_lock: tokio::sync::Mutex<()>,
    last_sync: Mutex<Option<SyncSummary>>,
    tests: tokio::sync::Semaphore,
    /// Réveille la boucle de synchronisation (tests).
    pub kick: Arc<tokio::sync::Notify>,
}

fn mode_code(m: AddressMode) -> &'static str {
    match m {
        AddressMode::Record => "record",
        AddressMode::Router => "router",
    }
}

fn err(status: StatusCode, code: ErrorCode) -> AppError {
    AppError::new(status, code)
}

impl Network {
    pub fn new(config: &crate::config::Config, db: &Db) -> Network {
        let dns: Option<Arc<dyn DnsApi>> = config
            .cloudflare
            .as_ref()
            .map(|c| Arc::new(cloudflare::Cloudflare::new(c.token.clone(), &c.zone_id)) as Arc<dyn DnsApi>);
        let fixed = |ip: Option<IpAddr>| ip.map(|ip| PublicIp { ip: ip.to_string(), source: IpSource::Fixed });
        let addresses = db.with(|c| {
            let mut s = match c.prepare("SELECT server_id, hostname, mode FROM server_addresses") {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("adresses : {e}");
                    return BTreeMap::new();
                }
            };
            s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
                .map(|it| {
                    it.filter_map(Result::ok)
                        .filter_map(|(id, hostname, mode)| {
                            let mode = match mode.as_str() {
                                "record" => AddressMode::Record,
                                "router" => AddressMode::Router,
                                _ => return None,
                            };
                            Some((ServerId::from_db(id)?, AddressSetting { hostname, mode }))
                        })
                        .collect()
                })
                .unwrap_or_default()
        });
        Network {
            zone: config.dns_zone.clone(),
            router_port: config.router.map(|r| r.port),
            fixed_v4: config.public_ipv4,
            fixed_v6: config.public_ipv6,
            detect: config.public_ip_detect,
            dns: RwLock::new(dns),
            detector: publicip::Detector::new(),
            ips: RwLock::new((fixed(config.public_ipv4.map(IpAddr::V4)), fixed(config.public_ipv6.map(IpAddr::V6)))),
            addresses: Arc::new(RwLock::new(addresses)),
            sync_lock: tokio::sync::Mutex::new(()),
            last_sync: Mutex::new(None),
            tests: tokio::sync::Semaphore::new(TESTS),
            kick: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Fournisseur DNS remplacé (tests : faux Cloudflare).
    #[doc(hidden)]
    pub fn set_dns(&self, dns: Option<Arc<dyn DnsApi>>) {
        *self.dns.write().unwrap_or_else(|p| p.into_inner()) = dns;
    }

    fn api(&self) -> Option<Arc<dyn DnsApi>> {
        self.dns.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// IP publiques remplacées (tests).
    #[doc(hidden)]
    pub fn set_ips(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) {
        let d = |ip: Option<IpAddr>| ip.map(|ip| PublicIp { ip: ip.to_string(), source: IpSource::Detected });
        *self.ips.write().unwrap_or_else(|p| p.into_inner()) = (d(v4.map(IpAddr::V4)), d(v6.map(IpAddr::V6)));
    }

    pub fn router_port(&self) -> Option<u16> {
        self.router_port
    }

    fn ips(&self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        let g = self.ips.read().unwrap_or_else(|p| p.into_inner());
        (g.0.as_ref().and_then(|p| p.ip.parse().ok()), g.1.as_ref().and_then(|p| p.ip.parse().ok()))
    }

    /// Redemande les IP publiques non fixées. Un échec garde la dernière IP connue (une coupure
    /// passagère ne doit pas retirer les enregistrements).
    pub async fn refresh_ips(&self) {
        if !self.detect {
            return;
        }
        let (v4, v6) = tokio::join!(
            async { if self.fixed_v4.is_none() { self.detector.detect(false).await } else { None } },
            async { if self.fixed_v6.is_none() { self.detector.detect(true).await } else { None } },
        );
        let mut guard = self.ips.write().unwrap_or_else(|p| p.into_inner());
        let g = &mut *guard;
        for (slot, ip) in [(&mut g.0, v4), (&mut g.1, v6)] {
            if let Some(ip) = ip {
                let new = PublicIp { ip: ip.to_string(), source: IpSource::Detected };
                if slot.as_ref() != Some(&new) {
                    tracing::info!("IP publique détectée : {ip}");
                }
                *slot = Some(new);
            }
        }
    }

    pub fn info(&self) -> NetworkInfo {
        let (ipv4, ipv6) = self.ips.read().unwrap_or_else(|p| p.into_inner()).clone();
        NetworkInfo {
            ipv4,
            ipv6,
            cloudflare: self.api().is_some(),
            zone: self.zone.clone(),
            router_port: self.router_port,
            last_sync: self.last_sync.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        }
    }

    pub fn address(&self, id: ServerId) -> Option<AddressSetting> {
        self.addresses.read().unwrap_or_else(|p| p.into_inner()).get(&id).cloned()
    }

    /// Adresses des serveurs existants, `over` remplaçant celle d'un serveur (aperçu).
    fn current(
        &self,
        mgr: &Manager,
        over: Option<(ServerId, Option<&AddressSetting>)>,
    ) -> Vec<(ServerId, AddressSetting)> {
        let mut m: BTreeMap<ServerId, AddressSetting> =
            self.addresses.read().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some((id, s)) = over {
            match s {
                Some(s) => {
                    m.insert(id, s.clone());
                }
                None => {
                    m.remove(&id);
                }
            }
        }
        m.into_iter().filter(|(id, _)| mgr.get(*id).is_some()).collect()
    }

    fn records(&self, mgr: &Manager, id: ServerId, s: &AddressSetting) -> Vec<DnsRecord> {
        let port = mgr.get(id).map_or(MINECRAFT_PORT, |srv| srv.row().port);
        let (v4, v6) = self.ips();
        dns::records_for(s, port, self.router_port, v4, v6)
    }

    /// Enregistrements attendus de tous les serveurs et leurs noms.
    fn desired(
        &self,
        mgr: &Manager,
        over: Option<(ServerId, Option<&AddressSetting>)>,
    ) -> (Vec<DnsRecord>, BTreeSet<String>) {
        let cur = self.current(mgr, over);
        let names = cur.iter().map(|(_, s)| s.hostname.clone()).collect();
        let mut recs: Vec<DnsRecord> = cur.iter().flat_map(|(id, s)| self.records(mgr, *id, s)).collect();
        recs.sort();
        (recs, names)
    }

    fn unknown_types(&self) -> Vec<DnsType> {
        let (v4, v6) = self.ips();
        let mut u = Vec::new();
        if v4.is_none() {
            u.push(DnsType::A);
        }
        if v6.is_none() {
            u.push(DnsType::Aaaa);
        }
        u
    }

    /// Réglage validé et normalisé : FQDN, dans la zone, aiguilleur actif pour ce mode, nom libre.
    pub fn validate(&self, mgr: &Manager, id: ServerId, s: &AddressSetting) -> Result<AddressSetting, AppError> {
        let hostname = normalize_hostname(&s.hostname);
        if !hostname_valid(&hostname) {
            return Err(AppError::unprocessable(ErrorCode::InvalidHostname));
        }
        if let Some(z) = &self.zone
            && hostname != *z
            && !hostname.ends_with(&format!(".{z}"))
        {
            return Err(AppError::unprocessable(ErrorCode::OutsideZone));
        }
        if s.mode == AddressMode::Router && self.router_port.is_none() {
            return Err(AppError::conflict(ErrorCode::RouterDisabled));
        }
        if self.current(mgr, None).iter().any(|(o, a)| *o != id && a.hostname == hostname) {
            return Err(AppError::conflict(ErrorCode::AlreadyExists));
        }
        Ok(AddressSetting { hostname, mode: s.mode })
    }

    pub fn view(&self, mgr: &Manager, id: ServerId) -> AddressView {
        let address = self.address(id);
        let records = address.as_ref().map(|s| self.records(mgr, id, s)).unwrap_or_default();
        AddressView { address, records, network: self.info() }
    }

    /// Aperçu de ce que ferait le réglage `next` pour ce serveur (rien n'est écrit).
    pub async fn preview(
        &self,
        mgr: &Manager,
        id: ServerId,
        next: Option<&AddressSetting>,
    ) -> Result<AddressPreview, AppError> {
        let records = next.map(|s| self.records(mgr, id, s)).unwrap_or_default();
        let Some(api) = self.api() else {
            let digest = dns::digest(&records, None, &[]);
            return Ok(AddressPreview { records, changes: None, conflicts: Vec::new(), digest });
        };
        let (want, names) = self.desired(mgr, Some((id, next)));
        let existing = api.list().await.map_err(|e| {
            tracing::warn!("Cloudflare : {e}");
            err(StatusCode::BAD_GATEWAY, ErrorCode::DnsFailed)
        })?;
        let plan = dns::plan(&want, &existing, &names, &self.unknown_types());
        let changes = plan.changes();
        let digest = dns::digest(&records, Some(&changes), &plan.conflicts);
        Ok(AddressPreview { records, changes: Some(changes), conflicts: plan.conflicts, digest })
    }

    /// Applique le réglage montré par l'aperçu (`digest` identique, sinon 409) : enregistré en
    /// base, puis changements chez Cloudflare (s'il y a un jeton), chacun audité.
    pub async fn apply(
        &self,
        st: &AppState,
        id: ServerId,
        req: &AddressRequest,
        who: (i64, &str, &crate::http::ClientInfo),
    ) -> Result<AddressApplied, AppError> {
        let mgr = &st.servers;
        let next = req.address.as_ref().map(|s| self.validate(mgr, id, s)).transpose()?;
        let _g = self.sync_lock.lock().await;
        let pre = self.preview(mgr, id, next.as_ref()).await?;
        if req.digest.as_deref() != Some(pre.digest.as_str()) {
            return Err(AppError::conflict(ErrorCode::PreviewOutdated));
        }
        let (n2, user) = (next.clone(), who.0);
        st.db
            .call(move |c, _| {
                let tx = write_tx(c)?;
                match &n2 {
                    Some(s) => {
                        tx.execute(
                            "INSERT INTO server_addresses (server_id, hostname, mode, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, ?5)
                             ON CONFLICT(server_id) DO UPDATE SET hostname = ?2, mode = ?3, updated_at = ?4, updated_by = ?5",
                            params![id.get(), s.hostname, mode_code(s.mode), now(), user],
                        )
                        .map_err(|e| match e {
                            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                                AppError::conflict(ErrorCode::AlreadyExists)
                            }
                            e => e.into(),
                        })?;
                    }
                    None => {
                        tx.execute("DELETE FROM server_addresses WHERE server_id = ?1", [id.get()])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        {
            let mut a = self.addresses.write().unwrap_or_else(|p| p.into_inner());
            match &next {
                Some(s) => a.insert(id, s.clone()),
                None => a.remove(&id),
            };
        }
        let detail = match &next {
            Some(s) => format!("{id} {} {}", s.hostname, mode_code(s.mode)),
            None => format!("{id} -"),
        };
        st.audit.log(Event::client("address_changed", who.2).user(Some(who.0), Some(who.1)).detail(&detail));
        let (applied, sync_failed) = match self.api() {
            Some(api) => {
                let (want, names) = self.desired(mgr, None);
                let existing = api.list().await;
                match existing {
                    Ok(existing) => {
                        let plan = dns::plan(&want, &existing, &names, &self.unknown_types());
                        self.execute(st, api.as_ref(), plan, Some(who)).await
                    }
                    Err(e) => {
                        self.failed(st, &e, Some(who));
                        (Vec::new(), true)
                    }
                }
            }
            None => (Vec::new(), false),
        };
        Ok(AddressApplied { view: self.view(mgr, id), applied, conflicts: pre.conflicts, sync_failed })
    }

    fn event(action: &'static str, who: Option<(i64, &str, &crate::http::ClientInfo)>) -> Event {
        match who {
            Some((uid, name, info)) => Event::client(action, info).user(Some(uid), Some(name)),
            None => Event::new(action, ""),
        }
    }

    fn failed(&self, st: &AppState, e: &cloudflare::DnsError, who: Option<(i64, &str, &crate::http::ClientInfo)>) {
        tracing::warn!("Cloudflare : {e}");
        st.audit.log(Self::event("dns_sync_failed", who).detail(&e.to_string()));
        *self.last_sync.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(SyncSummary { at: now(), applied: 0, conflicts: 0, failed: true });
    }

    /// Exécute un plan dans l'ordre ; s'arrête au premier échec. Rend (fait, échec).
    async fn execute(
        &self,
        st: &AppState,
        api: &dyn DnsApi,
        plan: dns::Plan,
        who: Option<(i64, &str, &crate::http::ClientInfo)>,
    ) -> (Vec<DnsChange>, bool) {
        let mut done = Vec::new();
        for (change, id) in &plan.changes {
            let r = &change.record;
            let res = match (change.kind, id) {
                (ChangeKind::Create, _) => api.create(r).await,
                (ChangeKind::Update, Some(id)) => api.update(id, r).await,
                (ChangeKind::Delete, Some(id)) => api.delete(id).await,
                _ => continue,
            };
            if let Err(e) = res {
                self.failed(st, &e, who);
                return (done, true);
            }
            let action = match change.kind {
                ChangeKind::Create => "dns_record_created",
                ChangeKind::Update => "dns_record_updated",
                ChangeKind::Delete => "dns_record_deleted",
            };
            st.audit.log(Self::event(action, who).detail(&format!("{} {} {}", r.kind.code(), r.name, r.content)));
            done.push(change.clone());
        }
        for c in &plan.conflicts {
            tracing::warn!(
                "DNS : {} {} laissé tel quel ({:?}, en place : {})",
                c.record.kind.code(),
                c.record.name,
                c.reason,
                c.existing
            );
        }
        *self.last_sync.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(SyncSummary { at: now(), applied: done.len(), conflicts: plan.conflicts.len(), failed: false });
        (done, false)
    }

    /// Synchronisation complète (démarrage, IP changée, port changé, serveur supprimé).
    /// `Ok(false)` : échec (Cloudflare), à refaire.
    pub async fn sync(&self, st: &AppState) -> bool {
        let Some(api) = self.api() else { return true };
        let _g = self.sync_lock.lock().await;
        let (want, names) = self.desired(&st.servers, None);
        match api.list().await {
            Ok(existing) => {
                let plan = dns::plan(&want, &existing, &names, &self.unknown_types());
                !self.execute(st, api.as_ref(), plan, None).await.1
            }
            Err(e) => {
                self.failed(st, &e, None);
                false
            }
        }
    }

    /// Routes de l'aiguilleur (serveurs en mode aiguilleur seulement).
    pub fn routes(&self, mgr: Arc<Manager>) -> Arc<dyn router::Routes> {
        Arc::new(RouterRoutes { addresses: self.addresses.clone(), mgr })
    }

    /// Test de joignabilité : résolution du nom, connexion TCP au port joint, ping de statut.
    pub async fn test(&self, mgr: &Manager, id: ServerId) -> Result<ReachTest, AppError> {
        let s = self.address(id).ok_or_else(|| AppError::unprocessable(ErrorCode::InvalidHostname))?;
        let _permit = self.tests.try_acquire().map_err(|_| AppError::busy())?;
        let port = match s.mode {
            AddressMode::Record => mgr.get(id).map_or(MINECRAFT_PORT, |srv| srv.row().port),
            AddressMode::Router => self.router_port.ok_or_else(|| AppError::conflict(ErrorCode::RouterDisabled))?,
        };
        let (v4, v6) = self.ips();
        let mut out = ReachTest {
            resolved: Vec::new(),
            matches_public: false,
            port,
            connect_ms: None,
            status: None,
            failed: None,
        };
        let addrs: Vec<std::net::SocketAddr> =
            match tokio::time::timeout(TEST_STEP, tokio::net::lookup_host((s.hostname.as_str(), port))).await {
                Ok(Ok(it)) => it.collect(),
                _ => Vec::new(),
            };
        let mut ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        ips.sort();
        ips.dedup();
        out.resolved = ips.iter().map(IpAddr::to_string).collect();
        if ips.is_empty() {
            out.failed = Some(ReachStep::Resolve);
            return Ok(out);
        }
        out.matches_public = ips.iter().all(|ip| match ip {
            IpAddr::V4(a) => Some(*a) == v4,
            IpAddr::V6(a) => Some(*a) == v6,
        });
        // IPv4 d'abord (la plus souvent publiée).
        let target = addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first()).copied().expect("non vide");
        let t0 = std::time::Instant::now();
        let Ok(Ok(mut sock)) = tokio::time::timeout(TEST_STEP, tokio::net::TcpStream::connect(target)).await else {
            out.failed = Some(ReachStep::Connect);
            return Ok(out);
        };
        out.connect_ms = Some(t0.elapsed().as_millis().min(u32::MAX as u128) as u32);
        match tokio::time::timeout(TEST_STEP, handshake::status_ping(&mut sock, &s.hostname, port)).await {
            Ok(Ok(st)) => out.status = Some(st),
            _ => out.failed = Some(ReachStep::Status),
        }
        Ok(out)
    }
}

struct RouterRoutes {
    addresses: Addresses,
    mgr: Arc<Manager>,
}

impl router::Routes for RouterRoutes {
    fn route(&self, hostname: &str) -> router::Route {
        let id = self
            .addresses
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, a)| a.mode == AddressMode::Router && a.hostname == hostname)
            .map(|(id, _)| *id);
        let Some(srv) = id.and_then(|id| self.mgr.get(id)) else { return router::Route::Unknown };
        if srv.state() == ServerState::Running {
            router::Route::Backend(srv.local_game_addr())
        } else {
            router::Route::Offline
        }
    }
}

/// Boucle de fond : IP publiques au démarrage puis toutes les 15 min, synchronisation au
/// démarrage puis à chaque changement des enregistrements attendus (port, nom, suppression d'un
/// serveur, IP) ; un échec est repris au tour suivant.
pub fn spawn(st: &Arc<AppState>) {
    let weak: Weak<AppState> = Arc::downgrade(st);
    let mut changed = st.servers.changed.subscribe();
    let mut closing = st.closing.subscribe();
    let kick = st.network.kick.clone();
    tokio::spawn(async move {
        let mut last: Option<Vec<DnsRecord>> = None;
        let mut ip_timer = tokio::time::interval(IP_REFRESH);
        ip_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // Aucune référence forte pendant l'attente : l'état peut être libéré (tests).
            let refresh = tokio::select! {
                _ = ip_timer.tick() => true,
                r = changed.changed() => {
                    if r.is_err() { return; }
                    false
                }
                _ = kick.notified() => { last = None; false }
                _ = closing.changed() => return,
            };
            // Rafale de changements (étapes d'une opération) : regroupée.
            if !refresh {
                tokio::time::sleep(Duration::from_millis(500)).await;
                changed.borrow_and_update();
            }
            let Some(st) = weak.upgrade() else { return };
            if refresh {
                st.network.refresh_ips().await;
            }
            let (want, _) = st.network.desired(&st.servers, None);
            if last.as_ref() != Some(&want) {
                last = st.network.sync(&st).await.then_some(want);
            }
        }
    });
}
