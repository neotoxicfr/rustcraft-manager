//! Aiguilleur : un seul port public partagé par plusieurs serveurs, routage par le nom
//! d'hôte de la poignée de main (comme mc-router).
//!
//! Par connexion : place prise dans le plafond global et dans celui de l'adresse (IPv6 par /64),
//! sinon fermeture immédiate ; poignée de main lue en 5 s au plus, 1 Kio au plus ; nom choisi
//! exactement (sans point final ni suffixe FML, casse ignorée) parmi les serveurs en mode
//! aiguilleur ; nom inconnu ou serveur arrêté : réponse de statut (liste des serveurs du
//! client) ou refus de connexion lisible, puis fermeture ; sinon connexion au serveur local
//! (5 s), octets déjà lus renvoyés tels quels, puis copie dans les deux sens par tampons de
//! 16 Kio, coupée après 2 min sans aucun octet dans un sens.

use super::handshake::{HANDSHAKE_MAX, Parse, login_disconnect, parse_handshake, read_packet, status_response};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const BUF: usize = 16 * 1024;

/// Motifs affichés au joueur (le client ne dit pas sa langue : les deux).
pub const UNKNOWN_MOTD: &str = "Adresse inconnue · Unknown address";
pub const OFFLINE_MOTD: &str = "Serveur arrêté · Server offline";

/// Où envoyer une connexion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Backend(SocketAddr),
    /// Nom connu, serveur arrêté.
    Offline,
    Unknown,
}

pub trait Routes: Send + Sync + 'static {
    fn route(&self, hostname: &str) -> Route;
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_connections: usize,
    pub max_per_ip: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

/// Clé de l'adresse : IPv4 exacte, IPv6 par /64 (une box donne un /64 entier).
fn ip_key(ip: IpAddr) -> IpAddr {
    match crate::config::canonical_ip(ip) {
        IpAddr::V6(v) => {
            let s = v.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

#[derive(Default)]
struct Counts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Place tenue par une connexion, rendue en sortant de portée.
struct Slot {
    counts: Arc<Mutex<Counts>>,
    key: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut c = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        c.total -= 1;
        if let Some(n) = c.per_ip.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                c.per_ip.remove(&self.key);
            }
        }
    }
}

fn take_slot(counts: &Arc<Mutex<Counts>>, ip: IpAddr, l: &Limits) -> Option<Slot> {
    let key = ip_key(ip);
    let mut c = counts.lock().unwrap_or_else(|p| p.into_inner());
    let n = c.per_ip.get(&key).copied().unwrap_or(0);
    if c.total >= l.max_connections || n >= l.max_per_ip {
        return None;
    }
    c.total += 1;
    c.per_ip.insert(key, n + 1);
    Some(Slot { counts: counts.clone(), key })
}

/// Boucle d'acceptation ; s'arrête quand `closing` passe à vrai.
pub async fn run(
    listener: TcpListener,
    routes: Arc<dyn Routes>,
    limits: Limits,
    mut closing: tokio::sync::watch::Receiver<bool>,
) {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let mut refused_logged = false;
    loop {
        let (sock, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("aiguilleur : acceptation : {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = closing.changed() => return,
        };
        let Some(slot) = take_slot(&counts, peer.ip(), &limits) else {
            if !refused_logged {
                tracing::warn!("aiguilleur : plafond de connexions atteint (connexions fermées à l'acceptation)");
                refused_logged = true;
            }
            drop(sock);
            continue;
        };
        let routes = routes.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = sock.set_nodelay(true);
            handle(sock, routes.as_ref(), &limits).await;
        });
    }
}

/// Une connexion : poignée de main, routage, relais.
pub async fn handle(mut client: TcpStream, routes: &dyn Routes, l: &Limits) {
    let mut buf = Vec::with_capacity(512);
    let read = tokio::time::timeout(l.handshake_timeout, async {
        let mut chunk = [0u8; 512];
        loop {
            match parse_handshake(&buf) {
                Parse::Done(h, n) => return Some((h, n)),
                Parse::Invalid => return None,
                Parse::Incomplete => {}
            }
            if buf.len() > HANDSHAKE_MAX + 8 {
                return None;
            }
            let n = client.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await;
    let Ok(Some((hs, consumed))) = read else { return };
    let host = hs.hostname();
    let backend = match routes.route(&host) {
        Route::Backend(a) => a,
        r => {
            let motd = if r == Route::Offline { OFFLINE_MOTD } else { UNKNOWN_MOTD };
            let rest = buf.split_off(consumed);
            let _ =
                tokio::time::timeout(l.handshake_timeout, refuse(&mut client, hs.next_state, hs.protocol, motd, rest))
                    .await;
            return;
        }
    };
    let Ok(Ok(mut server)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(backend)).await else {
        let _ = tokio::time::timeout(
            l.handshake_timeout,
            refuse(&mut client, hs.next_state, hs.protocol, OFFLINE_MOTD, buf.split_off(consumed)),
        )
        .await;
        return;
    };
    let _ = server.set_nodelay(true);
    // Tout ce qui a été lu (poignée de main et suite éventuelle) part tel quel.
    if server.write_all(&buf).await.is_err() {
        return;
    }
    let (cr, cw) = client.into_split();
    let (sr, sw) = server.into_split();
    let _ = tokio::try_join!(pipe(cr, sw, l.idle_timeout), pipe(sr, cw, l.idle_timeout));
}

/// Réponse propre à une connexion qu'on ne relaie pas : statut (puis réponse au ping) ou refus
/// de connexion. `rest` : octets déjà lus après la poignée de main.
async fn refuse(
    client: &mut TcpStream,
    next_state: i32,
    protocol: i32,
    motd: &str,
    rest: Vec<u8>,
) -> std::io::Result<()> {
    if next_state != 1 {
        client.write_all(&login_disconnect(motd)).await?;
        return client.shutdown().await;
    }
    let mut r = std::io::Cursor::new(rest).chain(&mut *client);
    // Demande de statut (paquet 0 vide), puis ping (paquet 1, 8 octets) renvoyé tel quel.
    // Le client attend la réponse avant d'envoyer son ping.
    let (id, _) = read_packet(&mut r, 16).await?;
    if id != 0 {
        return Ok(());
    }
    let (rest, _) = r.into_inner();
    let rest = rest.get_ref()[rest.position() as usize..].to_vec();
    client.write_all(&status_response(protocol, motd)).await?;
    let mut r = std::io::Cursor::new(rest).chain(&mut *client);
    let (id, payload) = read_packet(&mut r, 16).await.unwrap_or((-1, Vec::new()));
    drop(r);
    if id == 1 && payload.len() == 8 {
        client.write_all(&super::handshake::packet(1, &payload)).await?;
    }
    client.shutdown().await
}

/// Copie d'un sens, bornée (tampon fixe), coupée après `idle` sans rien lire ni pouvoir écrire.
async fn pipe<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut r: R, mut w: W, idle: Duration) -> std::io::Result<()> {
    let mut buf = vec![0u8; BUF];
    let timed_out = || std::io::Error::new(std::io::ErrorKind::TimedOut, "inactif");
    loop {
        let n = tokio::time::timeout(idle, r.read(&mut buf)).await.map_err(|_| timed_out())??;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        tokio::time::timeout(idle, w.write_all(&buf[..n])).await.map_err(|_| timed_out())??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plafonds_par_adresse_et_global() {
        let l = Limits {
            max_connections: 3,
            max_per_ip: 2,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
        };
        let c = Arc::new(Mutex::new(Counts::default()));
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let a2: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        let b: IpAddr = "198.51.100.1".parse().unwrap();
        let s1 = take_slot(&c, a, &l).unwrap();
        let _s2 = take_slot(&c, a2, &l).unwrap();
        // Même /64 : refusé.
        assert!(take_slot(&c, "2001:db8:1:2::9".parse().unwrap(), &l).is_none());
        let _s3 = take_slot(&c, b, &l).unwrap();
        // Plafond global.
        assert!(take_slot(&c, "198.51.100.2".parse().unwrap(), &l).is_none());
        drop(s1);
        assert!(take_slot(&c, "198.51.100.2".parse().unwrap(), &l).is_some());
        assert_eq!(ip_key("::ffff:198.51.100.1".parse().unwrap()), b);
    }
}
