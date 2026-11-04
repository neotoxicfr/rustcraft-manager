//! Client RCON (protocole Source, utilisé par Minecraft) : connexion à `127.0.0.1:<rcon.port>`,
//! authentification par le mot de passe généré par le gestionnaire (chiffré en base, jamais dans un
//! journal), commandes avec réponse. Délais et tailles bornés.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const AUTH: i32 = 3;
const EXEC: i32 = 2;
/// Délai d'une connexion ou d'une réponse.
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// Paquet reçu le plus grand accepté (Minecraft découpe à 4 096 octets de corps).
const MAX_PACKET: i32 = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum RconError {
    Connect,
    Auth,
    Protocol,
    Timeout,
}

pub struct Rcon {
    stream: TcpStream,
    next_id: i32,
}

async fn write_packet(s: &mut TcpStream, id: i32, kind: i32, body: &str) -> Result<(), RconError> {
    let b = body.as_bytes();
    if b.len() > 1446 {
        // Limite du serveur Minecraft pour une commande reçue.
        return Err(RconError::Protocol);
    }
    let len = (4 + 4 + b.len() + 2) as i32;
    let mut buf = Vec::with_capacity(len as usize + 4);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&id.to_le_bytes());
    buf.extend_from_slice(&kind.to_le_bytes());
    buf.extend_from_slice(b);
    buf.extend_from_slice(&[0, 0]);
    s.write_all(&buf).await.map_err(|_| RconError::Protocol)
}

async fn read_packet(s: &mut TcpStream) -> Result<(i32, i32, String), RconError> {
    let len = s.read_i32_le().await.map_err(|_| RconError::Protocol)?;
    if !(10..=MAX_PACKET).contains(&len) {
        return Err(RconError::Protocol);
    }
    let mut buf = vec![0u8; len as usize];
    s.read_exact(&mut buf).await.map_err(|_| RconError::Protocol)?;
    let id = i32::from_le_bytes(buf[0..4].try_into().map_err(|_| RconError::Protocol)?);
    let kind = i32::from_le_bytes(buf[4..8].try_into().map_err(|_| RconError::Protocol)?);
    let body = &buf[8..buf.len() - 2];
    Ok((id, kind, String::from_utf8_lossy(body).into_owned()))
}

impl Rcon {
    pub async fn connect(port: u16, password: &str) -> Result<Rcon, RconError> {
        let fut = async {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.map_err(|_| RconError::Connect)?;
            let _ = stream.set_nodelay(true);
            write_packet(&mut stream, 1, AUTH, password).await?;
            // Réponse d'authentification : id -1 si refusée.
            loop {
                let (id, kind, _) = read_packet(&mut stream).await?;
                if id == -1 {
                    return Err(RconError::Auth);
                }
                if kind == 2 && id == 1 {
                    break;
                }
            }
            Ok(Rcon { stream, next_id: 2 })
        };
        tokio::time::timeout(TIMEOUT, fut).await.map_err(|_| RconError::Timeout)?
    }

    /// Envoie une commande et rend sa réponse (un paquet).
    pub async fn exec(&mut self, cmd: &str) -> Result<String, RconError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(2);
        let fut = async {
            write_packet(&mut self.stream, id, EXEC, cmd).await?;
            loop {
                let (rid, _, body) = read_packet(&mut self.stream).await?;
                if rid == id {
                    return Ok(body);
                }
            }
        };
        tokio::time::timeout(TIMEOUT, fut).await.map_err(|_| RconError::Timeout)?
    }
}

/// Mot de passe RCON aléatoire (32 caractères alphanumériques : rien à échapper dans
/// `server.properties`).
pub fn new_password() -> String {
    const A: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // 248 = 4 × 62 : rejet des octets au-delà pour une répartition uniforme.
    let mut out = String::with_capacity(32);
    while out.len() < 32 {
        for b in crate::crypto::random_bytes::<48>() {
            if b < 248 && out.len() < 32 {
                out.push(A[(b % 62) as usize] as char);
            }
        }
    }
    out
}

/// `list` → (connectés, maximum, noms). Formes : « There are 3 of a max of 20 players online:
/// a, b, c » et « There are 3/20 players online: » (anciennes versions).
pub fn parse_list(s: &str) -> Option<(u32, u32, Vec<String>)> {
    let s = strip_colors(s);
    let rest = s.trim().strip_prefix("There are ")?;
    let (counts, names) = rest.split_once(':').unwrap_or((rest, ""));
    let nums: Vec<u32> = counts.split(|c: char| !c.is_ascii_digit()).filter_map(|p| p.parse().ok()).collect();
    let (n, max) = (*nums.first()?, *nums.get(1)?);
    let names = names.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
    Some((n, max, names))
}

/// Temps moyen d'un tick (ms) dans la réponse de `tick query` (vanilla 1.20.3+) ou `mspt`
/// (Paper : « … from last 5s, 10s, 1m: ◴ 1.2/0.5/3.1, … » → moyenne sur 5 s).
pub fn parse_mspt(s: &str) -> Option<f32> {
    let s = strip_colors(s);
    if let Some(i) = s.find("Average time per tick: ") {
        let rest = &s[i + "Average time per tick: ".len()..];
        return rest.split("ms").next()?.trim().parse().ok();
    }
    if s.contains("Server tick times") {
        let after = s.split_once(':')?.1;
        let first = after.split(',').next()?;
        let avg = first.trim_start_matches(|c: char| !c.is_ascii_digit()).split('/').next()?;
        return avg.trim().parse().ok();
    }
    None
}

/// TPS de Paper (`tps` : « TPS from last 1m, 5m, 15m: 20.0, 20.0, 20.0 », `*20.0` au plafond).
pub fn parse_tps(s: &str) -> Option<f32> {
    let s = strip_colors(s);
    let after = s.split_once("15m:")?.1;
    after.split(',').next()?.trim().trim_start_matches('*').parse().ok()
}

/// Codes de couleur `§x` retirés.
pub fn strip_colors(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut skip = false;
    for c in s.chars() {
        if skip {
            skip = false;
            continue;
        }
        if c == '§' {
            skip = true;
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reponses_lues() {
        assert_eq!(
            parse_list("There are 3 of a max of 20 players online: Steve, Alex, neo"),
            Some((3, 20, vec!["Steve".into(), "Alex".into(), "neo".into()]))
        );
        assert_eq!(parse_list("There are 0 of a max of 20 players online: "), Some((0, 20, vec![])));
        assert_eq!(parse_list("There are 1/10 players online:\nneo"), Some((1, 10, vec!["neo".into()])));
        assert_eq!(parse_list("Unknown command"), None);
        let tq = "The game is running normally\nTarget tick rate: 20.0 per second.\nAverage time per tick: 4.1ms (Target: 50.0ms)";
        assert_eq!(parse_mspt(tq), Some(4.1));
        assert_eq!(
            parse_mspt(
                "§6Server tick times §e(§7avg§e/§7min§e/§7max§e)§6 from last 5s§7,§6 10s§7,§6 1m§e:\n§6◴ §a1.2§7/§a0.5§7/§a3.1§e, §a1.0"
            ),
            Some(1.2)
        );
        assert_eq!(parse_tps("§6TPS from last 1m, 5m, 15m: §a*20.0, §a20.0, §a19.9"), Some(20.0));
        assert_eq!(parse_tps("rien"), None);
    }

    #[test]
    fn mots_de_passe_aleatoires() {
        let a = new_password();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_ne!(a, new_password());
    }

    /// Faux serveur RCON : authentification, commande, mot de passe refusé, paquet démesuré.
    #[tokio::test]
    async fn dialogue_avec_un_faux_serveur() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let (id, _, pw) = read_packet(&mut s).await.unwrap();
                    if pw != "bon" {
                        write_packet(&mut s, -1, 2, "").await.unwrap();
                        return;
                    }
                    write_packet(&mut s, id, 2, "").await.unwrap();
                    while let Ok((id, _, cmd)) = read_packet(&mut s).await {
                        if cmd == "gros" {
                            let len = (MAX_PACKET + 1).to_le_bytes();
                            let _ = s.write_all(&len).await;
                            return;
                        }
                        write_packet(&mut s, id, 0, &format!("reçu {cmd}")).await.unwrap();
                    }
                });
            }
        });
        assert_eq!(Rcon::connect(port, "mauvais").await.err(), Some(RconError::Auth));
        let mut r = Rcon::connect(port, "bon").await.unwrap();
        assert_eq!(r.exec("list").await.unwrap(), "reçu list");
        assert_eq!(r.exec("gros").await.err(), Some(RconError::Protocol));
        assert!(write_packet(&mut r.stream, 9, EXEC, &"x".repeat(2000)).await.is_err());
    }
}
