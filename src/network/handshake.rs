//! Protocole Minecraft, le strict nécessaire : poignée de main (paquet 0 de l'état initial),
//! réponse de statut et refus de connexion de l'aiguilleur, ping de statut du test de
//! joignabilité.
//!
//! Paquet : VarInt longueur, VarInt identifiant, données. Poignée de main : VarInt version,
//! chaîne (VarInt longueur + UTF-8, 255 caractères au plus) adresse, u16 port, VarInt état
//! suivant (1 statut, 2 connexion, 3 transfert).

use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Taille maximale d'une poignée de main (adresse de 255 caractères en UTF-8, plus le suffixe
/// FML et les champs) : au-delà, connexion refusée.
pub const HANDSHAKE_MAX: usize = 1024;
/// Réponse de statut lue au plus (test de joignabilité).
pub const STATUS_MAX: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub protocol: i32,
    /// Adresse telle qu'envoyée par le client.
    pub address: String,
    pub port: u16,
    pub next_state: i32,
}

impl Handshake {
    /// Nom servant au routage : avant le premier `\0` (suffixe FML de Forge, `\0FML\0`…), sans
    /// le point final, en minuscules.
    pub fn hostname(&self) -> String {
        let a = self.address.split('\0').next().unwrap_or("");
        a.trim_end_matches('.').to_ascii_lowercase()
    }
}

/// Lecture d'une poignée de main dans un tampon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse {
    /// Paquet incomplet : lire davantage.
    Incomplete,
    /// Paquet complet ; `usize` : octets consommés.
    Done(Handshake, usize),
    /// Pas une poignée de main valide (ping hérité `0xFE`, identifiant, taille, champ).
    Invalid,
}

/// VarInt de plus de 5 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong;

/// VarInt au début de `b` : (valeur, octets lus), `None` si incomplet, `Err` si plus de 5 octets.
pub fn read_varint(b: &[u8]) -> Result<Option<(i32, usize)>, TooLong> {
    let mut v: u32 = 0;
    for i in 0..5 {
        let Some(&byte) = b.get(i) else { return Ok(None) };
        v |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(Some((v as i32, i + 1)));
        }
    }
    Err(TooLong)
}

pub fn write_varint(out: &mut Vec<u8>, v: i32) {
    let mut v = v as u32;
    loop {
        if v & !0x7f == 0 {
            out.push(v as u8);
            return;
        }
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    write_varint(out, s.len() as i32);
    out.extend_from_slice(s.as_bytes());
}

/// Paquet complet (longueur en tête).
pub fn packet(id: i32, body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(body.len() + 5);
    write_varint(&mut inner, id);
    inner.extend_from_slice(body);
    let mut out = Vec::with_capacity(inner.len() + 5);
    write_varint(&mut out, inner.len() as i32);
    out.extend_from_slice(&inner);
    out
}

/// Analyse la poignée de main au début de `b`.
pub fn parse_handshake(b: &[u8]) -> Parse {
    // Ping hérité (clients d'avant 1.7) : pas de routage possible.
    if b.first() == Some(&0xFE) {
        return Parse::Invalid;
    }
    let (len, n) = match read_varint(b) {
        Ok(Some(x)) => x,
        Ok(None) => return Parse::Incomplete,
        Err(TooLong) => return Parse::Invalid,
    };
    if len <= 0 || len as usize > HANDSHAKE_MAX {
        return Parse::Invalid;
    }
    let len = len as usize;
    let Some(body) = b.get(n..n + len) else { return Parse::Incomplete };
    match fields(body) {
        Some(h) => Parse::Done(h, n + len),
        None => Parse::Invalid,
    }
}

fn fields(body: &[u8]) -> Option<Handshake> {
    let mut i = 0;
    let varint = |i: &mut usize| -> Option<i32> {
        let (v, n) = read_varint(&body[*i..]).ok()??;
        *i += n;
        Some(v)
    };
    if varint(&mut i)? != 0 {
        return None;
    }
    let protocol = varint(&mut i)?;
    let slen = varint(&mut i)?;
    if !(0..=(255 * 3 + 16)).contains(&slen) {
        return None;
    }
    let s = body.get(i..i + slen as usize)?;
    i += slen as usize;
    let address = std::str::from_utf8(s).ok()?.to_string();
    if address.chars().count() > 255 + 16 {
        return None;
    }
    let port = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]);
    i += 2;
    let next_state = varint(&mut i)?;
    // Champs en trop (paquet plus long que la poignée de main) : refusé.
    if i != body.len() || !(1..=3).contains(&next_state) {
        return None;
    }
    Some(Handshake { protocol, address, port, next_state })
}

/// Poignée de main encodée (test de joignabilité, tests).
pub fn encode_handshake(h: &Handshake) -> Vec<u8> {
    let mut body = Vec::new();
    write_varint(&mut body, h.protocol);
    write_string(&mut body, &h.address);
    body.extend_from_slice(&h.port.to_be_bytes());
    write_varint(&mut body, h.next_state);
    packet(0, &body)
}

/// Texte JSON d'un composant de chat simple, échappé par serde.
fn text_component(text: &str) -> String {
    serde_json::json!({ "text": text }).to_string()
}

/// Réponse de statut (paquet 0 de l'état « statut ») : version annoncée incompatible (-1)
/// pour que le client affiche le motif à la place du nombre de joueurs.
pub fn status_response(protocol: i32, motd: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "version": { "name": "Rustcraft Manager", "protocol": if protocol > 0 { -1 } else { protocol } },
        "players": { "max": 0, "online": 0 },
        "description": { "text": motd },
    })
    .to_string();
    let mut body = Vec::new();
    write_string(&mut body, &json);
    packet(0, &body)
}

/// Refus de connexion (paquet 0 de l'état « connexion ») : le client affiche le motif.
pub fn login_disconnect(reason: &str) -> Vec<u8> {
    let mut body = Vec::new();
    write_string(&mut body, &text_component(reason));
    packet(0, &body)
}

/// Lit un paquet entier (borné) ; rend (identifiant, données).
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<(i32, Vec<u8>)> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "paquet invalide");
    let mut head = Vec::with_capacity(5);
    let len = loop {
        let b = r.read_u8().await?;
        head.push(b);
        match read_varint(&head) {
            Ok(Some((v, _))) => break v,
            Ok(None) => {}
            Err(TooLong) => return Err(invalid()),
        }
    };
    if len <= 0 || len as usize > max {
        return Err(invalid());
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    let (id, n) = read_varint(&buf).map_err(|_| invalid())?.ok_or_else(invalid)?;
    Ok((id, buf[n..].to_vec()))
}

/// Ping de statut d'un serveur (test de joignabilité) : poignée de main avec le nom public,
/// demande de statut, réponse JSON bornée, puis ping pour la latence.
pub async fn status_ping<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    hostname: &str,
    port: u16,
) -> std::io::Result<rc_manager_shared::StatusReply> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "réponse de statut invalide");
    let hs = Handshake { protocol: -1, address: hostname.to_string(), port, next_state: 1 };
    let mut out = encode_handshake(&hs);
    out.extend_from_slice(&packet(0, &[]));
    s.write_all(&out).await?;
    let (id, body) = read_packet(s, STATUS_MAX).await?;
    if id != 0 {
        return Err(invalid());
    }
    let (slen, n) = read_varint(&body).map_err(|_| invalid())?.ok_or_else(invalid)?;
    let json = body.get(n..n + slen.max(0) as usize).ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_slice(json).map_err(|_| invalid())?;
    let t0 = Instant::now();
    s.write_all(&packet(1, &42i64.to_be_bytes())).await?;
    let (id, _) = read_packet(s, 64).await?;
    if id != 1 {
        return Err(invalid());
    }
    let ms = t0.elapsed().min(Duration::from_secs(60)).as_millis() as u32;
    let num = |p: &str| v.pointer(p).and_then(serde_json::Value::as_u64).unwrap_or(0).min(u32::MAX as u64) as u32;
    let version: String = v.pointer("/version/name").and_then(|x| x.as_str()).unwrap_or("").chars().take(64).collect();
    Ok(rc_manager_shared::StatusReply { version, online: num("/players/online"), max: num("/players/max"), ms })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs(addr: &str, state: i32) -> Vec<u8> {
        encode_handshake(&Handshake { protocol: 775, address: addr.into(), port: 25565, next_state: state })
    }

    #[test]
    fn varint_aller_retour() {
        for v in [0, 1, 127, 128, 255, 25565, 2_097_151, i32::MAX, -1, i32::MIN] {
            let mut b = Vec::new();
            write_varint(&mut b, v);
            assert_eq!(read_varint(&b), Ok(Some((v, b.len()))), "{v}");
            assert_eq!(read_varint(&b[..b.len() - 1]), Ok(None));
        }
        assert_eq!(read_varint(&[0xff; 6]), Err(TooLong));
    }

    #[test]
    fn poignee_de_main_analysee() {
        let b = hs("Survie.Example.com.", 2);
        let Parse::Done(h, n) = parse_handshake(&b) else { panic!() };
        assert_eq!(n, b.len());
        assert_eq!((h.protocol, h.port, h.next_state), (775, 25565, 2));
        assert_eq!(h.hostname(), "survie.example.com");
        // Suffixe FML (Forge 1.7 à 1.12, 1.13+) retiré.
        for fml in ["survie.example.com\0FML\0", "survie.example.com\0FML2\0", "survie.example.com\0FML3\0"] {
            let Parse::Done(h, _) = parse_handshake(&hs(fml, 2)) else { panic!("{fml:?}") };
            assert_eq!(h.hostname(), "survie.example.com");
        }
        // Octets suivants (demande de connexion déjà envoyée) : seul le premier paquet est lu.
        let mut more = hs("a.b", 2);
        let len = more.len();
        more.extend_from_slice(&packet(0, b"\x03Bob"));
        assert!(matches!(parse_handshake(&more), Parse::Done(_, n) if n == len));
    }

    #[test]
    fn poignee_de_main_incomplete_ou_hostile() {
        let b = hs("survie.example.com", 1);
        for cut in 0..b.len() {
            assert_eq!(parse_handshake(&b[..cut]), Parse::Incomplete, "{cut}");
        }
        // Ping hérité, longueur nulle, négative ou démesurée, VarInt sans fin.
        assert_eq!(parse_handshake(&[0xFE, 0x01]), Parse::Invalid);
        assert_eq!(parse_handshake(&[0x00]), Parse::Invalid);
        assert_eq!(parse_handshake(&[0xff, 0xff, 0xff, 0xff, 0x0f]), Parse::Invalid);
        let mut big = Vec::new();
        write_varint(&mut big, HANDSHAKE_MAX as i32 + 1);
        assert_eq!(parse_handshake(&big), Parse::Invalid);
        assert_eq!(parse_handshake(&[0xff; 8]), Parse::Invalid);
        // Mauvais identifiant, état inconnu, champ en trop, chaîne trop longue, UTF-8 invalide.
        assert_eq!(parse_handshake(&packet(1, &[0])), Parse::Invalid);
        assert_eq!(parse_handshake(&hs("a.b", 4)), Parse::Invalid);
        let mut extra = hs("a.b", 2);
        extra[0] += 1;
        extra.push(0);
        assert_eq!(parse_handshake(&extra), Parse::Invalid);
        assert_eq!(parse_handshake(&hs(&"a".repeat(800), 2)), Parse::Invalid);
        let mut body = Vec::new();
        write_varint(&mut body, 775);
        body.extend_from_slice(&[2, 0xff, 0xfe]);
        body.extend_from_slice(&[0x63, 0xdd, 2]);
        assert_eq!(parse_handshake(&packet(0, &body)), Parse::Invalid);
    }

    #[test]
    fn reponses_de_l_aiguilleur() {
        let s = status_response(775, "Adresse \"inconnue\"");
        let mut r = &s[..];
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let (id, body) = rt.block_on(read_packet(&mut r, STATUS_MAX)).unwrap();
        assert_eq!(id, 0);
        let (n, k) = read_varint(&body).unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body[k..k + n as usize]).unwrap();
        assert_eq!(v["description"]["text"], "Adresse \"inconnue\"");
        assert_eq!(v["version"]["protocol"], -1);
        let d = login_disconnect("Serveur arrêté");
        let mut r = &d[..];
        let (id, body) = rt.block_on(read_packet(&mut r, STATUS_MAX)).unwrap();
        assert_eq!(id, 0);
        assert!(String::from_utf8_lossy(&body).contains("Serveur arrêté"));
    }
}
