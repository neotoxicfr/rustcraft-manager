//! Listes d'accès d'un serveur (`whitelist.json`, `ops.json`, `banned-players.json`,
//! `banned-ips.json`) : lecture tolérante, modification SANS PERTE (champs inconnus, ordre des
//! clés et des entrées gardés, mise en forme du jeu : JSON indenté de deux espaces), commandes de
//! console équivalentes pour un serveur en marche, UUID officiels (Mojang) ou hors ligne.

use crate::fsutil;
use rc_manager_shared::*;
use serde_json::{Map, Value};
use std::path::Path;

/// Taille maximale d'une liste lue (le jeu n'en écrit jamais d'aussi grande).
pub const LIST_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Erreurs des opérations sur fichier.
#[derive(Debug, PartialEq, Eq)]
pub enum ListError {
    /// Fichier présent mais illisible (JSON invalide, pas une liste d'objets).
    Unreadable,
    Io,
}

/// Lit une liste : absente = vide ; illisible = erreur (jamais écrasée par une liste vide).
pub fn read_raw(dir: &Path, l: AccessList) -> Result<(Vec<Value>, Option<Vec<u8>>), ListError> {
    let p = dir.join(l.file());
    let bytes = match fsutil::read_bounded(&p, LIST_MAX_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
        Err(_) => return Err(ListError::Io),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| ListError::Unreadable)?;
    let text = text.trim_start_matches('\u{feff}');
    if text.trim().is_empty() {
        return Ok((Vec::new(), Some(bytes)));
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(a)) if a.iter().all(Value::is_object) => Ok((a, Some(bytes))),
        _ => Err(ListError::Unreadable),
    }
}

/// Contrôle de forme d'un texte de liste (mode texte) : une liste d'objets.
pub fn shape_ok(text: &str) -> bool {
    let t = text.trim_start_matches('\u{feff}');
    t.trim().is_empty()
        || matches!(serde_json::from_str::<Value>(t), Ok(Value::Array(a)) if a.iter().all(Value::is_object))
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

/// Entrée affichée.
pub fn to_entry(v: &Value) -> AccessEntry {
    AccessEntry {
        name: s(v, "name"),
        uuid: s(v, "uuid"),
        ip: s(v, "ip"),
        level: v.get("level").and_then(Value::as_u64).map(|n| n.min(255) as u8),
        bypasses_player_limit: v.get("bypassesPlayerLimit").and_then(Value::as_bool),
        reason: s(v, "reason"),
        expires: s(v, "expires"),
        created: s(v, "created"),
        source: s(v, "source"),
    }
}

/// Texte d'une liste comme le jeu l'écrit (Gson, deux espaces), fin de ligne finale gardée si
/// le fichier d'origine en avait une.
pub fn render(list: &[Value], original: Option<&[u8]>) -> Vec<u8> {
    let mut out = serde_json::to_string_pretty(list).unwrap_or_else(|_| "[]".into());
    if original.is_some_and(|o| o.ends_with(b"\n")) {
        out.push('\n');
    }
    out.into_bytes()
}

/// L'entrée vise-t-elle ce joueur (UUID, sinon pseudo sans casse) ou cette adresse ?
fn same_target(l: AccessList, v: &Value, name: &str, uuid: Option<&str>) -> bool {
    if l == AccessList::BannedIps {
        return s(v, "ip").is_some_and(|ip| ip == name);
    }
    let by_uuid = uuid.is_some_and(|u| s(v, "uuid").is_some_and(|x| x.eq_ignore_ascii_case(u)));
    by_uuid || s(v, "name").is_some_and(|n| n.eq_ignore_ascii_case(name))
}

/// Ajoute ou remplace (même joueur, même adresse) en gardant les champs inconnus de l'entrée
/// remplacée et sa place dans la liste. Rend la liste écrite.
pub fn upsert(list: &mut Vec<Value>, l: AccessList, target: &str, uuid: Option<&str>, fields: Map<String, Value>) {
    match list.iter_mut().find(|v| same_target(l, v, target, uuid)) {
        Some(Value::Object(o)) => {
            for (k, v) in fields {
                o.insert(k, v);
            }
        }
        _ => list.push(Value::Object(fields)),
    }
}

/// Retire le joueur ou l'adresse ; `false` si absent.
pub fn remove(list: &mut Vec<Value>, l: AccessList, target: &str) -> bool {
    let before = list.len();
    list.retain(|v| !same_target(l, v, target, Some(target)));
    list.len() != before
}

/// Champs d'une nouvelle entrée, dans l'ordre où le jeu les écrit.
pub fn fields(
    l: AccessList,
    name: &str,
    uuid: &str,
    req: &AccessAddRequest,
    default_level: u8,
    now: i64,
) -> Map<String, Value> {
    let mut m = Map::new();
    if l == AccessList::BannedIps {
        m.insert("ip".into(), Value::String(name.into()));
    } else {
        m.insert("uuid".into(), Value::String(uuid.into()));
        m.insert("name".into(), Value::String(name.into()));
    }
    match l {
        AccessList::Ops => {
            m.insert("level".into(), Value::from(req.level.unwrap_or(default_level)));
            m.insert("bypassesPlayerLimit".into(), Value::Bool(req.bypasses_player_limit.unwrap_or(false)));
        }
        AccessList::BannedPlayers | AccessList::BannedIps => {
            m.insert("created".into(), Value::String(game_date(now)));
            m.insert("source".into(), Value::String("Rustcraft Manager".into()));
            m.insert("expires".into(), Value::String(req.expires.map_or_else(|| "forever".into(), game_date)));
            let reason = req.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());
            m.insert("reason".into(), Value::String(reason.unwrap_or("Banned by an operator.").into()));
        }
        AccessList::Whitelist => {}
    }
    m
}

/// Date au format des listes du jeu (`yyyy-MM-dd HH:mm:ss Z`), en UTC.
pub fn game_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Jours depuis 1970 → date civile (algorithme de H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} +0000", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// UUID hors ligne du jeu (`UUID.nameUUIDFromBytes("OfflinePlayer:" + pseudo)` : MD5, version 3).
pub fn offline_uuid(name: &str) -> String {
    use md5::Digest;
    let mut h: [u8; 16] = md5::Md5::digest(format!("OfflinePlayer:{name}").as_bytes()).into();
    h[6] = (h[6] & 0x0f) | 0x30;
    h[8] = (h[8] & 0x3f) | 0x80;
    dashed(&h.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_default()
}

/// `0123…` (32 chiffres hexadécimaux) → forme à tirets ; une forme à tirets valide (8-4-4-4-12)
/// est gardée ; des tirets ailleurs sont refusés (`0-69a…` n'est pas un UUID).
pub fn dashed(id: &str) -> Option<String> {
    let dashes: Vec<usize> = id.char_indices().filter(|&(_, c)| c == '-').map(|(i, _)| i).collect();
    if !(dashes.is_empty() || dashes == [8, 13, 18, 23]) {
        return None;
    }
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let h = hex.to_ascii_lowercase();
    Some(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// Adresse IP valide, forme canonique (le jeu compare le texte).
pub fn ip_ok(s: &str) -> Option<String> {
    s.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

/// Raison d'un bannissement : une ligne, bornée.
pub fn reason_ok(r: &str) -> bool {
    r.chars().count() <= BAN_REASON_MAX && !r.chars().any(char::is_control)
}

/// Commande de console équivalente (serveur en marche).
pub fn command_add(l: AccessList, target: &str, reason: Option<&str>) -> String {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    match (l, reason) {
        (AccessList::Whitelist, _) => format!("whitelist add {target}"),
        (AccessList::Ops, _) => format!("op {target}"),
        (AccessList::BannedPlayers, Some(r)) => format!("ban {target} {r}"),
        (AccessList::BannedPlayers, None) => format!("ban {target}"),
        (AccessList::BannedIps, Some(r)) => format!("ban-ip {target} {r}"),
        (AccessList::BannedIps, None) => format!("ban-ip {target}"),
    }
}

pub fn command_remove(l: AccessList, target: &str) -> String {
    match l {
        AccessList::Whitelist => format!("whitelist remove {target}"),
        AccessList::Ops => format!("deop {target}"),
        AccessList::BannedPlayers => format!("pardon {target}"),
        AccessList::BannedIps => format!("pardon-ip {target}"),
    }
}

/// UUID d'un joueur déjà venu (`usercache.json`), pseudo à la casse du jeu.
pub fn from_usercache(dir: &Path, name: &str) -> Option<ResolvedPlayer> {
    let b = fsutil::read_bounded(&dir.join("usercache.json"), LIST_MAX_BYTES).ok()?;
    let list: Vec<Value> = serde_json::from_slice(&b).ok()?;
    list.iter().find_map(|v| {
        let n = s(v, "name")?;
        (n.eq_ignore_ascii_case(name))
            .then(|| Some(ResolvedPlayer { name: n, uuid: dashed(&s(v, "uuid")?)?, offline: false }))?
    })
}

/// État des quatre listes et des réglages liés.
pub fn state(dir: &Path) -> AccessState {
    let props = crate::files::server_properties(dir);
    let flag = |k: &str, d: bool| crate::props::get(&props, k).map_or(d, |v| v.trim() == "true");
    let mut st = AccessState {
        white_list: flag("white-list", false),
        enforce_whitelist: flag("enforce-whitelist", false),
        online_mode: flag("online-mode", true),
        default_op_level: crate::props::get(&props, "op-permission-level")
            .and_then(|v| v.trim().parse::<u8>().ok())
            .filter(|n| OP_LEVELS.contains(n))
            .unwrap_or(4),
        ..Default::default()
    };
    for l in AccessList::ALL {
        let entries = match read_raw(dir, l) {
            Ok((v, _)) => v.iter().map(to_entry).collect(),
            Err(_) => {
                st.unreadable.push(l);
                Vec::new()
            }
        };
        match l {
            AccessList::Whitelist => st.whitelist = entries,
            AccessList::Ops => st.ops = entries,
            AccessList::BannedPlayers => st.banned_players = entries,
            AccessList::BannedIps => st.banned_ips = entries,
        }
    }
    st
}

/// Cache des UUID officiels (pseudo en minuscules → réponse, instant) ; inconnus gardés moins
/// longtemps. Borné : vidé au-delà de [`CACHE_MAX`] entrées.
const CACHE_MAX: usize = 512;
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);
const CACHE_TTL_UNKNOWN: std::time::Duration = std::time::Duration::from_secs(600);
type Cached = (Option<ResolvedPlayer>, std::time::Instant);
static CACHE: std::sync::Mutex<Option<std::collections::HashMap<String, Cached>>> = std::sync::Mutex::new(None);

/// Délai d'une demande à Mojang.
pub const LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Demandes à Mojang par minute, pour tout le gestionnaire : Mojang limite par adresse, et des
/// comptes qui cherchent des pseudos sans fin ne doivent pas faire bloquer celle du gestionnaire
/// (les réponses en cache ne comptent pas).
pub const LOOKUPS_PER_MIN: u32 = 30;
const LOOKUP_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
static WINDOW: std::sync::Mutex<Option<(std::time::Instant, u32)>> = std::sync::Mutex::new(None);

/// Place dans la fenêtre d'une minute (`full` : Mojang a répondu 429, fenêtre remplie) ;
/// `Err(secondes)` avant la prochaine place.
fn lookup_slot(w: &mut Option<(std::time::Instant, u32)>, now: std::time::Instant, full: bool) -> Result<(), u64> {
    let (start, n) = w.get_or_insert((now, 0));
    if now.duration_since(*start) >= LOOKUP_WINDOW {
        (*start, *n) = (now, 0);
    }
    if full {
        (*start, *n) = (now, LOOKUPS_PER_MIN);
    }
    if *n >= LOOKUPS_PER_MIN {
        return Err(LOOKUP_WINDOW.saturating_sub(now.duration_since(*start)).as_secs().max(1));
    }
    *n += 1;
    Ok(())
}

/// Échec d'une demande à Mojang.
#[derive(Debug, PartialEq, Eq)]
pub enum LookupError {
    /// Injoignable ou réponse illisible.
    Failed,
    /// Limite de [`LOOKUPS_PER_MIN`] atteinte (ou 429 de Mojang) : secondes avant de réessayer.
    Limited(u64),
}

/// Profil officiel (`api.mojang.com`, hôte de la liste fermée) : `Ok(None)` pseudo inconnu.
pub async fn mojang(http: &crate::download::Http, name: &str) -> Result<Option<ResolvedPlayer>, LookupError> {
    use LookupError::Failed as LookupFailed;
    let key = name.to_ascii_lowercase();
    if let Some((v, t)) = CACHE.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|c| c.get(&key)).cloned() {
        let ttl = if v.is_some() { CACHE_TTL } else { CACHE_TTL_UNKNOWN };
        if t.elapsed() < ttl {
            return Ok(v);
        }
    }
    let slot =
        |full| lookup_slot(&mut WINDOW.lock().unwrap_or_else(|p| p.into_inner()), std::time::Instant::now(), full);
    slot(false).map_err(LookupError::Limited)?;
    let url = format!("https://api.mojang.com/users/profiles/minecraft/{name}");
    let res = tokio::time::timeout(LOOKUP_TIMEOUT, http.bytes(&url, 4096)).await.map_err(|_| LookupFailed)?;
    let found = match res {
        Ok(b) if b.is_empty() => None,
        Ok(b) => {
            let v: Value = serde_json::from_slice(&b).map_err(|_| LookupFailed)?;
            let n = s(&v, "name").filter(|n| crate::console::player_name_ok(n)).ok_or(LookupFailed)?;
            Some(ResolvedPlayer {
                name: n,
                uuid: dashed(&s(&v, "id").ok_or(LookupFailed)?).ok_or(LookupFailed)?,
                offline: false,
            })
        }
        Err(crate::download::DlError::Status(404 | 204)) => None,
        // Mojang limite déjà l'adresse : plus aucune demande pendant une minute.
        Err(crate::download::DlError::Status(429)) => {
            return Err(LookupError::Limited(slot(true).err().unwrap_or(60)));
        }
        Err(_) => return Err(LookupFailed),
    };
    let mut c = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let map = c.get_or_insert_with(Default::default);
    if map.len() >= CACHE_MAX {
        map.clear();
    }
    map.insert(key, (found.clone(), std::time::Instant::now()));
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UUID hors ligne identiques à ceux du jeu (valeurs de `UUID.nameUUIDFromBytes`).
    #[test]
    fn uuid_hors_ligne_du_jeu() {
        assert_eq!(offline_uuid("Notch"), "b50ad385-829d-3141-a216-7e7d7539ba7f");
        assert_eq!(dashed("069a79f444e94726a5befca90e38aaf5").as_deref(), Some("069a79f4-44e9-4726-a5be-fca90e38aaf5"));
        assert_eq!(
            dashed("069A79F4-44E9-4726-A5BE-FCA90E38AAF5").as_deref(),
            Some("069a79f4-44e9-4726-a5be-fca90e38aaf5")
        );
        assert_eq!(dashed("xyz"), None);
        for bad in [
            "0-69a79f444e94726a5befca90e38aaf5",
            "069a79f444e94726a5befca90e38aaf5-",
            "069a79f4-44e9-4726-a5be-fca90e38-aaf5",
        ] {
            assert_eq!(dashed(bad), None, "{bad}");
        }
    }

    /// Demandes à Mojang bornées pour tout le gestionnaire ; un 429 remplit la fenêtre.
    #[test]
    fn limite_des_demandes_a_mojang() {
        let t0 = std::time::Instant::now();
        let mut w = None;
        for _ in 0..LOOKUPS_PER_MIN {
            assert_eq!(lookup_slot(&mut w, t0, false), Ok(()));
        }
        assert_eq!(lookup_slot(&mut w, t0 + std::time::Duration::from_secs(20), false), Err(40));
        let t1 = t0 + LOOKUP_WINDOW;
        assert_eq!(lookup_slot(&mut w, t1, false), Ok(()), "fenêtre suivante");
        assert_eq!(lookup_slot(&mut w, t1, true), Err(60), "429 : fenêtre pleine");
        assert!(lookup_slot(&mut w, t1 + std::time::Duration::from_secs(1), false).is_err());
    }

    /// Lien posé par le serveur à la place d'une liste ou de `server.properties` : jamais lu au
    /// travers, ni recopié dans le fichier.
    #[test]
    fn listes_et_reglages_jamais_lus_au_travers_d_un_lien() {
        let d = std::env::temp_dir().join(format!("rcm-access-lien-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let secret = d.join("secret.json");
        std::fs::write(&secret, "[{\"name\": \"cle-secrete\"}]\nonline-mode=false\n").unwrap();
        if !crate::files::tests::link_file(&secret, &d.join("whitelist.json")) {
            eprintln!("liens de fichier impossibles ici (Windows sans mode développeur) : test sauté");
            return;
        }
        assert!(crate::files::tests::link_file(&secret, &d.join("server.properties")));
        assert_eq!(read_raw(&d, AccessList::Whitelist).unwrap_err(), ListError::Io);
        let st = state(&d);
        assert!(st.whitelist.is_empty() && st.unreadable.contains(&AccessList::Whitelist));
        assert!(st.online_mode, "server.properties lié : valeurs par défaut");
        assert!(crate::props::patch_file(&d.join("server.properties"), &[("motd", "x".into())]).is_err());
        assert!(std::fs::symlink_metadata(d.join("server.properties")).unwrap().file_type().is_symlink());
        assert!(!std::fs::read_to_string(&secret).unwrap().contains("motd"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dates_du_jeu() {
        assert_eq!(game_date(0), "1970-01-01 00:00:00 +0000");
        assert_eq!(game_date(1_792_497_600), "2026-10-20 12:00:00 +0000");
        assert_eq!(game_date(951_782_400), "2000-02-29 00:00:00 +0000");
    }

    /// Modification sans perte : champs inconnus et place gardés, mise en forme du jeu.
    #[test]
    fn modification_sans_perte() {
        let src = b"[\n  {\n    \"uuid\": \"b50ad385-829d-3141-a216-7e7d7539ba7f\",\n    \"name\": \"Notch\",\n    \"level\": 4,\n    \"bypassesPlayerLimit\": false,\n    \"extra\": 1\n  },\n  {\n    \"uuid\": \"u2\",\n    \"name\": \"Bob\",\n    \"level\": 2,\n    \"bypassesPlayerLimit\": true\n  }\n]";
        let mut list: Vec<Value> = serde_json::from_slice(src).unwrap();
        assert_eq!(render(&list, Some(src)), src.to_vec(), "relu et réécrit à l'identique");
        let req = AccessAddRequest {
            list: AccessList::Ops,
            target: "notch".into(),
            level: Some(2),
            bypasses_player_limit: Some(true),
            reason: None,
            expires: None,
        };
        let f = fields(AccessList::Ops, "Notch", "b50ad385-829d-3141-a216-7e7d7539ba7f", &req, 4, 0);
        upsert(&mut list, AccessList::Ops, "notch", Some("b50ad385-829d-3141-a216-7e7d7539ba7f"), f);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["level"], 2);
        assert_eq!(list[0]["extra"], 1, "champ inconnu gardé");
        let keys: Vec<&String> = list[0].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["uuid", "name", "level", "bypassesPlayerLimit", "extra"], "ordre gardé");
        assert!(remove(&mut list, AccessList::Ops, "BOB"));
        assert!(!remove(&mut list, AccessList::Ops, "bob"));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn valeurs_hostiles() {
        assert_eq!(ip_ok("192.168.1.10").as_deref(), Some("192.168.1.10"));
        assert_eq!(ip_ok(" ::1 ").as_deref(), Some("::1"));
        for bad in ["", "1.2.3", "a.b.c.d", "1.2.3.4; stop", "1.2.3.4\nop x", "999.1.1.1"] {
            assert_eq!(ip_ok(bad), None, "{bad:?}");
        }
        assert!(reason_ok("Triche"));
        assert!(!reason_ok("a\nop Bob"));
        assert!(!reason_ok(&"x".repeat(BAN_REASON_MAX + 1)));
        assert_eq!(command_add(AccessList::BannedPlayers, "Bob", Some(" grief ")), "ban Bob grief");
        assert_eq!(command_remove(AccessList::BannedIps, "1.2.3.4"), "pardon-ip 1.2.3.4");
        assert!(!shape_ok("{}"));
        assert!(!shape_ok("[1]"));
        assert!(shape_ok("[]"));
        assert!(shape_ok("[{\"name\":\"a\"}]"));
    }
}
