//! Enregistrements DNS attendus et plan de synchronisation, sans réseau.
//!
//! Un enregistrement posé par le gestionnaire porte le commentaire
//! `rustcraft-manager <empreinte>`, l'empreinte (8 chiffres hexadécimaux) étant celle de
//! « type|nom|contenu » au moment de l'écriture. Il est à nous et INTACT si le commentaire est
//! exactement celui-là, que l'empreinte correspond au contenu actuel et qu'il est en nuage gris.
//! Tout le reste (créé à la main, ou à nous puis modifié : contenu, commentaire, proxy) n'est
//! jamais touché : il apparaît comme conflit.

use rc_manager_shared::{
    AddressMode, AddressSetting, ChangeKind, ConflictReason, DnsChange, DnsConflict, DnsRecord, DnsType, MINECRAFT_PORT,
};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Début du commentaire des enregistrements du gestionnaire.
pub const MARKER: &str = "rustcraft-manager";

/// Enregistrement en place chez le fournisseur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Existing {
    pub id: String,
    /// Type tel que lu (`A`, `AAAA`, `SRV`, `CNAME`, `TXT`…).
    pub kind: String,
    pub name: String,
    /// Contenu normalisé (SRV : « priorité poids port cible »).
    pub content: String,
    pub proxied: bool,
    pub comment: Option<String>,
}

/// Empreinte d'un enregistrement (8 chiffres hexadécimaux).
pub fn fingerprint(kind: &str, name: &str, content: &str) -> String {
    let h = crate::crypto::sha256(format!("{kind}|{}|{content}", name.to_ascii_lowercase()).as_bytes());
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Commentaire posé sur un enregistrement écrit par le gestionnaire.
pub fn comment_for(r: &DnsRecord) -> String {
    format!("{MARKER} {}", fingerprint(r.kind.code(), &r.name, &r.content))
}

impl Existing {
    /// Posé par le gestionnaire (commentaire de la forme attendue), modifié ou non.
    pub fn marked(&self) -> bool {
        self.comment.as_deref().is_some_and(|c| c == MARKER || c.starts_with(&format!("{MARKER} ")))
    }
    /// Posé par le gestionnaire et intact : seul cas où il peut être modifié ou supprimé.
    pub fn ours_intact(&self) -> bool {
        !self.proxied
            && self.comment.as_deref()
                == Some(&format!("{MARKER} {}", fingerprint(&self.kind, &self.name, &self.content)))
    }
    fn describe(&self) -> String {
        format!("{} {}{}", self.kind, self.content, if self.proxied { " (proxy)" } else { "" })
    }
}

/// Une entrée : nom public et port joint par le client (port du serveur en mode direct, de
/// l'aiguilleur sinon).
pub struct Target<'a> {
    pub setting: &'a AddressSetting,
    pub game_port: u16,
}

/// Enregistrements attendus d'un nom : A et AAAA selon les IP connues, SRV
/// `_minecraft._tcp.<nom>` si le port joint n'est pas 25565 (cible : le nom lui-même).
pub fn records_for(
    setting: &AddressSetting,
    game_port: u16,
    router_port: Option<u16>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
) -> Vec<DnsRecord> {
    let host = &setting.hostname;
    let port = match setting.mode {
        AddressMode::Record => game_port,
        AddressMode::Router => match router_port {
            Some(p) => p,
            None => return Vec::new(),
        },
    };
    let mut out = Vec::new();
    if let Some(ip) = v4 {
        out.push(DnsRecord { kind: DnsType::A, name: host.clone(), content: ip.to_string() });
    }
    if let Some(ip) = v6 {
        out.push(DnsRecord { kind: DnsType::Aaaa, name: host.clone(), content: ip.to_string() });
    }
    if port != MINECRAFT_PORT {
        out.push(DnsRecord {
            kind: DnsType::Srv,
            name: format!("_minecraft._tcp.{host}"),
            content: srv_content(0, 5, port, host),
        });
    }
    out
}

pub fn srv_content(priority: u16, weight: u16, port: u16, target: &str) -> String {
    format!("{priority} {weight} {port} {}", target.trim_end_matches('.').to_ascii_lowercase())
}

/// Plan : changements à faire et conflits laissés tels quels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub changes: Vec<(DnsChange, Option<String>)>,
    pub conflicts: Vec<DnsConflict>,
}

impl Plan {
    pub fn changes(&self) -> Vec<DnsChange> {
        self.changes.iter().map(|(c, _)| c.clone()).collect()
    }
}

/// Plan de synchronisation. `desired` : enregistrements attendus de tous les serveurs ;
/// `hostnames` : noms publics actuels ; `unknown` : types dont l'IP n'est pas connue en ce
/// moment (détection en échec) : nos enregistrements de ce type sur un nom encore attendu sont
/// gardés tels quels au lieu d'être supprimés.
pub fn plan(desired: &[DnsRecord], existing: &[Existing], hostnames: &BTreeSet<String>, unknown: &[DnsType]) -> Plan {
    let mut p = Plan::default();
    let same_name = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let mut used: BTreeSet<&str> = BTreeSet::new();
    let mut sorted = desired.to_vec();
    sorted.sort();
    sorted.dedup();
    for d in &sorted {
        let code = d.kind.code();
        // Un CNAME interdit tout autre enregistrement à ce nom.
        if let Some(c) = existing.iter().find(|e| e.kind == "CNAME" && same_name(&e.name, &d.name)) {
            p.conflicts.push(DnsConflict { reason: ConflictReason::Cname, record: d.clone(), existing: c.describe() });
            continue;
        }
        let same: Vec<&Existing> = existing.iter().filter(|e| e.kind == code && same_name(&e.name, &d.name)).collect();
        let ours: Vec<&&Existing> = same.iter().filter(|e| e.ours_intact()).collect();
        let others: Vec<&&Existing> = same.iter().filter(|e| !e.ours_intact()).collect();
        if let Some(o) = others.first() {
            // Une valeur posée à la main (ou retouchée) à ce nom : on n'ajoute rien à côté.
            let reason = if o.marked() { ConflictReason::Edited } else { ConflictReason::Manual };
            p.conflicts.push(DnsConflict { reason, record: d.clone(), existing: o.describe() });
            for e in &ours {
                used.insert(e.id.as_str());
            }
            continue;
        }
        match ours.first() {
            Some(e) => {
                used.insert(e.id.as_str());
                if e.content != d.content {
                    p.changes.push((
                        DnsChange { kind: ChangeKind::Update, record: d.clone(), before: Some(e.content.clone()) },
                        Some(e.id.clone()),
                    ));
                }
                // Doublons à nous (deux A identiques) : le surplus part.
                for extra in ours.iter().skip(1) {
                    used.insert(extra.id.as_str());
                    p.changes.push((delete_of(extra), Some(extra.id.clone())));
                }
            }
            None => p.changes.push((DnsChange { kind: ChangeKind::Create, record: d.clone(), before: None }, None)),
        }
    }
    for e in existing {
        if used.contains(e.id.as_str()) || !e.ours_intact() {
            continue;
        }
        let host = e.name.strip_prefix("_minecraft._tcp.").unwrap_or(&e.name).to_ascii_lowercase();
        let kept = unknown.iter().any(|t| t.code() == e.kind) && hostnames.contains(&host);
        if !kept {
            p.changes.push((delete_of(e), Some(e.id.clone())));
        }
    }
    p
}

fn delete_of(e: &Existing) -> DnsChange {
    let kind = match e.kind.as_str() {
        "AAAA" => DnsType::Aaaa,
        "SRV" => DnsType::Srv,
        _ => DnsType::A,
    };
    DnsChange {
        kind: ChangeKind::Delete,
        record: DnsRecord { kind, name: e.name.clone(), content: e.content.clone() },
        before: None,
    }
}

/// Empreinte d'un aperçu : ce qui sera fait (changements, conflits, enregistrements attendus).
pub fn digest(records: &[DnsRecord], changes: Option<&[DnsChange]>, conflicts: &[DnsConflict]) -> String {
    let v = serde_json::json!({ "r": records, "c": changes, "k": conflicts });
    let h = crate::crypto::sha256(v.to_string().as_bytes());
    h[..16].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting(h: &str, mode: AddressMode) -> AddressSetting {
        AddressSetting { hostname: h.into(), mode }
    }
    const V4: Option<Ipv4Addr> = Some(Ipv4Addr::new(203, 0, 113, 7));

    fn ours(id: &str, r: &DnsRecord) -> Existing {
        Existing {
            id: id.into(),
            kind: r.kind.code().into(),
            name: r.name.clone(),
            content: r.content.clone(),
            proxied: false,
            comment: Some(comment_for(r)),
        }
    }

    fn hosts(h: &[&str]) -> BTreeSet<String> {
        h.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn enregistrements_construits() {
        let s = setting("survie.example.com", AddressMode::Record);
        // Port par défaut : A seul (pas de SRV), AAAA si l'IPv6 est connue.
        let r = records_for(&s, 25565, None, V4, None);
        assert_eq!(
            r,
            vec![DnsRecord { kind: DnsType::A, name: "survie.example.com".into(), content: "203.0.113.7".into() }]
        );
        let v6 = Some("2001:db8::7".parse().unwrap());
        let r = records_for(&s, 25570, None, V4, v6);
        assert_eq!(r.len(), 3);
        assert_eq!(r[1].kind, DnsType::Aaaa);
        assert_eq!(r[2].name, "_minecraft._tcp.survie.example.com");
        assert_eq!(r[2].content, "0 5 25570 survie.example.com");
        // Aiguilleur : port de l'aiguilleur, pas celui du serveur ; coupé : rien.
        let s = setting("crea.example.com", AddressMode::Router);
        assert_eq!(records_for(&s, 25570, Some(25565), V4, None).len(), 1);
        let r = records_for(&s, 25570, Some(25600), V4, None);
        assert_eq!(r[1].content, "0 5 25600 crea.example.com");
        assert!(records_for(&s, 25570, None, V4, None).is_empty());
        // Aucune IP connue : seulement le SRV.
        assert_eq!(records_for(&s, 1, Some(25600), None, None).len(), 1);
    }

    #[test]
    fn commentaire_et_empreinte() {
        let r = DnsRecord { kind: DnsType::A, name: "Survie.example.com".into(), content: "203.0.113.7".into() };
        let e = ours("1", &r);
        assert!(e.marked() && e.ours_intact());
        assert!(comment_for(&r).starts_with("rustcraft-manager "));
        assert_eq!(comment_for(&r).len(), MARKER.len() + 9);
        // Contenu, commentaire ou proxy retouchés : plus intact.
        assert!(!Existing { content: "198.51.100.1".into(), ..e.clone() }.ours_intact());
        assert!(!Existing { proxied: true, ..e.clone() }.ours_intact());
        assert!(!Existing { comment: Some("rustcraft-manager".into()), ..e.clone() }.ours_intact());
        assert!(Existing { comment: Some("rustcraft-manager".into()), ..e.clone() }.marked());
        assert!(!Existing { comment: Some("à la main".into()), ..e.clone() }.marked());
        assert!(!Existing { comment: Some("rustcraft-managerX".into()), ..e }.marked());
    }

    #[test]
    fn creation_mise_a_jour_suppression() {
        let s = setting("survie.example.com", AddressMode::Record);
        let want = records_for(&s, 25570, None, V4, None);
        // Rien en place : tout est créé.
        let p = plan(&want, &[], &hosts(&["survie.example.com"]), &[]);
        assert_eq!(p.changes().iter().filter(|c| c.kind == ChangeKind::Create).count(), 2);
        assert!(p.conflicts.is_empty());
        // Tout en place et intact : rien à faire.
        let have: Vec<Existing> = want.iter().enumerate().map(|(i, r)| ours(&i.to_string(), r)).collect();
        assert_eq!(plan(&want, &have, &hosts(&["survie.example.com"]), &[]), Plan::default());
        // Nouvelle IP et nouveau port : mises à jour sur les mêmes identifiants.
        let want2 = records_for(&s, 25571, None, Some(Ipv4Addr::new(203, 0, 113, 8)), None);
        let p = plan(&want2, &have, &hosts(&["survie.example.com"]), &[]);
        assert_eq!(p.changes.len(), 2);
        assert!(p.changes.iter().all(|(c, id)| c.kind == ChangeKind::Update && id.is_some()));
        assert_eq!(p.changes[0].0.before.as_deref(), Some("203.0.113.7"));
        // Retour au port 25565 : le SRV part, le A reste.
        let want3 = records_for(&s, 25565, None, V4, None);
        let p = plan(&want3, &have, &hosts(&["survie.example.com"]), &[]);
        assert_eq!(p.changes(), vec![delete_of(&have[1])]);
        // Renommage : les anciens partent, les nouveaux sont créés.
        let want4 = records_for(&setting("monde.example.com", AddressMode::Record), 25570, None, V4, None);
        let p = plan(&want4, &have, &hosts(&["monde.example.com"]), &[]);
        let kinds: Vec<ChangeKind> = p.changes().iter().map(|c| c.kind).collect();
        assert_eq!(kinds.iter().filter(|k| **k == ChangeKind::Create).count(), 2);
        assert_eq!(kinds.iter().filter(|k| **k == ChangeKind::Delete).count(), 2);
        // Serveur supprimé : plus rien d'attendu, nos enregistrements partent.
        let p = plan(&[], &have, &hosts(&[]), &[]);
        assert_eq!(p.changes.len(), 2);
        assert!(p.changes().iter().all(|c| c.kind == ChangeKind::Delete));
    }

    /// Ce qui a été posé ou retouché à la main n'est jamais modifié ni supprimé.
    #[test]
    fn jamais_d_ecrasement_du_manuel() {
        let s = setting("survie.example.com", AddressMode::Record);
        let want = records_for(&s, 25570, None, V4, None);
        let manual = Existing {
            id: "m".into(),
            kind: "A".into(),
            name: "survie.example.com".into(),
            content: "198.51.100.9".into(),
            proxied: false,
            comment: None,
        };
        let p = plan(&want, std::slice::from_ref(&manual), &hosts(&["survie.example.com"]), &[]);
        assert_eq!(p.conflicts.len(), 1);
        assert_eq!(p.conflicts[0].reason, ConflictReason::Manual);
        assert_eq!(p.conflicts[0].existing, "A 198.51.100.9");
        // Le SRV est créé, le A n'est ni créé à côté, ni modifié, ni supprimé.
        assert_eq!(p.changes().len(), 1);
        assert_eq!(p.changes()[0].record.kind, DnsType::Srv);
        // À nous puis retouché (contenu, ou passé en orange) : conflit « modifié », rien touché.
        let mut edited = ours("e", &want[0]);
        edited.content = "198.51.100.10".into();
        let mut orange = ours("o", &want[0]);
        orange.proxied = true;
        for e in [edited, orange] {
            let p = plan(&want[..1], std::slice::from_ref(&e), &hosts(&["survie.example.com"]), &[]);
            assert_eq!(p.conflicts.len(), 1, "{e:?}");
            assert_eq!(p.conflicts[0].reason, ConflictReason::Edited);
            assert!(p.changes.is_empty(), "{e:?}");
            // Plus attendu du tout (serveur supprimé) : toujours pas supprimé.
            assert!(plan(&[], std::slice::from_ref(&e), &hosts(&[]), &[]).changes.is_empty());
        }
        // Un manuel sans rapport (autre nom, joker orange) : ignoré.
        let joker = Existing { name: "*.example.com".into(), proxied: true, ..manual.clone() };
        let p = plan(&want, std::slice::from_ref(&joker), &hosts(&["survie.example.com"]), &[]);
        assert!(p.conflicts.is_empty());
        assert!(plan(&[], &[joker], &hosts(&[]), &[]).changes.is_empty());
        // CNAME au même nom : conflit, rien de créé.
        let cname = Existing { kind: "CNAME".into(), content: "ailleurs.example".into(), ..manual };
        let p = plan(&want[..1], &[cname], &hosts(&["survie.example.com"]), &[]);
        assert_eq!(p.conflicts[0].reason, ConflictReason::Cname);
        assert!(p.changes.is_empty());
    }

    #[test]
    fn ip_inconnue_garde_l_existant() {
        let s = setting("survie.example.com", AddressMode::Record);
        let have = vec![ours("a", &records_for(&s, 25565, None, V4, None)[0])];
        // Détection IPv4 en échec : le A reste tant que le nom est attendu…
        assert!(plan(&[], &have, &hosts(&["survie.example.com"]), &[DnsType::A]).changes.is_empty());
        // … mais part si le serveur n'a plus ce nom.
        assert_eq!(plan(&[], &have, &hosts(&[]), &[DnsType::A]).changes.len(), 1);
    }

    #[test]
    fn empreinte_d_apercu_stable() {
        let r = vec![DnsRecord { kind: DnsType::A, name: "a.b".into(), content: "203.0.113.7".into() }];
        assert_eq!(digest(&r, None, &[]), digest(&r, None, &[]));
        assert_ne!(digest(&r, None, &[]), digest(&r, Some(&[]), &[]));
        assert_eq!(digest(&r, None, &[]).len(), 32);
    }
}
