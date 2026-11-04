//! Adresse publique d'un serveur : nom (FQDN), mode (enregistrement direct ou aiguilleur),
//! enregistrements DNS attendus, aperçu des changements chez Cloudflare, test de joignabilité.

use serde::{Deserialize, Serialize};

/// Port de jeu par défaut : sans SRV, le client vise ce port.
pub const MINECRAFT_PORT: u16 = 25565;
/// Longueur maximale d'un nom DNS complet.
pub const HOSTNAME_MAX: usize = 253;

/// Comment le serveur est joint sous son nom.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AddressMode {
    /// A/AAAA vers l'IP publique, plus un SRV si le port n'est pas 25565.
    Record,
    /// Port partagé par l'aiguilleur du gestionnaire, routage par le nom de la poignée de main.
    Router,
}

/// Nom public et mode d'un serveur.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AddressSetting {
    pub hostname: String,
    pub mode: AddressMode,
}

/// Nom DNS accepté (même règle des deux côtés) : minuscules, au moins deux étiquettes de 1 à
/// 63 caractères `a-z 0-9 -` sans tiret au bord, 253 caractères au plus, pas de joker, dernière
/// étiquette pas uniquement numérique (une IP n'est pas un nom). Point final retiré avant.
pub fn hostname_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > HOSTNAME_MAX {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Forme canonique d'un nom saisi : espaces de bord et point final retirés, minuscules.
pub fn normalize_hostname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Type d'enregistrement DNS géré.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsType {
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "SRV")]
    Srv,
}

impl DnsType {
    pub fn code(self) -> &'static str {
        match self {
            DnsType::A => "A",
            DnsType::Aaaa => "AAAA",
            DnsType::Srv => "SRV",
        }
    }
}

/// Un enregistrement : nom complet, contenu (IP ; pour un SRV : « priorité poids port cible »).
/// Toujours en nuage gris (sans le proxy de Cloudflare).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsRecord {
    pub kind: DnsType,
    pub name: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Create,
    Update,
    Delete,
}

/// Changement prévu (ou fait) chez Cloudflare. `before` : contenu actuel (mise à jour).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnsChange {
    pub kind: ChangeKind,
    pub record: DnsRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
}

/// Pourquoi un enregistrement attendu n'est pas posé.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    /// Un enregistrement de ce nom et de ce type existe, créé à la main.
    Manual,
    /// Posé par le gestionnaire puis modifié à la main (contenu, commentaire ou proxy).
    Edited,
    /// Un CNAME occupe ce nom.
    Cname,
}

/// Enregistrement attendu laissé tel quel : rien n'est écrasé.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnsConflict {
    pub reason: ConflictReason,
    pub record: DnsRecord,
    /// Ce qui est en place (type et contenu, « orange » si proxifié).
    pub existing: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpSource {
    /// `RCM_PUBLIC_IPV4` / `RCM_PUBLIC_IPV6`.
    Fixed,
    /// Demandée à un service extérieur.
    Detected,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublicIp {
    pub ip: String,
    pub source: IpSource,
}

/// Dernière synchronisation avec Cloudflare.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SyncSummary {
    pub at: i64,
    pub applied: usize,
    pub conflicts: usize,
    /// Échec (Cloudflare injoignable, jeton refusé…).
    #[serde(default)]
    pub failed: bool,
}

/// Réseau du gestionnaire, commun à tous les serveurs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    #[serde(default)]
    pub ipv4: Option<PublicIp>,
    #[serde(default)]
    pub ipv6: Option<PublicIp>,
    /// Automatisation Cloudflare active (jeton fourni par secret).
    pub cloudflare: bool,
    /// Zone DNS (`RCM_DNS_ZONE`) : les noms doivent en faire partie.
    #[serde(default)]
    pub zone: Option<String>,
    /// Port de l'aiguilleur (absent : aiguilleur coupé).
    #[serde(default)]
    pub router_port: Option<u16>,
    #[serde(default)]
    pub last_sync: Option<SyncSummary>,
}

/// `GET /api/servers/{id}/address`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AddressView {
    #[serde(default)]
    pub address: Option<AddressSetting>,
    /// Enregistrements attendus pour ce serveur.
    pub records: Vec<DnsRecord>,
    pub network: NetworkInfo,
}

/// `POST /api/servers/{id}/address/preview` (sans `digest`) et `POST /api/servers/{id}/address`
/// (avec l'empreinte de l'aperçu montré : refus si le plan a changé depuis). `address` absente :
/// le serveur n'a plus de nom public.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AddressRequest {
    #[serde(default)]
    pub address: Option<AddressSetting>,
    #[serde(default)]
    pub digest: Option<String>,
}

/// Aperçu : enregistrements attendus, changements chez Cloudflare (absents sans automatisation :
/// à créer à la main), conflits, empreinte à renvoyer pour appliquer.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AddressPreview {
    pub records: Vec<DnsRecord>,
    #[serde(default)]
    pub changes: Option<Vec<DnsChange>>,
    #[serde(default)]
    pub conflicts: Vec<DnsConflict>,
    pub digest: String,
}

/// Résultat de l'application.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AddressApplied {
    pub view: AddressView,
    pub applied: Vec<DnsChange>,
    #[serde(default)]
    pub conflicts: Vec<DnsConflict>,
    /// Réglage enregistré mais Cloudflare en échec : réessayer plus tard.
    #[serde(default)]
    pub sync_failed: bool,
}

/// Étape du test de joignabilité qui a échoué.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReachStep {
    Resolve,
    Connect,
    Status,
}

/// Réponse de statut du jeu.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StatusReply {
    pub version: String,
    pub online: u32,
    pub max: u32,
    pub ms: u32,
}

/// `POST /api/servers/{id}/address/test`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReachTest {
    pub resolved: Vec<String>,
    /// Toutes les adresses résolues sont l'IP publique connue (sinon : proxy orange, ancien
    /// enregistrement ou cache).
    pub matches_public: bool,
    pub port: u16,
    #[serde(default)]
    pub connect_ms: Option<u32>,
    #[serde(default)]
    pub status: Option<StatusReply>,
    #[serde(default)]
    pub failed: Option<ReachStep>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_publics() {
        for ok in ["survie.example.com", "a.b", "mc-1.example.org", "x1.y2.z3"] {
            assert!(hostname_valid(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "*.example.com",
            "Survie.example.com",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b.net",
            "1.2.3.4",
            "survie.example.com.",
            "é.net",
            &format!("{}.net", "a".repeat(64)),
            &format!("{}.net", ["a"; 127].join(".")),
        ] {
            assert!(!hostname_valid(bad), "{bad}");
        }
        assert_eq!(normalize_hostname(" Survie.Example.COM. "), "survie.example.com");
    }
}
