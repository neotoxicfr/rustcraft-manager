//! Petites briques cryptographiques (aléa système, SHA-256, comparaison à temps constant,
//! encodages) sur `ring`, déjà dans le dépôt.

use base64::Engine;
use ring::rand::SecureRandom;

/// Octets aléatoires du système.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new().fill(&mut b).expect("générateur aléatoire du système indisponible");
    b
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Égalité sans fuite de temps sur le contenu (la longueur, elle, n'est pas secrète ici).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Jeton opaque de 256 bits, base64 URL sans remplissage (cookie, CSRF).
pub fn token() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 RFC 4648 sans remplissage (secrets TOTP, jetons à recopier).
pub fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Chiffrement des champs sensibles en base

/// Clé maîtresse de 256 bits (`RCM_ENCRYPTION_KEY`, ou fichier `manager.key`). Jamais affichée :
/// `Debug` la masque.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterKey([u8; 32]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(masquée)")
    }
}

impl MasterKey {
    /// 32 octets en hexadécimal (64 chiffres) ou en base64 (standard ou URL, avec ou sans
    /// remplissage). Une clé nulle (que des zéros) est refusée : c'est la trace d'une clé jamais
    /// initialisée. Le message d'erreur ne recopie jamais la valeur.
    pub fn parse(s: &str) -> Result<MasterKey, String> {
        let s = s.trim();
        let bytes = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            (0..32)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| "hexadécimal invalide".to_string())?
        } else {
            use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
            [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|e| e.decode(s).ok())
                .ok_or_else(|| "32 octets en base64 ou 64 chiffres hexadécimaux attendus".to_string())?
        };
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| format!("32 octets attendus, {} lus", v.len()))?;
        Self::from_bytes(arr)
    }

    pub fn from_bytes(b: [u8; 32]) -> Result<MasterKey, String> {
        if b.iter().all(|&x| x == 0) {
            return Err("clé nulle refusée (jamais initialisée ?)".into());
        }
        Ok(MasterKey(b))
    }

    pub fn generate() -> MasterKey {
        loop {
            if let Ok(k) = Self::from_bytes(random_bytes::<32>()) {
                return k;
            }
        }
    }

    /// Forme écrite dans le fichier de clé (base64 standard).
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

/// Préfixe du format des valeurs chiffrées. Un nouveau format = un nouveau préfixe, jamais une
/// heuristique (« chiffré si contient `:` » finit en migrations de rattrapage).
pub const FIELD_PREFIX: &str = "v1:";

/// Erreur de déchiffrement : format inconnu, valeur altérée, mauvaise ligne ou mauvaise clé.
/// Toujours fermée : aucune valeur en clair n'est jamais rendue à la place.
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptError;

/// Clés dérivées de la clé maîtresse (HKDF-SHA256, une étiquette par usage) : chiffrement des
/// champs (AES-256-GCM) et HMAC des codes de secours. On ne peut pas en obtenir sans clé
/// maîtresse : pas d'état « non initialisé » possible.
pub struct Keys {
    field: ring::aead::LessSafeKey,
    recovery: ring::hmac::Key,
}

/// Longueur demandée à HKDF (32 octets pour les deux usages).
struct Len32;
impl ring::hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

impl Keys {
    pub fn derive(master: &MasterKey) -> Keys {
        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"rustcraft-manager").extract(&master.0);
        let expand = |info: &[u8]| {
            let mut out = [0u8; 32];
            prk.expand(&[info], Len32).and_then(|okm| okm.fill(&mut out)).expect("HKDF : longueur fixe valide");
            out
        };
        let field = expand(b"rcm field aes-256-gcm v1");
        let recovery = expand(b"rcm recovery-code hmac v1");
        Keys {
            field: ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &field).expect("clé AES de 32 octets"),
            ),
            recovery: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &recovery),
        }
    }

    /// Clés jetables (tests, base en mémoire).
    pub fn ephemeral() -> Keys {
        Self::derive(&MasterKey::generate())
    }

    /// `v1:` + base64 URL (nonce aléatoire de 96 bits ‖ texte chiffré ‖ étiquette). `aad` lie la
    /// valeur à sa place (« table:colonne:id ») : recopiée sur une autre ligne, elle ne se
    /// déchiffre plus.
    pub fn encrypt(&self, aad: &str, plain: &[u8]) -> String {
        use ring::aead::{Aad, Nonce};
        let nonce = random_bytes::<12>();
        let mut buf = plain.to_vec();
        self.field
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut buf)
            .expect("AES-GCM : taille dans les bornes");
        let mut out = Vec::with_capacity(12 + buf.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        format!("{FIELD_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out))
    }

    pub fn decrypt(&self, aad: &str, stored: &str) -> Result<Vec<u8>, DecryptError> {
        use ring::aead::{Aad, Nonce};
        let b64 = stored.strip_prefix(FIELD_PREFIX).ok_or(DecryptError)?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).map_err(|_| DecryptError)?;
        if raw.len() < 12 + 16 {
            return Err(DecryptError);
        }
        let (nonce, rest) = raw.split_at(12);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| DecryptError)?;
        let mut buf = rest.to_vec();
        let plain = self.field.open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf).map_err(|_| DecryptError)?;
        Ok(plain.to_vec())
    }

    /// Empreinte d'un code de secours : HMAC-SHA256 (clé dérivée), liée au compte.
    pub fn recovery_mac(&self, user_id: i64, normalized: &str) -> [u8; 32] {
        let tag = ring::hmac::sign(&self.recovery, format!("{user_id}:{normalized}").as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

/// Données associées d'un champ chiffré.
pub fn aad(table: &str, column: &str, id: i64) -> String {
    format!("{table}:{column}:{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chiffrement_par_champ_ferme() {
        let k = Keys::ephemeral();
        let a = aad("users", "totp_secret", 1);
        let c = k.encrypt(&a, b"secret totp");
        assert!(c.starts_with("v1:"), "{c}");
        assert_eq!(k.decrypt(&a, &c).unwrap(), b"secret totp");
        // Nonce aléatoire : deux chiffrements diffèrent.
        assert_ne!(c, k.encrypt(&a, b"secret totp"));
        // Recopié sur une autre ligne ou une autre colonne : refusé.
        assert_eq!(k.decrypt(&aad("users", "totp_secret", 2), &c), Err(DecryptError));
        assert_eq!(k.decrypt(&aad("users", "totp_pending", 1), &c), Err(DecryptError));
        // Autre clé : refusé.
        assert_eq!(Keys::ephemeral().decrypt(&a, &c), Err(DecryptError));
        // Altéré, tronqué, sans préfixe, en clair : refusé (jamais de repli « valeur en clair »).
        let mut t = c.clone().into_bytes();
        let last = t.len() - 3;
        t[last] = if t[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(k.decrypt(&a, std::str::from_utf8(&t).unwrap()), Err(DecryptError));
        assert_eq!(k.decrypt(&a, &c[..c.len() - 4]), Err(DecryptError));
        assert_eq!(k.decrypt(&a, c.trim_start_matches("v1:")), Err(DecryptError));
        assert_eq!(k.decrypt(&a, "secret totp"), Err(DecryptError));
        assert_eq!(k.decrypt(&a, "v2:AAAA"), Err(DecryptError));
    }

    #[test]
    fn cle_maitresse_validee() {
        let hex = "0123456789abcdef".repeat(4);
        let k = MasterKey::parse(&hex).unwrap();
        assert_eq!(MasterKey::parse(&k.to_base64()).unwrap(), k);
        assert_eq!(MasterKey::parse(&format!(" {}\n", k.to_base64())).unwrap(), k);
        // Clé nulle (non initialisée), trop courte, trop longue, illisible : refusées.
        assert!(MasterKey::parse(&"0".repeat(64)).is_err());
        assert!(MasterKey::parse(&"ab".repeat(16)).is_err());
        assert!(MasterKey::parse(&base64::engine::general_purpose::STANDARD.encode([7u8; 33])).is_err());
        assert!(MasterKey::parse("pas une clé !").is_err());
        assert_eq!(format!("{k:?}"), "MasterKey(masquée)");
        // HMAC des codes de secours : dépend de la clé et du compte.
        let (a, b) = (Keys::derive(&k), Keys::ephemeral());
        assert_eq!(a.recovery_mac(1, "ABC"), Keys::derive(&k).recovery_mac(1, "ABC"));
        assert_ne!(a.recovery_mac(1, "ABC"), b.recovery_mac(1, "ABC"));
        assert_ne!(a.recovery_mac(1, "ABC"), a.recovery_mac(2, "ABC"));
    }

    #[test]
    fn base32_rfc4648() {
        // Vecteurs de la RFC 4648 § 10 (sans remplissage).
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn egalite_et_jetons() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        let (a, b) = (token(), token());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }
}
