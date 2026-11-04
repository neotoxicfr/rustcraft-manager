//! Double authentification TOTP (RFC 6238 : HMAC-SHA1, pas de 30 s, 6 chiffres), compatible avec
//! les applications courantes. Écrite sur `ring` (quelques lignes) plutôt qu'une dépendance de
//! plus ; vérifiée contre les vecteurs de la RFC.
//!
//! Le rejeu est refusé : l'appelant enregistre le pas accepté et [`verify`] n'accepte qu'un pas
//! strictement plus récent.

use ring::hmac;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
/// Taille du secret (160 bits, recommandée par la RFC 4226).
pub const SECRET_LEN: usize = 20;
/// Décalage d'horloge toléré, en pas, de chaque côté.
pub const SKEW: u64 = 1;

/// Pas courant pour un instant Unix.
pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// Code HOTP (RFC 4226) du pas donné, tronqué à `digits` chiffres.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits)
}

/// Code à 6 chiffres du pas donné, sous forme de texte (zéros de tête gardés).
pub fn code(secret: &[u8], step: u64) -> String {
    format!("{:06}", hotp(secret, step, DIGITS))
}

/// Vérifie `input` (6 chiffres, espaces tolérés) autour de `now_step`. Rend le pas reconnu s'il
/// est strictement après `last_step` (sinon : rejeu ou code faux → `None`).
pub fn verify(secret: &[u8], input: &str, now_step: u64, last_step: Option<u64>) -> Option<u64> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS as usize || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut found = None;
    // Tous les pas de la fenêtre sont calculés (durée indépendante de celui qui correspond).
    for step in now_step.saturating_sub(SKEW)..=now_step + SKEW {
        if crate::crypto::ct_eq(code(secret, step).as_bytes(), digits.as_bytes()) && last_step.is_none_or(|l| step > l)
        {
            found = Some(step);
        }
    }
    found
}

/// Lien `otpauth://` (contenu du QR code). Le nom d'utilisateur est déjà restreint à
/// `[A-Za-z0-9_.-]` : rien à échapper.
pub fn otpauth_uri(secret_b32: &str, username: &str) -> String {
    format!(
        "otpauth://totp/Rustcraft%20Manager:{username}?secret={secret_b32}&issuer=Rustcraft%20Manager&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}"
    )
}

/// QR code SVG autonome du lien.
pub fn qr_svg(uri: &str) -> String {
    match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(qr) => qr.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn vecteurs_rfc6238_sha1() {
        // RFC 6238 annexe B (8 chiffres), instants → codes.
        for (t, expected) in [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            assert_eq!(hotp(RFC_SECRET, step_at(t), 8), expected, "t = {t}");
        }
        assert_eq!(code(RFC_SECRET, step_at(1111111109)), "081804");
        assert_eq!(crate::crypto::base32(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn fenetre_et_rejeu() {
        let now = step_at(1_800_000_000);
        let c = code(RFC_SECRET, now);
        assert_eq!(verify(RFC_SECRET, &c, now, None), Some(now));
        assert_eq!(verify(RFC_SECRET, &format!("{} {}", &c[..3], &c[3..]), now, None), Some(now));
        // Rejeu du même pas refusé.
        assert_eq!(verify(RFC_SECRET, &c, now, Some(now)), None);
        // Pas précédent et suivant tolérés, au-delà refusés.
        assert_eq!(verify(RFC_SECRET, &code(RFC_SECRET, now - 1), now, None), Some(now - 1));
        assert_eq!(verify(RFC_SECRET, &code(RFC_SECRET, now + 1), now, None), Some(now + 1));
        assert_eq!(verify(RFC_SECRET, &code(RFC_SECRET, now + 2), now, None), None);
        assert_eq!(verify(RFC_SECRET, &code(RFC_SECRET, now - 2), now, None), None);
        // Un code plus ancien que le dernier accepté est refusé même dans la fenêtre.
        assert_eq!(verify(RFC_SECRET, &code(RFC_SECRET, now - 1), now, Some(now)), None);
        // Formes invalides.
        assert_eq!(verify(RFC_SECRET, "12345", now, None), None);
        assert_eq!(verify(RFC_SECRET, "abcdef", now, None), None);
        assert_eq!(verify(RFC_SECRET, "1234567", now, None), None);
    }

    #[test]
    fn qr_et_lien() {
        let uri = otpauth_uri("GEZDGNBV", "admin");
        assert!(uri.starts_with("otpauth://totp/Rustcraft%20Manager:admin?secret=GEZDGNBV"));
        let svg = qr_svg(&uri);
        assert!(svg.contains("<svg") && !svg.contains("<script"));
    }
}
