//! Thème par compte (direction « Obsidienne ») : une couleur principale, une secondaire, un fond
//! (froid, neutre, chaud) et l'apparence (auto, clair, sombre). Un seul réglage donne les jetons
//! CSS du thème clair ET du thème sombre : la couleur principale est assombrie en clair (éclaircie
//! en sombre) juste assez pour un contraste de 4,5:1 sur le fond, la secondaire pour 3:1 (objets
//! graphiques, WCAG 1.4.11).
//!
//! Le calcul est ici (code partagé) : l'interface l'applique, les tests natifs le vérifient.

use serde::{Deserialize, Serialize};

/// Fond.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Cold,
    #[default]
    Neutral,
    Warm,
}

impl Tone {
    pub const ALL: [Tone; 3] = [Tone::Cold, Tone::Neutral, Tone::Warm];
}

/// Apparence.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Appearance {
    #[default]
    Auto,
    Light,
    Dark,
}

impl Appearance {
    pub const ALL: [Appearance; 3] = [Appearance::Auto, Appearance::Light, Appearance::Dark];
}

/// Réglage du thème d'un compte (`POST /api/account/theme`, `Me::theme`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ThemeSettings {
    /// Couleur principale `#rrggbb` (une des 12 proposées ou personnalisée).
    pub primary: String,
    /// Couleur secondaire `#rrggbb`.
    pub secondary: String,
    #[serde(default)]
    pub tone: Tone,
    #[serde(default)]
    pub appearance: Appearance,
}

impl Default for ThemeSettings {
    fn default() -> Self {
        ThemeSettings {
            primary: PRIMARY[0].2.to_string(),
            secondary: SECONDARY[0].2.to_string(),
            tone: Tone::Neutral,
            appearance: Appearance::Auto,
        }
    }
}

impl ThemeSettings {
    pub fn valid(&self) -> bool {
        Rgb::parse(&self.primary).is_some() && Rgb::parse(&self.secondary).is_some()
    }
}

/// Couleurs principales proposées : (français, anglais, valeur).
pub const PRIMARY: [(&str, &str, &str); 12] = [
    ("Émeraude", "Emerald", "#5fd0a0"),
    ("Menthe", "Mint", "#7fe0c8"),
    ("Mousse", "Moss", "#94bf55"),
    ("Citron", "Lemon", "#d6d65a"),
    ("Or", "Gold", "#e0b44c"),
    ("Cuivre", "Copper", "#e8955a"),
    ("Braise", "Ember", "#ff8a65"),
    ("Corail", "Coral", "#f27a7a"),
    ("Rose", "Pink", "#f07fa8"),
    ("Lilas", "Lilac", "#b49cf5"),
    ("Glacier", "Glacier", "#6cbcf0"),
    ("Océan", "Ocean", "#4f9fd6"),
];

/// Couleurs secondaires proposées.
pub const SECONDARY: [(&str, &str, &str); 12] = [
    ("Lavande", "Lavender", "#9fb4ff"),
    ("Ciel", "Sky", "#8fd3ff"),
    ("Turquoise", "Turquoise", "#79d9d0"),
    ("Sauge", "Sage", "#a9c79a"),
    ("Sable", "Sand", "#e2cfa8"),
    ("Or", "Gold", "#e6c477"),
    ("Pêche", "Peach", "#f6b896"),
    ("Corail", "Coral", "#f4a38b"),
    ("Bruyère", "Heather", "#d9a6c9"),
    ("Mauve", "Mauve", "#c3b1f0"),
    ("Ardoise", "Slate", "#9aa6b5"),
    ("Perle", "Pearl", "#d4d8de"),
];

/// Couleur sRGB 8 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// `#rrggbb` (minuscules ou majuscules) seulement.
    pub fn parse(s: &str) -> Option<Rgb> {
        let h = s.strip_prefix('#')?;
        if h.len() != 6 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let v = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
        Some(Rgb(v(0)?, v(2)?, v(4)?))
    }

    pub fn hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }

    pub fn rgba(self, a: f32) -> String {
        format!("rgba({},{},{},{})", self.0, self.1, self.2, trim(a))
    }

    /// Mélange vers `to` (k = 0 : soi, k = 1 : `to`).
    pub fn mix(self, to: Rgb, k: f32) -> Rgb {
        let m = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * k).round().clamp(0.0, 255.0) as u8;
        Rgb(m(self.0, to.0), m(self.1, to.1), m(self.2, to.2))
    }

    /// Luminance relative (WCAG 2).
    pub fn luminance(self) -> f32 {
        let c = |v: u8| {
            let s = v as f32 / 255.0;
            if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * c(self.0) + 0.7152 * c(self.1) + 0.0722 * c(self.2)
    }

    /// Teinte en degrés (0 à 360).
    pub fn hue(self) -> f32 {
        let (r, g, b) = (self.0 as f32 / 255.0, self.1 as f32 / 255.0, self.2 as f32 / 255.0);
        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        let d = max - min;
        if d == 0.0 {
            return 0.0;
        }
        let h = if max == r {
            ((g - b) / d).rem_euclid(6.0)
        } else if max == g {
            (b - r) / d + 2.0
        } else {
            (r - g) / d + 4.0
        };
        h * 60.0
    }

    /// Saturation (0 à 1, au sens TSL).
    pub fn saturation(self) -> f32 {
        let (r, g, b) = (self.0 as f32 / 255.0, self.1 as f32 / 255.0, self.2 as f32 / 255.0);
        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        let l = (max + min) / 2.0;
        if max == min { 0.0 } else { (max - min) / (1.0 - (2.0 * l - 1.0).abs()) }
    }
}

fn trim(a: f32) -> String {
    let s = format!("{a:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() { "0".into() } else { s.into() }
}

/// Rapport de contraste WCAG entre deux couleurs (1 à 21).
pub fn contrast(a: Rgb, b: Rgb) -> f32 {
    let (la, lb) = (a.luminance(), b.luminance());
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// Contraste minimal d'un texte (couleur principale sur le fond).
pub const TEXT_CONTRAST: f32 = 4.5;
/// Contraste minimal d'un objet graphique (courbes, barres : couleur secondaire).
pub const GRAPHIC_CONTRAST: f32 = 3.0;

const BLACK: Rgb = Rgb(0, 0, 0);
const WHITE: Rgb = Rgb(255, 255, 255);

/// Plus petit mélange vers le noir (fond clair) ou le blanc (fond sombre) qui donne au moins
/// `min` de contraste sur `bg` (et sur `bg2`, la surface des cartes).
pub fn ensure_contrast(c: Rgb, bg: Rgb, bg2: Rgb, min: f32) -> Rgb {
    let toward = if bg.luminance() > 0.5 { BLACK } else { WHITE };
    for step in 0..=100 {
        let x = c.mix(toward, step as f32 / 100.0);
        if contrast(x, bg) >= min && contrast(x, bg2) >= min {
            return x;
        }
    }
    toward
}

/// Fonds (sombre, clair) de chaque ton.
pub fn backgrounds(t: Tone) -> (Rgb, Rgb) {
    match t {
        Tone::Cold => (Rgb(0x0a, 0x0d, 0x12), Rgb(0xf2, 0xf5, 0xf9)),
        Tone::Neutral => (Rgb(0x0b, 0x0d, 0x10), Rgb(0xf5, 0xf5, 0xf3)),
        Tone::Warm => (Rgb(0x0e, 0x0c, 0x0b), Rgb(0xf7, 0xf2, 0xec)),
    }
}

/// Jetons CSS (`--nom`, valeur) d'un thème, clair ou sombre. Les feuilles de style n'emploient
/// que ces variables pour la couleur.
pub fn tokens(s: &ThemeSettings, dark: bool) -> Vec<(&'static str, String)> {
    let def = ThemeSettings::default();
    let acc = Rgb::parse(&s.primary).or_else(|| Rgb::parse(&def.primary)).unwrap_or(Rgb(0x5f, 0xd0, 0xa0));
    let sec = Rgb::parse(&s.secondary).or_else(|| Rgb::parse(&def.secondary)).unwrap_or(Rgb(0x9f, 0xb4, 0xff));
    let (bg_dark, bg_light) = backgrounds(s.tone);
    let bg = if dark { bg_dark } else { bg_light };
    // Surface des cartes (verre léger) vue sur le fond : blanc à 3,5 % en sombre, à 75 % en clair.
    let surface = if dark { bg.mix(WHITE, 0.035) } else { bg.mix(WHITE, 0.75) };
    let text = if dark { Rgb(0xe6, 0xe8, 0xeb) } else { Rgb(0x1b, 0x1d, 0x21) };
    let muted = if dark { Rgb(0xa9, 0xaf, 0xb8) } else { Rgb(0x5a, 0x61, 0x6b) };
    let faint = if dark { Rgb(0x7d, 0x84, 0x8f) } else { Rgb(0x6c, 0x73, 0x7d) };
    let ink = ensure_contrast(acc, bg, surface, TEXT_CONTRAST);
    let ink2 = ensure_contrast(sec, bg, surface, GRAPHIC_CONTRAST);
    // Bouton principal : dégradé de la couleur (assombrie en clair), texte le plus lisible.
    let fill = if dark { acc } else { ink };
    let fill_top = fill.mix(WHITE, if dark { 0.28 } else { 0.12 });
    let on_fill = best_on(fill);
    // Arrêt : corail, sauf si la couleur principale est déjà rouge-orangé (alors perle).
    let warm_accent = {
        let h = acc.hue();
        acc.saturation() > 0.35 && !(35.0..=340.0).contains(&h)
    };
    let (stop_a, stop_b) = if warm_accent {
        (Rgb(0xe9, 0xed, 0xf2), Rgb(0xc4, 0xcc, 0xd6))
    } else {
        (Rgb(0xf2, 0xa4, 0x8f), Rgb(0xe0, 0x7a, 0x5f))
    };
    let danger = ensure_contrast(Rgb(0xef, 0x7f, 0x73), bg, surface, TEXT_CONTRAST);
    let warn = ensure_contrast(Rgb(0xf0, 0xa8, 0x68), bg, surface, TEXT_CONTRAST);
    let gold = ensure_contrast(Rgb(0xe6, 0xc4, 0x77), bg, surface, GRAPHIC_CONTRAST);
    let line = if dark { WHITE.rgba(0.07) } else { BLACK.rgba(0.08) };
    let line_strong = if dark { WHITE.rgba(0.12) } else { BLACK.rgba(0.14) };
    vec![
        ("--bg", bg.hex()),
        ("--glow", acc.rgba(if dark { 0.10 } else { 0.16 })),
        ("--surface", if dark { WHITE.rgba(0.035) } else { WHITE.rgba(0.72) }),
        ("--surface-2", if dark { WHITE.rgba(0.06) } else { BLACK.rgba(0.04) }),
        ("--surface-3", if dark { WHITE.rgba(0.10) } else { BLACK.rgba(0.07) }),
        ("--surface-solid", if dark { bg.mix(WHITE, 0.06).hex() } else { WHITE.hex() }),
        ("--sunken", if dark { BLACK.rgba(0.35) } else { BLACK.rgba(0.045) }),
        ("--line", line),
        ("--line-strong", line_strong),
        ("--text", text.hex()),
        ("--muted", muted.hex()),
        ("--faint", faint.hex()),
        ("--accent", ink.hex()),
        ("--accent-raw", acc.hex()),
        ("--accent-soft", acc.rgba(if dark { 0.11 } else { 0.14 })),
        ("--accent-line", acc.rgba(if dark { 0.22 } else { 0.35 })),
        ("--accent-text", if dark { acc.mix(WHITE, 0.45).hex() } else { ink.mix(BLACK, 0.12).hex() }),
        ("--accent-fill", format!("linear-gradient(180deg, {}, {})", fill_top.hex(), fill.hex())),
        ("--accent-fill-flat", fill.hex()),
        ("--on-accent", on_fill.hex()),
        ("--accent-shadow", fill.rgba(0.6)),
        ("--accent-2", ink2.hex()),
        ("--accent-2-soft", sec.rgba(if dark { 0.12 } else { 0.18 })),
        ("--stop-fill", format!("linear-gradient(180deg, {}, {})", stop_a.hex(), stop_b.hex())),
        ("--on-stop", Rgb(0x1a, 0x0f, 0x0b).hex()),
        ("--stop-shadow", stop_b.rgba(0.6)),
        ("--danger", danger.hex()),
        ("--danger-soft", Rgb(0xef, 0x7f, 0x73).rgba(0.12)),
        ("--warn", warn.hex()),
        ("--warn-soft", Rgb(0xf0, 0xa8, 0x68).rgba(if dark { 0.08 } else { 0.14 })),
        ("--gold", gold.hex()),
        ("--focus", ink.hex()),
        (
            "--shadow",
            if dark {
                "0 20px 50px -30px rgba(0,0,0,0.8)".into()
            } else {
                "0 1px 2px rgba(0,0,0,0.05), 0 16px 40px -28px rgba(0,0,0,0.35)".into()
            },
        ),
        ("--scheme", if dark { "dark".into() } else { "light".into() }),
    ]
}

/// Texte posé sur une couleur pleine : quasi-noir ou blanc, le plus contrasté.
pub fn best_on(fill: Rgb) -> Rgb {
    let dark = Rgb(0x06, 0x0b, 0x0d);
    if contrast(dark, fill) >= contrast(WHITE, fill) { dark } else { WHITE }
}

/// Couleur de la barre d'état (meta `theme-color`) : le fond.
pub fn bar_color(s: &ThemeSettings, dark: bool) -> String {
    let (d, l) = backgrounds(s.tone);
    if dark { d.hex() } else { l.hex() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(t: &[(&'static str, String)], name: &str) -> Rgb {
        Rgb::parse(&t.iter().find(|(k, _)| *k == name).unwrap().1).unwrap()
    }

    #[test]
    fn lecture_des_couleurs() {
        assert_eq!(Rgb::parse("#5fd0a0"), Some(Rgb(0x5f, 0xd0, 0xa0)));
        assert_eq!(Rgb::parse("#5FD0A0"), Some(Rgb(0x5f, 0xd0, 0xa0)));
        for bad in ["5fd0a0", "#5fd0a", "#5fd0a0f", "#gggggg", "", "#", "red", "#5fd0a0;x"] {
            assert_eq!(Rgb::parse(bad), None, "{bad}");
        }
        assert!((contrast(BLACK, WHITE) - 21.0).abs() < 0.01);
    }

    /// Les 12 × 12 couleurs proposées, sur les 3 fonds, en clair et en sombre : couleur
    /// principale ≥ 4,5:1 sur le fond et sur les cartes, secondaire ≥ 3:1, texte du bouton
    /// principal ≥ 4,5:1 ; en clair, la principale est bien assombrie.
    #[test]
    fn contrastes_de_toutes_les_combinaisons() {
        for (_, _, p) in PRIMARY {
            for (_, _, s) in SECONDARY {
                for tone in Tone::ALL {
                    let set =
                        ThemeSettings { primary: p.into(), secondary: s.into(), tone, appearance: Appearance::Auto };
                    for dark in [false, true] {
                        let t = tokens(&set, dark);
                        let bg = token(&t, "--bg");
                        let acc = token(&t, "--accent");
                        assert!(contrast(acc, bg) >= TEXT_CONTRAST, "{p} {tone:?} dark={dark}");
                        assert!(contrast(token(&t, "--accent-2"), bg) >= GRAPHIC_CONTRAST, "{s} {tone:?} {dark}");
                        let fill = token(&t, "--accent-fill-flat");
                        assert!(contrast(token(&t, "--on-accent"), fill) >= TEXT_CONTRAST, "{p} {dark}");
                        assert!(contrast(token(&t, "--text"), bg) >= 7.0);
                        assert!(contrast(token(&t, "--muted"), bg) >= TEXT_CONTRAST, "{tone:?} {dark}");
                        assert!(contrast(token(&t, "--danger"), bg) >= TEXT_CONTRAST);
                        assert!(contrast(token(&t, "--warn"), bg) >= TEXT_CONTRAST);
                        if !dark {
                            assert!(acc.luminance() < Rgb::parse(p).unwrap().luminance(), "{p} assombrie en clair");
                        }
                    }
                }
            }
        }
    }

    /// Couleurs personnalisées extrêmes : le contraste tient quand même.
    #[test]
    fn couleurs_personnalisees_extremes() {
        for c in ["#000000", "#ffffff", "#000080", "#ffff00", "#808080", "#123456", "#fefefe", "#010101"] {
            for dark in [false, true] {
                let set = ThemeSettings { primary: c.into(), secondary: c.into(), ..Default::default() };
                let t = tokens(&set, dark);
                let bg = token(&t, "--bg");
                assert!(contrast(token(&t, "--accent"), bg) >= TEXT_CONTRAST, "{c} {dark}");
                assert!(contrast(token(&t, "--accent-2"), bg) >= GRAPHIC_CONTRAST, "{c} {dark}");
                assert!(contrast(token(&t, "--on-accent"), token(&t, "--accent-fill-flat")) >= TEXT_CONTRAST);
            }
        }
    }

    #[test]
    fn arret_perle_si_la_principale_est_rouge() {
        let stop = |p: &str| {
            let t = tokens(&ThemeSettings { primary: p.into(), ..Default::default() }, true);
            t.iter().find(|(k, _)| *k == "--stop-fill").unwrap().1.clone()
        };
        assert!(stop("#ff8a65").contains("#e9edf2"), "braise : perle");
        assert!(stop("#5fd0a0").contains("#f2a48f"), "émeraude : corail");
    }

    #[test]
    fn reglage_valide() {
        assert!(ThemeSettings::default().valid());
        let bad = ThemeSettings { primary: "red".into(), ..Default::default() };
        assert!(!bad.valid());
        let j = serde_json::to_string(&ThemeSettings::default()).unwrap();
        assert_eq!(j, r##"{"primary":"#5fd0a0","secondary":"#9fb4ff","tone":"neutral","appearance":"auto"}"##);
    }
}
