//! Parité des traductions, sur le TEXTE des sources de l'interface (la crate wasm ne se teste pas
//! sur la cible native) :
//! - chaque clé de `K` a sa traduction en français ET en anglais, non vide, une seule fois ;
//! - la table anglaise ne contient pas de français oublié (lettres accentuées, texte identique) ;
//! - aucun texte visible écrit en dur dans les `view!` (tout passe par `ctx.tr`) ;
//! - les pages servies avant l'interface (noscript, page de repli du binaire, manifeste) sont
//!   dans les deux langues.

use std::collections::{BTreeMap, BTreeSet};

const I18N: &str = include_str!("../web/src/i18n.rs");
const MAIN: &str = include_str!("../web/src/main.rs");
/// Tous les fichiers de l'interface qui contiennent des `view!`.
const VIEWS: &[(&str, &str)] = &[
    ("main.rs", MAIN),
    ("servers.rs", include_str!("../web/src/servers.rs")),
    ("console.rs", include_str!("../web/src/console.rs")),
    ("configs.rs", include_str!("../web/src/configs.rs")),
    ("players.rs", include_str!("../web/src/players.rs")),
    ("files.rs", include_str!("../web/src/files.rs")),
    ("address.rs", include_str!("../web/src/address.rs")),
    ("theme.rs", include_str!("../web/src/theme.rs")),
    ("icons.rs", include_str!("../web/src/icons.rs")),
];
const INDEX: &str = include_str!("../web/index.html");
const BUILD: &str = include_str!("../build.rs");
const MANIFEST: &str = include_str!("../web/public/manifest.webmanifest");

/// Noms propres gardés tels quels dans les deux langues.
const SAME_IN_BOTH: &[&str] =
    &["Rustcraft Manager", "Auto", "Code", "Passkeys", "Ticks/s", "Mojang", "Navigation", "Menu", "Console", "JSON"];
/// Textes en dur permis dans les `view!` (nom de l'application).
const ALLOWED_LITERALS: &[&str] = &["Rustcraft Manager"];

fn enum_keys() -> BTreeSet<String> {
    let start = I18N.find("pub enum K {").expect("enum K");
    let body = &I18N[start + "pub enum K {".len()..];
    let body = &body[..body.find('}').unwrap()];
    body.lines()
        .map(|l| l.trim().trim_end_matches(','))
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .map(str::to_string)
        .collect()
}

/// Lit une chaîne Rust à partir du guillemet ouvrant ; rend (contenu, fin).
fn read_string(s: &str, open: usize) -> (String, usize) {
    let b = s.as_bytes();
    let mut i = open + 1;
    let mut out = String::new();
    while i < b.len() {
        match b[i] {
            b'\\' => {
                out.push(b[i + 1] as char);
                i += 2;
            }
            b'"' => return (out, i + 1),
            _ => {
                let ch = s[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    panic!("chaîne non fermée");
}

/// Bras `K::X => "…"` de la fonction de traduction `name`.
fn arms(name: &str) -> Vec<(String, String)> {
    let head = format!("fn {name}(k: K)");
    let start = I18N.find(&head).unwrap_or_else(|| panic!("{head} absent"));
    let rest = &I18N[start + head.len()..];
    let end = rest.find("\nfn ").or_else(|| rest.find("\npub fn ")).unwrap_or(rest.len());
    let body = &rest[..end];
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = body[pos..].find("K::") {
        let at = pos + i + 3;
        let key: String = body[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        let after = at + key.len();
        let arrow = body[after..].trim_start();
        if !arrow.starts_with("=>") {
            pos = after;
            continue;
        }
        let q = after + body[after..].find('"').expect("traduction : chaîne attendue");
        let (text, end) = read_string(body, q);
        out.push((key, text));
        pos = end;
    }
    out
}

#[test]
fn chaque_cle_dans_chaque_langue() {
    let keys = enum_keys();
    assert!(keys.len() > 20, "{} clés lues", keys.len());
    let mut tables = BTreeMap::new();
    for lang in ["fr", "en"] {
        let a = arms(lang);
        let mut seen = BTreeSet::new();
        for (k, v) in &a {
            assert!(seen.insert(k.clone()), "{lang} : clé {k} traduite deux fois");
            assert!(!v.trim().is_empty(), "{lang} : clé {k} vide");
        }
        assert_eq!(seen, keys, "{lang} : clés manquantes ou en trop");
        tables.insert(lang, a.into_iter().collect::<BTreeMap<_, _>>());
    }
    for (k, en) in &tables["en"] {
        let fr = &tables["fr"][k];
        assert!(
            !en.chars().any(|c| "éèêëàâäçùûüôöîïœÉÈÊÀÇ«»’".contains(c)),
            "en : {k} semble encore en français : {en}"
        );
        let letters = en.chars().filter(|c| c.is_alphabetic()).count();
        assert!(
            letters < 4 || en != fr || SAME_IN_BOTH.contains(&en.as_str()),
            "en : {k} identique au français : {en}"
        );
    }
}

/// Blocs `view! { … }` (contenu entre les accolades), imbriqués compris.
fn view_blocks(src: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = src[pos..].find("view! {") {
        let open = pos + i + "view! ".len();
        let b = src.as_bytes();
        let (mut depth, mut j) = (0i32, open);
        while j < b.len() {
            match b[j] {
                b'"' => {
                    j = read_string(src, j).1;
                    continue;
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        out.push(&src[open + 1..j]);
        pos = open + 1;
    }
    out
}

/// Textes visibles écrits en dur : chaînes au premier niveau d'un `view!` (pas dans une
/// expression entre accolades) qui ne sont pas la valeur d'un attribut (`=` juste avant).
fn hard_coded(block: &str) -> Vec<String> {
    let b = block.as_bytes();
    let (mut depth, mut i, mut out) = (0i32, 0usize, Vec::new());
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b'"' => {
                let (text, end) = read_string(block, i);
                let before = block[..i].trim_end();
                // Valeur d'attribut (`=`) ou argument d'un appel (`format!(`) : du code, pas du texte.
                let is_attr = before.ends_with('=') || before.ends_with('(');
                if depth == 0
                    && !is_attr
                    && text.chars().any(char::is_alphabetic)
                    && !ALLOWED_LITERALS.contains(&text.as_str())
                {
                    out.push(text);
                }
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

#[test]
fn aucun_texte_visible_en_dur() {
    for (name, src) in VIEWS {
        let blocks = view_blocks(src);
        assert!(!blocks.is_empty(), "{name} : aucun bloc view! lu");
        let found: Vec<String> = blocks.iter().flat_map(|b| hard_coded(b)).collect();
        assert!(found.is_empty(), "{name} : textes en dur dans l'interface (passer par ctx.tr) : {found:?}");
    }
    // L'analyse elle-même attrape bien un texte en dur.
    assert_eq!(hard_coded(r#"<p>"Bonjour"</p><a href="/x">{move || ctx.tr(K::A)} " "</a>"#), vec!["Bonjour"]);
}

#[test]
fn pages_avant_l_interface_dans_les_deux_langues() {
    let noscript = &INDEX[INDEX.find("<noscript>").unwrap()..INDEX.find("</noscript>").unwrap()];
    assert!(noscript.contains(r#"lang="fr""#) && noscript.contains(r#"lang="en""#), "{noscript}");
    let fallback = &BUILD[BUILD.find("const FALLBACK").unwrap()..];
    let fallback = &fallback[..fallback.find("\";").unwrap()];
    assert!(fallback.contains(r#"lang=\"fr\""#) && fallback.contains(r#"lang=\"en\""#));
    assert!(MANIFEST.contains("Minecraft server manager") && MANIFEST.contains("Gestionnaire"));
}

/// Le navigateur décide de la langue tant qu'aucune n'est choisie.
#[test]
fn langue_du_navigateur() {
    assert!(I18N.contains("pub fn from_browser"));
    assert!(MAIN.contains(".unwrap_or_else(browser_lang)"), "langue par défaut = navigateur");
}
