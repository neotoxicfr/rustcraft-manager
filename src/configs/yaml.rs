//! YAML (Bukkit, Spigot, Paper, Purpur, mods) : analyse par saphyr-parser (YAML 1.2, positions
//! de chaque nœud) et éditions CIBLÉES sur le texte : seule la valeur touchée est réécrite, dans
//! son style d'origine (simple, entre apostrophes, entre guillemets) ; commentaires, ordre,
//! indentation et clés inconnues restent tels quels. Aucune bibliothèque YAML de Rust ne
//! réécrit un fichier en gardant ses commentaires : pas de re-sérialisation.

use super::{Budget, Lines, comment_above, error_at};
use rc_manager_shared::{ConfigEdit, ConfigEntry, ConfigError, ConfigSeg, ConfigValue, EntryKind, Unverifiable};
use saphyr_parser::{Event, Parser, ScalarStyle};
use std::ops::Range;

/// Style d'une valeur éditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Plain,
    /// `clé:` sans valeur (nulle) : la valeur s'insère après les deux-points.
    Empty,
    Single,
    Double,
}

#[derive(Debug, Clone)]
struct Item {
    /// Octets de la valeur dans le texte.
    span: Range<usize>,
    style: Style,
    /// Seul nœud de sa ligne (`- valeur`, commentaire permis) : la ligne peut partir entière.
    alone: bool,
}

#[derive(Debug, Clone)]
struct List {
    flow: bool,
    /// Octets de `[` et de `]` (liste en ligne).
    open: usize,
    close: usize,
    /// Éléments simples éditables (dans l'ordre) ; `None` si un élément ne l'est pas.
    items: Option<Vec<Item>>,
}

#[derive(Debug, Clone)]
struct Node {
    entry: ConfigEntry,
    item: Option<Item>,
    list: Option<List>,
}

enum Frame {
    Map { path: Vec<ConfigSeg>, key: Option<(String, u32)>, flow: bool },
    Seq { path: Vec<ConfigSeg>, index: usize, node: Option<usize>, flow: bool },
}

/// Valeur d'un scalaire simple (schéma de base de YAML 1.2).
pub fn interpret_plain(s: &str) -> ConfigValue {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return ConfigValue::Null,
        "true" | "True" | "TRUE" => return ConfigValue::Bool(true),
        "false" | "False" | "FALSE" => return ConfigValue::Bool(false),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => return ConfigValue::Float(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => return ConfigValue::Float(f64::NEG_INFINITY),
        ".nan" | ".NaN" | ".NAN" => return ConfigValue::Float(f64::NAN),
        _ => {}
    }
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    if !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && let Ok(n) = s.parse::<i64>()
    {
        return ConfigValue::Int(n);
    }
    let float_like = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'-' | b'+'))
        && digits.bytes().next().is_some_and(|b| b.is_ascii_digit() || b == b'.')
        && digits.bytes().any(|b| b.is_ascii_digit());
    if float_like && let Ok(f) = s.parse::<f64>() {
        return ConfigValue::Float(f);
    }
    ConfigValue::Str(s.to_string())
}

/// Nombre à virgule écrit pour YAML 1.1 et 1.2 (point toujours présent : SnakeYAML, lu par Paper,
/// lirait `1e5` comme un texte).
pub fn render_float(f: f64) -> String {
    if f.is_nan() {
        return ".nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { ".inf".into() } else { "-.inf".into() };
    }
    let s = format!("{f:?}");
    if s.contains('.') {
        s
    } else if let Some((m, e)) = s.split_once('e') {
        format!("{m}.0e{}", if e.starts_with('-') { e.to_string() } else { format!("+{e}") })
    } else {
        format!("{s}.0")
    }
}

/// Caractère à échapper : contrôles (U+0085 compris), et ce que YAML 1.1 (SnakeYAML) lit comme
/// une fin de ligne (U+2028, U+2029) ou retire (U+FEFF) alors que YAML 1.2 le garde : écrit tel
/// quel, il ferait commencer une autre clé côté serveur.
fn must_escape(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}')
}

/// Nombre écrit selon YAML 1.1 : `Some(Ok(n))` entier, `Some(Err(()))` base 60 (`12:30`),
/// `None` sinon. Expressions du résolveur de SnakeYAML.
fn int11(b: &str) -> Option<Result<i128, ()>> {
    let digits =
        |t: &str, ok: fn(u8) -> bool| !t.is_empty() && t.bytes().all(|c| ok(c) || c == b'_') && t.bytes().any(ok);
    let parse = |t: &str, radix| i128::from_str_radix(&t.replace('_', ""), radix).ok().map(Ok);
    if let Some(t) = b.strip_prefix("0b") {
        return if digits(t, |c| matches!(c, b'0' | b'1')) { parse(t, 2) } else { None };
    }
    if let Some(t) = b.strip_prefix("0x") {
        return if digits(t, |c| c.is_ascii_hexdigit()) { parse(t, 16) } else { None };
    }
    if b == "0" {
        return Some(Ok(0));
    }
    if let Some(t) = b.strip_prefix('0') {
        return if digits(t, |c| (b'0'..=b'7').contains(&c)) { parse(t, 8) } else { None };
    }
    let first_ok = b.bytes().next().is_some_and(|c| (b'1'..=b'9').contains(&c));
    if first_ok && b.bytes().all(|c| c.is_ascii_digit() || c == b'_') {
        return parse(b, 10);
    }
    let mut parts = b.split(':');
    let head = parts.next().unwrap_or("");
    let sexa = first_ok
        && b.contains(':')
        && head.bytes().all(|c| c.is_ascii_digit() || c == b'_')
        && parts.all(|p| (1..=2).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()) && p < "60");
    sexa.then_some(Err(()))
}

/// Nombre à virgule selon YAML 1.1 (SnakeYAML) : `Some(Some(f))`, base 60 : `Some(None)`.
fn float11(b: &str) -> Option<Option<f64>> {
    match b {
        ".inf" | ".Inf" | ".INF" => return Some(Some(f64::INFINITY)),
        _ => {}
    }
    let (mant, exp) = match b.find(['e', 'E']) {
        Some(i) => (&b[..i], Some(&b[i + 1..])),
        None => (b, None),
    };
    let exp_ok = exp.is_none_or(|e| {
        let d = e.strip_prefix(['-', '+']).unwrap_or(e);
        !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())
    });
    let mant_ok = match mant.split_once('.') {
        Some(("", frac)) => !frac.is_empty() && frac.bytes().all(|c| c.is_ascii_digit()),
        Some((int, frac)) => {
            !int.is_empty()
                && int.bytes().all(|c| c.is_ascii_digit() || c == b'_')
                && frac.bytes().all(|c| c.is_ascii_digit() || c == b'_')
        }
        None => !mant.is_empty() && mant.bytes().all(|c| c.is_ascii_digit() || c == b'_'),
    };
    if mant_ok && exp_ok {
        let clean = b.replace('_', "");
        return Some(clean.parse::<f64>().ok());
    }
    // Base 60 avec virgule (`190:20:30.15`).
    let sexa = b
        .split_once('.')
        .is_some_and(|(h, f)| int11(h) == Some(Err(())) && f.bytes().all(|c| c.is_ascii_digit() || c == b'_'));
    sexa.then_some(None)
}

/// Lecture d'un scalaire simple par YAML 1.1 (SnakeYAML, lu par Bukkit, Spigot, Paper, Purpur) :
/// `None` pour un type que le visuel ne représente pas (date, base 60, `<<`, `=`, nombre hors
/// bornes).
fn yaml11(s: &str) -> Option<ConfigValue> {
    match s {
        "" | "~" | "null" | "Null" | "NULL" | " " => return Some(ConfigValue::Null),
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => return Some(ConfigValue::Bool(true)),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => {
            return Some(ConfigValue::Bool(false));
        }
        "<<" | "=" | ".nan" | ".NaN" | ".NAN" => {
            return s.starts_with('.').then_some(ConfigValue::Float(f64::NAN));
        }
        _ => {}
    }
    let (neg, body) = match s.as_bytes()[0] {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    if let Some(n) = int11(body) {
        let n = n.ok()?;
        return i64::try_from(if neg { -n } else { n }).ok().map(ConfigValue::Int);
    }
    if let Some(f) = float11(body) {
        let f = f?;
        return Some(ConfigValue::Float(if neg { -f } else { f }));
    }
    // Date et horodatage (`2026-10-20`, `2026-10-20 12:30:00`).
    let b = s.as_bytes();
    if b.len() >= 8 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[5].is_ascii_digit() {
        return None;
    }
    Some(ConfigValue::Str(s.to_string()))
}

/// YAML 1.1 (le serveur) et 1.2 (l'analyseur du gestionnaire) lisent ce scalaire simple de la
/// même façon. Sinon (`0755` : 493 pour SnakeYAML, 755 en 1.2 ; `0x10`, `1_000`, `12:30`,
/// `2026-10-20`) le visuel l'affiche tel quel et le laisse au mode texte.
fn same_in_11(s: &str) -> bool {
    match (yaml11(s), interpret_plain(s)) {
        (Some(ConfigValue::Float(a)), ConfigValue::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
        (Some(a), b) => a == b,
        (None, _) => false,
    }
}

/// Texte simple sûr (relu comme le même texte, sans guillemets, en YAML 1.2 ET 1.1).
fn plain_ok(s: &str, flow: bool) -> bool {
    let Some(first) = s.chars().next() else { return false };
    !s.starts_with(char::is_whitespace)
        && !s.ends_with(char::is_whitespace)
        && !"-?:,[]{}#&*!|>'\"%@`".contains(first)
        && !s.contains(": ")
        && !s.contains(" #")
        && !s.ends_with(':')
        && !s.chars().any(must_escape)
        && !(flow && s.contains([',', '[', ']', '{', '}']))
        // YAML 1.1 (SnakeYAML) lit aussi ces mots comme des booléens.
        && !matches!(s.to_ascii_lowercase().as_str(), "yes" | "no" | "on" | "off" | "y" | "n")
        && interpret_plain(s) == ConfigValue::Str(s.to_string())
        && yaml11(s) == Some(ConfigValue::Str(s.to_string()))
}

fn double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if must_escape(c) => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Écrit une valeur ; le style d'origine d'un texte est gardé quand c'est possible.
fn render(v: &ConfigValue, style: Style, flow: bool) -> String {
    match v {
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        ConfigValue::Float(f) => render_float(*f),
        ConfigValue::Null => "null".into(),
        ConfigValue::Str(s) => {
            if s.chars().any(must_escape) || style == Style::Double {
                double_quoted(s)
            } else if style == Style::Single || !plain_ok(s, flow) {
                format!("'{}'", s.replace('\'', "''"))
            } else {
                s.clone()
            }
        }
    }
}

/// Fin (octet exclu) d'un texte entre apostrophes ou guillemets qui commence en `start`, sur la
/// même ligne ; `None` s'il continue sur la ligne suivante.
fn quoted_end(t: &str, start: usize, quote: u8) -> Option<usize> {
    let b = t.as_bytes();
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\n' | b'\r' => return None,
            b'\\' if quote == b'"' => i += 2,
            q if q == quote => {
                if quote == b'\'' && b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                } else {
                    return Some(i + 1);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Reste de la ligne après `end` : blancs et commentaire seulement ?
fn rest_is_blank(t: &str, end: usize) -> bool {
    let rest = &t[end..];
    let line = &rest[..rest.find(['\n', '\r']).unwrap_or(rest.len())];
    let l = line.trim_start();
    l.is_empty() || l.starts_with('#')
}

struct Doc {
    nodes: Vec<Node>,
}

/// Analyse : erreur de l'analyseur (ligne, colonne) ou arbre. Un document que le visuel ne sait
/// pas représenter (clé complexe, plusieurs documents) rend un arbre vide.
fn analyze(text: &str) -> Result<Doc, ConfigError> {
    let lines = Lines::new(text);
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut docs = 0;
    let mut unsupported = false;
    let mut budget = Budget::default();
    fn add(nodes: &mut Vec<Node>, budget: &mut Budget, n: Node) -> Result<(), ConfigError> {
        budget.take(&n.entry)?;
        nodes.push(n);
        Ok(())
    }
    // Chemin, ligne de la clé et contexte en ligne du prochain nœud.
    fn child(stack: &[Frame]) -> Option<(Vec<ConfigSeg>, Option<u32>, bool)> {
        match stack.last()? {
            Frame::Map { path, key: Some((k, line)), flow } => {
                let mut p = path.clone();
                p.push(ConfigSeg::Key(k.clone()));
                Some((p, Some(*line), *flow))
            }
            Frame::Map { .. } => None,
            Frame::Seq { path, index, flow, .. } => {
                let mut p = path.clone();
                p.push(ConfigSeg::Index(*index));
                Some((p, None, *flow))
            }
        }
    }
    fn advance(stack: &mut [Frame]) {
        match stack.last_mut() {
            Some(Frame::Map { key, .. }) => *key = None,
            Some(Frame::Seq { index, .. }) => *index += 1,
            None => {}
        }
    }
    for ev in Parser::new_from_str(text) {
        let (ev, span) =
            ev.map_err(|e| error_at(e.marker().line() as u32, e.marker().col() as u32 + 1, e.info().to_string()))?;
        let start = lines.char_to_byte(span.start.index());
        let ev_line = span.start.line() as u32;
        // Pile bornée (`- - - - … x` : chaque niveau copierait le chemin entier).
        Budget::nest(stack.len(), ev_line)?;
        match ev {
            Event::DocumentStart(_) => {
                docs += 1;
                unsupported |= docs > 1;
            }
            // Racine : section sans entrée propre ; une liste à la racine reste au mode texte.
            Event::MappingStart(anchor, tag) if stack.is_empty() => {
                unsupported |= anchor != 0 || tag.is_some();
                let flow = text.as_bytes().get(start) == Some(&b'{');
                stack.push(Frame::Map { path: Vec::new(), key: None, flow });
            }
            Event::SequenceStart(..) if stack.is_empty() => {
                unsupported = true;
                stack.push(Frame::Seq { path: Vec::new(), index: 0, node: None, flow: false });
            }
            Event::MappingStart(anchor, tag) => {
                let Some((path, key_line, _)) = child(&stack) else {
                    // Clé complexe (section en guise de clé) : hors du visuel.
                    unsupported = true;
                    stack.push(Frame::Map { path: Vec::new(), key: None, flow: false });
                    continue;
                };
                let flow = text.as_bytes().get(start) == Some(&b'{');
                let line = key_line.unwrap_or(ev_line);
                add(
                    &mut nodes,
                    &mut budget,
                    Node {
                        entry: ConfigEntry {
                            path: path.clone(),
                            kind: EntryKind::Section,
                            value: None,
                            raw: None,
                            comment: key_line.and_then(|l| comment_above(&lines, l)),
                            editable_list: false,
                            line,
                        },
                        item: None,
                        list: None,
                    },
                )?;
                unsupported |= anchor != 0 || tag.is_some();
                stack.push(Frame::Map { path, key: None, flow });
            }
            Event::SequenceStart(anchor, tag) => {
                let Some((path, key_line, _)) = child(&stack) else {
                    unsupported = true;
                    stack.push(Frame::Seq { path: Vec::new(), index: 0, node: None, flow: false });
                    continue;
                };
                let flow = text.as_bytes().get(start) == Some(&b'[');
                add(
                    &mut nodes,
                    &mut budget,
                    Node {
                        entry: ConfigEntry {
                            path: path.clone(),
                            kind: EntryKind::List,
                            value: None,
                            raw: None,
                            comment: key_line.and_then(|l| comment_above(&lines, l)),
                            editable_list: anchor == 0 && tag.is_none(),
                            line: key_line.unwrap_or(ev_line),
                        },
                        item: None,
                        list: Some(List { flow, open: start, close: start, items: Some(Vec::new()) }),
                    },
                )?;
                stack.push(Frame::Seq { path, index: 0, node: Some(nodes.len() - 1), flow });
            }
            Event::MappingEnd => {
                stack.pop();
                advance(&mut stack);
            }
            Event::SequenceEnd => {
                if let Some(Frame::Seq { node: Some(n), .. }) = stack.pop() {
                    if let Some(l) = nodes[n].list.as_mut() {
                        l.close = start;
                        if l.items.as_ref().is_none_or(Vec::is_empty) && !l.flow {
                            l.items = None;
                        }
                    }
                    let ok = nodes[n].list.as_ref().is_some_and(|l| l.items.is_some());
                    nodes[n].entry.editable_list &= ok;
                }
                advance(&mut stack);
            }
            Event::Scalar(v, style, anchor, tag) => {
                if let Some(Frame::Map { key: key @ None, .. }) = stack.last_mut() {
                    // Clé de section.
                    *key = Some((v.to_string(), ev_line));
                    continue;
                }
                let Some((path, key_line, flow)) = child(&stack) else { continue };
                let plain_text = style == ScalarStyle::Plain && text[start..].starts_with(v.as_ref());
                let item = if anchor != 0 || tag.is_some() || (style == ScalarStyle::Plain && !same_in_11(&v)) {
                    None
                } else {
                    match style {
                        // `clé:` sans valeur : la position donnée est celle des deux-points.
                        ScalarStyle::Plain if v.is_empty() => text[start..].starts_with(':').then(|| Item {
                            span: start + 1..start + 1,
                            style: Style::Empty,
                            alone: false,
                        }),
                        ScalarStyle::Plain if plain_text => {
                            Some(Item { span: start..start + v.len(), style: Style::Plain, alone: false })
                        }
                        ScalarStyle::SingleQuoted => quoted_end(text, start, b'\'').map(|e| Item {
                            span: start..e,
                            style: Style::Single,
                            alone: false,
                        }),
                        ScalarStyle::DoubleQuoted => quoted_end(text, start, b'"').map(|e| Item {
                            span: start..e,
                            style: Style::Double,
                            alone: false,
                        }),
                        _ => None,
                    }
                };
                let value = match (&item, style) {
                    (None, _) => None,
                    (Some(_), ScalarStyle::Plain) => Some(interpret_plain(&v)),
                    (Some(_), _) => Some(ConfigValue::Str(v.to_string())),
                };
                let item = item.map(|mut it| {
                    let ls = lines.line_start_of(it.span.start);
                    let before = text[ls..it.span.start].trim();
                    it.alone = before == "-" && rest_is_blank(text, it.span.end);
                    it
                });
                // Élément de liste : retenu pour les ajouts et retraits.
                if let Some(Frame::Seq { node: Some(n), .. }) = stack.last() {
                    let n = *n;
                    if let Some(l) = nodes[n].list.as_mut() {
                        match (&item, l.items.as_mut()) {
                            (Some(it), Some(items)) if l.flow || it.alone => items.push(it.clone()),
                            _ => l.items = None,
                        }
                    }
                }
                let _ = flow;
                add(
                    &mut nodes,
                    &mut budget,
                    Node {
                        entry: ConfigEntry {
                            path,
                            kind: EntryKind::Value,
                            value,
                            raw: item.is_none().then(|| v.to_string()),
                            comment: key_line.and_then(|l| comment_above(&lines, l)),
                            editable_list: false,
                            line: key_line.unwrap_or(ev_line),
                        },
                        item,
                        list: None,
                    },
                )?;
                advance(&mut stack);
            }
            Event::Alias(_) => {
                if let Some((path, key_line, _)) = child(&stack) {
                    if let Some(Frame::Seq { node: Some(n), .. }) = stack.last()
                        && let Some(l) = nodes[*n].list.as_mut()
                    {
                        l.items = None;
                    }
                    let raw = text[start..].split(['\n', '\r', ',', ']', '}']).next().unwrap_or("").trim().to_string();
                    add(
                        &mut nodes,
                        &mut budget,
                        Node {
                            entry: ConfigEntry {
                                path,
                                kind: EntryKind::Value,
                                value: None,
                                raw: Some(raw),
                                comment: None,
                                editable_list: false,
                                line: key_line.unwrap_or(ev_line),
                            },
                            item: None,
                            list: None,
                        },
                    )?;
                }
                advance(&mut stack);
            }
            _ => {}
        }
    }
    for n in &mut nodes {
        if n.entry.kind == EntryKind::List {
            n.entry.editable_list &= n.list.as_ref().is_some_and(|l| l.items.is_some());
        }
    }
    if unsupported {
        nodes.clear();
    }
    Ok(Doc { nodes })
}

pub fn entries(text: &str) -> Result<Vec<ConfigEntry>, ConfigError> {
    Ok(analyze(text)?.nodes.into_iter().map(|n| n.entry).collect())
}

/// Étiquettes du schéma de base (`!!` résolu par l'analyseur).
const CORE_MAP: &str = "tag:yaml.org,2002:map";
const CORE_SEQ: &str = "tag:yaml.org,2002:seq";
const CORE_MERGE: &str = "tag:yaml.org,2002:merge";

/// Nœud de l'arbre complet (lecture des réglages, pas du mode visuel).
enum Y {
    /// Valeur, nature (étiquette, ou style : simple / entre guillemets) ; `bare` : simple sans
    /// étiquette (seul `<<` ainsi écrit est une fusion).
    S {
        v: String,
        kind: String,
        bare: bool,
    },
    M(Vec<(std::rc::Rc<Y>, std::rc::Rc<Y>)>),
    Q(Vec<std::rc::Rc<Y>>),
}

/// Toutes les valeurs de l'arbre COMPLET, quel que soit le mode visuel : ancres et alias résolus,
/// fusions `<<` (SnakeYAML, lu par Bukkit et dérivés, les applique) comprises, étiquettes gardées
/// dans la nature de la valeur. Rend (chemin, valeur, nature) pour chaque feuille, dans l'ordre.
/// Erreur : arbre non représentable par des chemins (clé complexe, alias inconnu, plusieurs
/// documents, arbre trop grand une fois les alias dépliés) : rien ne peut en être conclu.
pub fn flat(text: &str) -> Result<Vec<(Vec<ConfigSeg>, String, String)>, Unverifiable> {
    use Unverifiable as U;
    use std::rc::Rc;
    enum B {
        M(usize, Vec<Rc<Y>>),
        Q(usize, Vec<Rc<Y>>),
    }
    let tag_of = |t: Option<String>, style: ScalarStyle| {
        t.unwrap_or_else(|| if style == ScalarStyle::Plain { "plain".into() } else { "quoted".into() })
    };
    let mut anchors: std::collections::HashMap<usize, Rc<Y>> = std::collections::HashMap::new();
    let mut stack: Vec<B> = Vec::new();
    let mut root: Option<Rc<Y>> = None;
    let mut docs = 0;
    for ev in Parser::new_from_str(text) {
        let (ev, _) = ev.map_err(|_| U::Syntax)?;
        if stack.len() > super::MAX_NEST {
            return Err(U::TooLarge);
        }
        let done: Rc<Y> = match ev {
            Event::DocumentStart(_) => {
                docs += 1;
                if docs > 1 {
                    return Err(U::ManyDocuments);
                }
                continue;
            }
            // Étiquette de section ou de liste autre que la forme de base (`!!omap`, `!!pairs`,
            // `!!set`, étiquette locale) : SnakeYAML en ferait autre chose qu'un arbre de clés.
            Event::MappingStart(a, t) => {
                if t.is_some_and(|t| format!("{}{}", t.handle, t.suffix) != CORE_MAP) {
                    return Err(U::CollectionTag);
                }
                stack.push(B::M(a, Vec::new()));
                continue;
            }
            Event::SequenceStart(a, t) => {
                if t.is_some_and(|t| format!("{}{}", t.handle, t.suffix) != CORE_SEQ) {
                    return Err(U::CollectionTag);
                }
                stack.push(B::Q(a, Vec::new()));
                continue;
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let (a, y) = match stack.pop().ok_or(U::Syntax)? {
                    B::M(a, v) => {
                        if v.len() % 2 != 0 {
                            return Err(U::Syntax);
                        }
                        let mut it = v.into_iter();
                        let mut kv = Vec::new();
                        while let (Some(k), Some(x)) = (it.next(), it.next()) {
                            kv.push((k, x));
                        }
                        (a, Y::M(kv))
                    }
                    B::Q(a, v) => (a, Y::Q(v)),
                };
                let y = Rc::new(y);
                if a != 0 {
                    anchors.insert(a, y.clone());
                }
                y
            }
            Event::Scalar(v, style, a, tag) => {
                let t = tag.as_ref().map(|t| format!("{}{}", t.handle, t.suffix));
                let bare = t.is_none() && style == ScalarStyle::Plain;
                let y = Rc::new(Y::S { v: v.to_string(), kind: tag_of(t, style), bare });
                if a != 0 {
                    anchors.insert(a, y.clone());
                }
                y
            }
            // Alias d'un nœud encore ouvert (ou inconnu) : rien de sûr.
            Event::Alias(a) => anchors.get(&a).ok_or(U::UnknownAlias)?.clone(),
            _ => continue,
        };
        match stack.last_mut() {
            Some(B::M(_, v) | B::Q(_, v)) => v.push(done),
            None => root = Some(done),
        }
    }
    let mut out = Vec::new();
    let mut budget = (Budget::default(), 0usize);
    fn walk(
        y: &Y,
        path: &mut Vec<ConfigSeg>,
        out: &mut Vec<(Vec<ConfigSeg>, String, String)>,
        budget: &mut (Budget, usize),
    ) -> Result<(), Unverifiable> {
        Budget::nest(path.len(), 0).map_err(|_| Unverifiable::TooLarge)?;
        // Nœuds visités (alias dépliés), feuilles ou non : une bombe d'alias s'arrête ici.
        budget.1 += 1;
        if budget.1 > 4 * super::MAX_ENTRIES {
            return Err(Unverifiable::TooLarge);
        }
        match y {
            Y::S { v, kind, .. } => {
                let e = ConfigEntry {
                    path: path.clone(),
                    kind: EntryKind::Value,
                    value: Some(ConfigValue::Str(v.clone())),
                    raw: None,
                    comment: None,
                    editable_list: false,
                    line: 0,
                };
                budget.0.take(&e).map_err(|_| Unverifiable::TooLarge)?;
                out.push((e.path, v.clone(), kind.clone()));
            }
            Y::Q(items) => {
                for (i, x) in items.iter().enumerate() {
                    path.push(ConfigSeg::Index(i));
                    walk(x, path, out, budget)?;
                    path.pop();
                }
            }
            Y::M(kv) => {
                for (k, x) in kv {
                    // Clé complexe (section ou liste en guise de clé) : pas de chemin.
                    let Y::S { v: key, bare, kind } = &**k else { return Err(Unverifiable::ComplexKey) };
                    // Fusion (`<<` simple, ou toute clé d'étiquette `!!merge` quel que soit son
                    // texte, comme SnakeYAML) : les clés de la ou des sections fusionnées valent ici.
                    if (*bare && key == "<<") || kind == CORE_MERGE {
                        match &**x {
                            Y::M(_) => {
                                walk(x, path, out, budget)?;
                                continue;
                            }
                            Y::Q(l) if l.iter().all(|m| matches!(&**m, Y::M(_))) => {
                                for m in l {
                                    walk(m, path, out, budget)?;
                                }
                                continue;
                            }
                            // SnakeYAML refuse une fusion d'autre chose : rien de sûr.
                            _ => return Err(Unverifiable::BadMerge),
                        }
                    }
                    path.push(ConfigSeg::Key(key.clone()));
                    walk(x, path, out, budget)?;
                    path.pop();
                }
            }
        }
        Ok(())
    }
    if let Some(r) = root {
        walk(&r, &mut Vec::new(), &mut out, &mut budget)?;
    }
    Ok(out)
}

fn not_editable() -> ConfigError {
    error_at(0, 0, "valeur non éditable en mode visuel".into())
}

/// Applique une édition ciblée.
pub fn apply(text: &str, edit: &ConfigEdit) -> Result<String, ConfigError> {
    let doc = analyze(text)?;
    let find = |p: &[ConfigSeg]| doc.nodes.iter().find(|n| n.entry.path == p);
    let in_flow =
        |p: &[ConfigSeg]| p.len() > 1 && find(&p[..p.len() - 1]).and_then(|n| n.list.as_ref()).is_some_and(|l| l.flow);
    let splice = |r: Range<usize>, s: &str| format!("{}{}{}", &text[..r.start], s, &text[r.end..]);
    match edit {
        ConfigEdit::Set { path, value } => {
            let n = find(path).ok_or_else(not_editable)?;
            let it = n.item.as_ref().ok_or_else(not_editable)?;
            let mut s = render(value, it.style, in_flow(path));
            if it.style == Style::Empty {
                s.insert(0, ' ');
            }
            Ok(splice(it.span.clone(), &s))
        }
        ConfigEdit::Push { path, value } => {
            let n = find(path).ok_or_else(not_editable)?;
            let l = n.list.as_ref().filter(|_| n.entry.editable_list).ok_or_else(not_editable)?;
            let items = l.items.as_ref().ok_or_else(not_editable)?;
            if l.flow {
                let v = render(value, Style::Plain, true);
                return Ok(match items.last() {
                    None => splice(l.open + 1..l.close, &v),
                    Some(last) => splice(last.span.end..last.span.end, &format!(", {v}")),
                });
            }
            let last = items.last().ok_or_else(not_editable)?;
            let v = render(value, Style::Plain, false);
            let ls = Lines::line_start(text, last.span.start);
            let indent = &text[ls..ls + text[ls..].find('-').unwrap_or(0)];
            let (eol_at, next) = Lines::line_end(text, last.span.end);
            let nl = if text[eol_at..next].is_empty() { "\n" } else { &text[eol_at..next] };
            let ins = if next == eol_at { format!("{nl}{indent}- {v}") } else { format!("{indent}- {v}{nl}") };
            Ok(splice(next..next, &ins))
        }
        ConfigEdit::Remove { path } => {
            let (Some(ConfigSeg::Index(i)), Some(parent)) = (path.last(), path.get(..path.len().saturating_sub(1)))
            else {
                return Err(not_editable());
            };
            let n = find(parent).ok_or_else(not_editable)?;
            let l = n.list.as_ref().filter(|_| n.entry.editable_list).ok_or_else(not_editable)?;
            let items = l.items.as_ref().ok_or_else(not_editable)?;
            let it = items.get(*i).ok_or_else(not_editable)?;
            if l.flow {
                let r = if let Some(next) = items.get(i + 1) {
                    it.span.start..next.span.start
                } else if *i > 0 {
                    items[i - 1].span.end..it.span.end
                } else {
                    it.span.clone()
                };
                return Ok(splice(r, ""));
            }
            if items.len() == 1 {
                // Dernier élément d'une liste en blocs : la liste devient `[]` en ligne.
                let ls = Lines::line_start(text, it.span.start);
                let (_, next) = Lines::line_end(text, it.span.end);
                let before = &text[..ls];
                let key_end = before.trim_end_matches(['\n', '\r']).len();
                if !before[..key_end].ends_with(':') {
                    return Err(not_editable());
                }
                let mut out = format!("{} []", &text[..key_end]);
                out.push_str(&text[key_end..ls]);
                out.push_str(&text[next..]);
                return Ok(out);
            }
            let ls = Lines::line_start(text, it.span.start);
            let (_, next) = Lines::line_end(text, it.span.end);
            Ok(splice(ls..next, ""))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// YAML 1.1 (SnakeYAML, lu par Bukkit et dérivés) contre 1.2 (saphyr) : textes qui seraient
    /// relus comme nombres ou dates mis entre apostrophes ; fins de ligne propres à 1.1 échappées ;
    /// scalaires lus autrement par les deux versions affichés tels quels, hors du visuel.
    #[test]
    fn compatibilite_yaml_1_1() {
        let set = |v: &str| {
            let e = ConfigEdit::Set { path: vec![ConfigSeg::Key("k".into())], value: ConfigValue::Str(v.into()) };
            apply("k: a\n", &e).unwrap()
        };
        for t in ["0x10", "1_000", "12:30", "0b11", "2026-10-20", "0755", "1e5", "+12", ".5", "-.inf", "on", "~", "="] {
            assert_eq!(set(t), format!("k: '{t}'\n"), "{t}");
        }
        for t in ["abc", "Paper", "v1.2", "12 blocs", "x:y", "8080a"] {
            assert_eq!(set(t), format!("k: {t}\n"), "{t}");
        }
        for (c, esc) in
            [('\u{85}', "\\u0085"), ('\u{2028}', "\\u2028"), ('\u{2029}', "\\u2029"), ('\u{feff}', "\\uFEFF")]
        {
            assert_eq!(set(&format!("a{c}b: 1")), format!("k: \"a{esc}b: 1\"\n"), "{c:?}");
        }
        let text = "a: 0755\nb: 0x10\nc: 1_000\nd: 12:30\ne: 2026-10-20\nf: 755\ng: 1e5\nh: 08\ni: 0\nj: -12\nk: 1.5\nl: yes\n";
        let e = entries(text).unwrap();
        let get = |k: &str| e.iter().find(|x| x.path == [ConfigSeg::Key(k.into())]).unwrap();
        for k in ["a", "b", "c", "d", "e", "h"] {
            assert_eq!(get(k).value, None, "{k} : lu autrement par YAML 1.1");
            assert!(get(k).raw.is_some(), "{k}");
        }
        assert_eq!(get("f").value, Some(ConfigValue::Int(755)));
        assert_eq!(get("g").value, Some(ConfigValue::Float(1e5)));
        assert_eq!(get("i").value, Some(ConfigValue::Int(0)));
        assert_eq!(get("j").value, Some(ConfigValue::Int(-12)));
        assert_eq!(get("k").value, Some(ConfigValue::Float(1.5)));
        // `yes` : texte en 1.2, booléen en 1.1 : hors du visuel aussi.
        assert_eq!(get("l").value, None);
    }

    const SRC: &str = "# en-tête\n\n# commentaire de é\né: 'à b'   # garde\nplain: hello world  # c\nnum: 12\nf: 2048.0\ndq: \"x\\ty\"\nempty:\nlist:\n- a\n- 'b'  # deux\nflow: [1, two , \"3\"]\nnone: []\nblk: |\n  ligne\nnested:\n  k: v\n  deep:\n    - x\n";

    fn val(text: &str, p: &[&str]) -> Option<ConfigValue> {
        let path: Vec<ConfigSeg> = p
            .iter()
            .map(|s| s.parse::<usize>().map(ConfigSeg::Index).unwrap_or_else(|_| ConfigSeg::Key((*s).into())))
            .collect();
        entries(text).unwrap().into_iter().find(|e| e.path == path).and_then(|e| e.value)
    }
    fn key(p: &[&str]) -> Vec<ConfigSeg> {
        p.iter()
            .map(|s| s.parse::<usize>().map(ConfigSeg::Index).unwrap_or_else(|_| ConfigSeg::Key((*s).into())))
            .collect()
    }
    fn set(text: &str, p: &[&str], v: ConfigValue) -> String {
        apply(text, &ConfigEdit::Set { path: key(p), value: v }).unwrap()
    }

    #[test]
    fn arbre_et_types() {
        let e = entries(SRC).unwrap();
        assert_eq!(val(SRC, &["é"]), Some(ConfigValue::Str("à b".into())));
        assert_eq!(val(SRC, &["num"]), Some(ConfigValue::Int(12)));
        assert_eq!(val(SRC, &["f"]), Some(ConfigValue::Float(2048.0)));
        assert_eq!(val(SRC, &["empty"]), Some(ConfigValue::Null));
        assert_eq!(val(SRC, &["flow", "2"]), Some(ConfigValue::Str("3".into())));
        assert_eq!(val(SRC, &["nested", "deep", "0"]), Some(ConfigValue::Str("x".into())));
        let blk = e.iter().find(|x| x.path == key(&["blk"])).unwrap();
        assert_eq!((blk.value.clone(), blk.raw.as_deref()), (None, Some("ligne\n")));
        let first = e.iter().find(|x| x.path == key(&["é"])).unwrap();
        assert_eq!(first.comment.as_deref(), Some("commentaire de é"));
        assert_eq!(first.line, 4);
        assert!(e.iter().find(|x| x.path == key(&["list"])).unwrap().editable_list);
    }

    /// Chaque édition ne touche que sa valeur : le reste du texte est identique à l'octet.
    #[test]
    fn editions_ciblees() {
        assert_eq!(set(SRC, &["num"], ConfigValue::Int(40)), SRC.replace("num: 12", "num: 40"));
        assert_eq!(set(SRC, &["é"], ConfigValue::Str("l'été".into())), SRC.replace("é: 'à b'", "é: 'l''été'"));
        // Style d'origine gardé même quand le texte simple suffirait.
        assert_eq!(set(SRC, &["é"], ConfigValue::Str("abc".into())), SRC.replace("é: 'à b'", "é: 'abc'"));
        assert_eq!(set(SRC, &["dq"], ConfigValue::Str("abc".into())), SRC.replace("\"x\\ty\"", "\"abc\""));
        assert_eq!(set(SRC, &["plain"], ConfigValue::Str("yes".into())), SRC.replace("hello world", "'yes'"));
        assert_eq!(set(SRC, &["plain"], ConfigValue::Str("a: b".into())), SRC.replace("hello world", "'a: b'"));
        assert_eq!(set(SRC, &["dq"], ConfigValue::Str("l\"a".into())), SRC.replace("\"x\\ty\"", "\"l\\\"a\""));
        assert_eq!(set(SRC, &["empty"], ConfigValue::Bool(true)), SRC.replace("empty:\n", "empty: true\n"));
        assert_eq!(set(SRC, &["f"], ConfigValue::Float(1e21)), SRC.replace("2048.0", "1.0e+21"));
        assert_eq!(set(SRC, &["flow", "1"], ConfigValue::Str("a,b".into())), SRC.replace("two ", "'a,b' "));
        assert_eq!(set(SRC, &["nested", "k"], ConfigValue::Int(1)), SRC.replace("  k: v", "  k: 1"));
        assert!(apply(SRC, &ConfigEdit::Set { path: key(&["blk"]), value: ConfigValue::Int(1) }).is_err());
    }

    #[test]
    fn listes() {
        let push = |p: &[&str], v: &str| {
            apply(SRC, &ConfigEdit::Push { path: key(p), value: ConfigValue::Str(v.into()) }).unwrap()
        };
        let rm = |p: &[&str]| apply(SRC, &ConfigEdit::Remove { path: key(p) }).unwrap();
        assert_eq!(push(&["list"], "c"), SRC.replace("- 'b'  # deux\n", "- 'b'  # deux\n- c\n"));
        assert_eq!(push(&["flow"], "4"), SRC.replace("\"3\"]", "\"3\", '4']"));
        assert_eq!(push(&["none"], "z"), SRC.replace("none: []", "none: [z]"));
        assert_eq!(push(&["nested", "deep"], "z"), SRC.replace("    - x\n", "    - x\n    - z\n"));
        // `y` est un booléen pour YAML 1.1 (SnakeYAML, lu par Paper) : gardé en texte.
        assert_eq!(push(&["nested", "deep"], "y"), SRC.replace("    - x\n", "    - x\n    - 'y'\n"));
        assert_eq!(rm(&["list", "0"]), SRC.replace("- a\n", ""));
        assert_eq!(rm(&["flow", "0"]), SRC.replace("[1, two", "[two"));
        assert_eq!(rm(&["flow", "2"]), SRC.replace("two , \"3\"]", "two]"));
        assert_eq!(rm(&["nested", "deep", "0"]), SRC.replace("  deep:\n    - x\n", "  deep: []\n"));
    }

    #[test]
    fn erreurs_de_l_analyseur() {
        let e = entries("a: 1\nb: [2\nc: 3\n").unwrap_err();
        assert!(e.line >= 2, "{e:?}");
        let e = entries("a:\n\tb: 1\n").unwrap_err();
        assert_eq!(e.line, 2, "{e:?}");
    }
}
