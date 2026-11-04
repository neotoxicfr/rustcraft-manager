//! JSON et JSON5 (configurations de mods) : analyse avec positions et éditions CIBLÉES (seule la
//! valeur touchée est réécrite ; espaces, ordre, commentaires JSON5 intacts). Le JSON strict est
//! d'abord validé par serde_json (message et position de l'analyseur de référence).

use super::{Budget, Lines, MAX_NEST, error_at};
use rc_manager_shared::{ConfigEdit, ConfigEntry, ConfigError, ConfigSeg, ConfigValue, EntryKind};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Double,
    Single,
}

#[derive(Debug, Clone)]
struct Item {
    span: Range<usize>,
    quote: Quote,
}

#[derive(Debug, Clone)]
struct List {
    open: usize,
    close: usize,
    /// Éléments (tous simples) ; `None` si l'un est une section ou une liste.
    items: Option<Vec<Item>>,
}

#[derive(Debug, Clone)]
struct Node {
    entry: ConfigEntry,
    item: Option<Item>,
    list: Option<List>,
}

struct P<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
    json5: bool,
    lines: Lines<'a>,
    nodes: Vec<Node>,
    root_ok: bool,
    budget: Budget,
}

impl<'a> P<'a> {
    fn err(&self, msg: &str) -> ConfigError {
        let (l, c) = self.lines.pos(self.i.min(self.b.len()));
        error_at(l, c, msg.into())
    }

    fn ws(&mut self) -> Result<(), ConfigError> {
        loop {
            match self.b.get(self.i) {
                Some(b' ' | b'\t' | b'\n' | b'\r') => self.i += 1,
                // Commentaire de ligne : jusqu'à n'importe quelle fin de ligne de JSON5 (`\n`, `\r`,
                // U+2028, U+2029), sinon une clé écrite après `\r` serait avalée ici et lue par le jeu.
                Some(b'/') if self.json5 && self.b.get(self.i + 1) == Some(&b'/') => {
                    let rest = &self.s[self.i..];
                    self.i += rest.find(['\n', '\r', '\u{2028}', '\u{2029}']).unwrap_or(rest.len());
                }
                Some(b'/') if self.json5 && self.b.get(self.i + 1) == Some(&b'*') => {
                    let start = self.i;
                    match self.s[self.i + 2..].find("*/") {
                        Some(e) => self.i += e + 4,
                        None => {
                            self.i = start;
                            return Err(self.err("commentaire /* non fermé"));
                        }
                    }
                }
                Some(_) if self.json5 => {
                    // Blancs Unicode permis par JSON5 (espace insécable, BOM, séparateurs).
                    let c = self.s[self.i..].chars().next().unwrap_or('x');
                    if c.is_whitespace() || c == '\u{feff}' {
                        self.i += c.len_utf8();
                    } else {
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn string(&mut self) -> Result<(String, Item), ConfigError> {
        let q = self.b[self.i];
        let start = self.i;
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(c) = self.s[self.i..].chars().next() else { return Err(self.err("texte non fermé")) };
            self.i += c.len_utf8();
            match c {
                c if c as u32 == q as u32 => break,
                '\\' => {
                    let Some(e) = self.s[self.i..].chars().next() else { return Err(self.err("texte non fermé")) };
                    self.i += e.len_utf8();
                    match e {
                        '"' | '\\' | '/' => out.push(e),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code) && self.s[self.i..].starts_with("\\u") {
                                self.i += 2;
                                let lo = self.hex4()?;
                                code = 0x10000 + ((code - 0xD800) << 10) + (lo.wrapping_sub(0xDC00) & 0x3FF);
                            }
                            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        '\'' if self.json5 => out.push('\''),
                        'v' if self.json5 => out.push('\u{b}'),
                        '0' if self.json5 => out.push('\0'),
                        'x' if self.json5 => {
                            let h = self.s.get(self.i..self.i + 2).and_then(|h| u32::from_str_radix(h, 16).ok());
                            let Some(h) = h else { return Err(self.err("échappement \\x invalide")) };
                            self.i += 2;
                            out.push(char::from_u32(h).unwrap_or('\u{FFFD}'));
                        }
                        '\n' | '\r' | '\u{2028}' | '\u{2029}' if self.json5 => {
                            if e == '\r' && self.b.get(self.i) == Some(&b'\n') {
                                self.i += 1;
                            }
                        }
                        o if self.json5 && !o.is_ascii_digit() => out.push(o),
                        _ => return Err(self.err("échappement invalide")),
                    }
                }
                '\n' | '\r' => return Err(self.err("retour à la ligne dans un texte")),
                c if (c as u32) < 0x20 && !self.json5 => return Err(self.err("caractère de contrôle dans un texte")),
                c => out.push(c),
            }
        }
        let quote = if q == b'\'' { Quote::Single } else { Quote::Double };
        Ok((out, Item { span: start..self.i, quote }))
    }

    fn hex4(&mut self) -> Result<u32, ConfigError> {
        let h = self.s.get(self.i..self.i + 4).filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
        let Some(h) = h else { return Err(self.err("échappement \\u invalide")) };
        self.i += 4;
        Ok(u32::from_str_radix(h, 16).unwrap_or(0xFFFD))
    }

    fn ident(&mut self) -> Option<String> {
        let start = self.i;
        while let Some(c) = self.s[self.i..].chars().next() {
            if c.is_alphanumeric() || c == '_' || c == '$' {
                self.i += c.len_utf8();
            } else {
                break;
            }
        }
        (self.i > start).then(|| self.s[start..self.i].to_string())
    }

    fn scalar(&mut self) -> Result<(ConfigValue, Item), ConfigError> {
        let start = self.i;
        let word = |p: &mut Self, w: &str| {
            let ok = p.s[p.i..].starts_with(w)
                && !p.s[p.i + w.len()..].chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_');
            if ok {
                p.i += w.len();
            }
            ok
        };
        let v = if word(self, "true") {
            ConfigValue::Bool(true)
        } else if word(self, "false") {
            ConfigValue::Bool(false)
        } else if word(self, "null") {
            ConfigValue::Null
        } else {
            let end = self.s[self.i..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')))
                .map_or(self.b.len(), |e| self.i + e);
            let t = &self.s[self.i..end];
            let parsed = number(t, self.json5).ok_or_else(|| self.err("valeur attendue"))?;
            self.i = end;
            parsed
        };
        Ok((v, Item { span: start..self.i, quote: Quote::None }))
    }

    fn push(
        &mut self,
        path: Vec<ConfigSeg>,
        kind: EntryKind,
        line: u32,
        value: Option<ConfigValue>,
        item: Option<Item>,
    ) -> Result<(), ConfigError> {
        let entry = ConfigEntry { path, kind, value, raw: None, comment: None, editable_list: false, line };
        self.budget.take(&entry)?;
        self.nodes.push(Node { entry, item, list: None });
        Ok(())
    }

    fn value(&mut self, path: Vec<ConfigSeg>, line: u32, depth: usize) -> Result<bool, ConfigError> {
        if depth > MAX_NEST {
            return Err(self.err("imbrication trop profonde"));
        }
        self.ws()?;
        match self.b.get(self.i) {
            Some(b'{') => {
                if depth > 0 {
                    self.push(path.clone(), EntryKind::Section, line, None, None)?;
                }
                self.i += 1;
                loop {
                    self.ws()?;
                    if self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        break;
                    }
                    let kline = self.lines.pos(self.i).0;
                    let key = match self.b.get(self.i) {
                        Some(b'"') => self.string()?.0,
                        Some(b'\'') if self.json5 => self.string()?.0,
                        _ if self.json5 => self.ident().ok_or_else(|| self.err("clé attendue"))?,
                        _ => return Err(self.err("clé attendue")),
                    };
                    self.ws()?;
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(self.err("« : » attendu"));
                    }
                    self.i += 1;
                    let mut p = path.clone();
                    p.push(ConfigSeg::Key(key));
                    self.value(p, kline, depth + 1)?;
                    self.ws()?;
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {}
                        _ => return Err(self.err("« , » ou « } » attendu")),
                    }
                    if !self.json5 && self.b.get(self.i - 1) == Some(&b',') {
                        self.ws()?;
                        if self.b.get(self.i) == Some(&b'}') {
                            return Err(self.err("virgule finale"));
                        }
                    }
                }
                Ok(false)
            }
            Some(b'[') => {
                if depth == 0 {
                    self.root_ok = false;
                }
                let node = self.nodes.len();
                self.push(path.clone(), EntryKind::List, line, None, None)?;
                let open = self.i;
                self.i += 1;
                let mut items: Option<Vec<Item>> = Some(Vec::new());
                let mut idx = 0;
                loop {
                    self.ws()?;
                    if self.b.get(self.i) == Some(&b']') {
                        break;
                    }
                    let mut p = path.clone();
                    p.push(ConfigSeg::Index(idx));
                    let iline = self.lines.pos(self.i).0;
                    let before = self.nodes.len();
                    let simple = self.value(p, iline, depth + 1)?;
                    match (&mut items, simple) {
                        (Some(v), true) => {
                            v.push(self.nodes[before].item.clone().unwrap_or(Item { span: 0..0, quote: Quote::None }))
                        }
                        _ => items = None,
                    }
                    idx += 1;
                    self.ws()?;
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {}
                        _ => return Err(self.err("« , » ou « ] » attendu")),
                    }
                    if !self.json5 && self.b.get(self.i - 1) == Some(&b',') {
                        self.ws()?;
                        if self.b.get(self.i) == Some(&b']') {
                            return Err(self.err("virgule finale"));
                        }
                    }
                }
                let close = self.i;
                self.i += 1;
                let n = &mut self.nodes[node];
                n.entry.editable_list = items.is_some();
                n.list = Some(List { open, close, items });
                Ok(false)
            }
            Some(b'"') | Some(b'\'') if self.b[self.i] == b'"' || self.json5 => {
                let (s, it) = self.string()?;
                self.push(path, EntryKind::Value, line, Some(ConfigValue::Str(s)), Some(it))?;
                Ok(true)
            }
            Some(_) => {
                let (v, it) = self.scalar()?;
                self.push(path, EntryKind::Value, line, Some(v), Some(it))?;
                Ok(true)
            }
            None => Err(self.err("valeur attendue")),
        }
    }
}

/// Nombre JSON (ou JSON5 : `+`, `.5`, `5.`, hexadécimal, `Infinity`, `NaN`).
fn number(t: &str, json5: bool) -> Option<ConfigValue> {
    let (sign, body) = match t.as_bytes().first() {
        Some(b'-') => (-1.0, &t[1..]),
        Some(b'+') if json5 => (1.0, &t[1..]),
        _ => (1.0, t),
    };
    if json5 {
        match body {
            "Infinity" => return Some(ConfigValue::Float(sign * f64::INFINITY)),
            "NaN" => return Some(ConfigValue::Float(f64::NAN)),
            _ => {}
        }
        if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            let n = i64::from_str_radix(h, 16).ok()?;
            return Some(ConfigValue::Int(if sign < 0.0 { -n } else { n }));
        }
    }
    let b = body.as_bytes();
    let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    let (mant, exp) = match body.find(['e', 'E']) {
        Some(e) => (&body[..e], Some(&body[e + 1..])),
        None => (body, None),
    };
    let (int, frac) = match mant.split_once('.') {
        Some((a, f)) => (a, Some(f)),
        None => (mant, None),
    };
    let int_ok = if json5 { int.is_empty() || digits(int.as_bytes()) } else { digits(int.as_bytes()) };
    let lead_zero_ok = json5 || int.len() == 1 || !int.starts_with('0');
    let frac_ok = match frac {
        None => true,
        Some(f) => digits(f.as_bytes()) || (json5 && f.is_empty() && !int.is_empty()),
    };
    let exp_ok = exp.is_none_or(|e| digits(e.strip_prefix(['+', '-']).unwrap_or(e).as_bytes()));
    if b.is_empty() || !int_ok || !lead_zero_ok || !frac_ok || !exp_ok || (int.is_empty() && frac.is_none()) {
        return None;
    }
    if frac.is_none()
        && exp.is_none()
        && let Ok(n) = t.trim_start_matches('+').parse::<i64>()
    {
        return Some(ConfigValue::Int(n));
    }
    let f: f64 = format!("{}{}", if sign < 0.0 { "-" } else { "" }, body.trim_end_matches('.')).parse().ok()?;
    Some(ConfigValue::Float(f))
}

struct Doc {
    nodes: Vec<Node>,
}

fn analyze(text: &str, json5: bool) -> Result<Doc, ConfigError> {
    let (nodes, visual) = parse(text, json5)?;
    // Liste ou valeur seule à la racine : mode texte.
    Ok(Doc { nodes: if visual { nodes } else { Vec::new() } })
}

/// Arbre COMPLET (racine en liste ou valeur seule comprise) : lecture des réglages réservés et
/// des chemins, indépendante du mode visuel.
pub fn entries_all(text: &str, json5: bool) -> Result<Vec<ConfigEntry>, ConfigError> {
    Ok(parse(text, json5)?.0.into_iter().map(|n| n.entry).collect())
}

/// Nœuds de tout le document, et mode visuel possible (racine en section).
fn parse(text: &str, json5: bool) -> Result<(Vec<Node>, bool), ConfigError> {
    if !json5 {
        // Analyseur de référence d'abord (message et position exacts).
        if let Err(e) = serde_json::from_str::<serde::de::IgnoredAny>(text) {
            return Err(error_at(e.line() as u32, e.column() as u32, e.to_string()));
        }
    }
    let mut p = P {
        s: text,
        b: text.as_bytes(),
        i: 0,
        json5,
        lines: Lines::new(text),
        nodes: Vec::new(),
        root_ok: true,
        budget: Budget::default(),
    };
    if text.starts_with('\u{feff}') {
        p.i = 3;
    }
    p.value(Vec::new(), 1, 0)?;
    p.ws()?;
    if p.i < p.b.len() {
        return Err(p.err("texte après la fin du document"));
    }
    let visual = p.root_ok && !p.nodes.first().is_some_and(|n| n.entry.path.is_empty());
    Ok((p.nodes, visual))
}

pub fn entries(text: &str, json5: bool) -> Result<Vec<ConfigEntry>, ConfigError> {
    Ok(analyze(text, json5)?.nodes.into_iter().map(|n| n.entry).collect())
}

fn render(v: &ConfigValue, quote: Quote, json5: bool) -> Result<String, ConfigError> {
    Ok(match v {
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        ConfigValue::Null => "null".into(),
        ConfigValue::Float(f) if f.is_finite() => format!("{f:?}"),
        ConfigValue::Float(f) if json5 => {
            if f.is_nan() {
                "NaN".into()
            } else if *f > 0.0 {
                "Infinity".into()
            } else {
                "-Infinity".into()
            }
        }
        ConfigValue::Float(_) => return Err(error_at(0, 0, "JSON : nombre infini ou NaN impossible".into())),
        ConfigValue::Str(s) if quote == Quote::Single => {
            let inner = serde_json::to_string(s).unwrap_or_default();
            let inner = &inner[1..inner.len() - 1];
            format!("'{}'", inner.replace("\\\"", "\"").replace('\'', "\\'"))
        }
        ConfigValue::Str(s) => serde_json::to_string(s).unwrap_or_default(),
    })
}

fn not_editable() -> ConfigError {
    error_at(0, 0, "valeur non éditable en mode visuel".into())
}

pub fn apply(text: &str, json5: bool, edit: &ConfigEdit) -> Result<String, ConfigError> {
    let doc = analyze(text, json5)?;
    let find = |p: &[ConfigSeg]| doc.nodes.iter().find(|n| n.entry.path == p);
    let splice = |r: Range<usize>, s: &str| format!("{}{}{}", &text[..r.start], s, &text[r.end..]);
    match edit {
        ConfigEdit::Set { path, value } => {
            let n = find(path).ok_or_else(not_editable)?;
            let it = n.item.as_ref().ok_or_else(not_editable)?;
            Ok(splice(it.span.clone(), &render(value, it.quote, json5)?))
        }
        ConfigEdit::Push { path, value } => {
            let n = find(path).ok_or_else(not_editable)?;
            let l = n.list.as_ref().ok_or_else(not_editable)?;
            let items = l.items.as_ref().ok_or_else(not_editable)?;
            let quote = items
                .first()
                .map_or(Quote::Double, |i| if i.quote == Quote::Single { Quote::Single } else { Quote::Double });
            let v = render(value, quote, json5)?;
            let Some(last) = items.last() else { return Ok(splice(l.open + 1..l.close, &v)) };
            let lines = Lines::new(text);
            if lines.pos(last.span.start).0 != lines.pos(l.open).0 {
                // Liste sur plusieurs lignes : nouvel élément sur sa ligne, même indentation.
                let ls = Lines::line_start(text, last.span.start);
                let indent = &text[ls..last.span.start];
                let indent = if indent.trim().is_empty() { indent } else { "" };
                let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
                return Ok(splice(last.span.end..last.span.end, &format!(",{nl}{indent}{v}")));
            }
            Ok(splice(last.span.end..last.span.end, &format!(", {v}")))
        }
        ConfigEdit::Remove { path } => {
            let (Some(ConfigSeg::Index(i)), Some(parent)) = (path.last(), path.get(..path.len().saturating_sub(1)))
            else {
                return Err(not_editable());
            };
            let l = find(parent).and_then(|n| n.list.as_ref()).ok_or_else(not_editable)?;
            let items = l.items.as_ref().ok_or_else(not_editable)?;
            let it = items.get(*i).ok_or_else(not_editable)?;
            let r = if let Some(next) = items.get(i + 1) {
                it.span.start..next.span.start
            } else if *i > 0 {
                items[i - 1].span.end..it.span.end
            } else {
                it.span.clone()
            };
            Ok(splice(r, ""))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(p: &[&str]) -> Vec<ConfigSeg> {
        p.iter()
            .map(|s| s.parse::<usize>().map(ConfigSeg::Index).unwrap_or_else(|_| ConfigSeg::Key((*s).into())))
            .collect()
    }

    const SRC: &str = "{\n  \"a\": 1,\n  \"b\": { \"c\": \"x\\\"y\", \"d\": [1, 2] },\n  \"e\": [\n    \"p\",\n    \"q\"\n  ],\n  \"f\": 1.5e3,\n  \"g\": null\n}\n";

    #[test]
    fn arbre_json() {
        let e = entries(SRC, false).unwrap();
        let get = |p: &[&str]| e.iter().find(|x| x.path == key(p)).and_then(|x| x.value.clone());
        assert_eq!(get(&["a"]), Some(ConfigValue::Int(1)));
        assert_eq!(get(&["b", "c"]), Some(ConfigValue::Str("x\"y".into())));
        assert_eq!(get(&["e", "1"]), Some(ConfigValue::Str("q".into())));
        assert_eq!(get(&["f"]), Some(ConfigValue::Float(1500.0)));
        assert_eq!(get(&["g"]), Some(ConfigValue::Null));
        assert_eq!(e.iter().find(|x| x.path == key(&["e", "1"])).unwrap().line, 6);
    }

    #[test]
    fn editions_json() {
        let set = |p: &[&str], v: ConfigValue| apply(SRC, false, &ConfigEdit::Set { path: key(p), value: v }).unwrap();
        assert_eq!(set(&["a"], ConfigValue::Int(7)), SRC.replace("\"a\": 1", "\"a\": 7"));
        assert_eq!(set(&["b", "c"], ConfigValue::Str("é\n".into())), SRC.replace("\"x\\\"y\"", "\"é\\n\""));
        assert!(
            apply(SRC, false, &ConfigEdit::Set { path: key(&["a"]), value: ConfigValue::Float(f64::NAN) }).is_err()
        );
        let push = |p: &[&str]| {
            apply(SRC, false, &ConfigEdit::Push { path: key(p), value: ConfigValue::Str("r".into()) }).unwrap()
        };
        assert_eq!(push(&["e"]), SRC.replace("    \"q\"\n", "    \"q\",\n    \"r\"\n"));
        assert_eq!(push(&["b", "d"]), SRC.replace("[1, 2]", "[1, 2, \"r\"]"));
        let rm = |p: &[&str]| apply(SRC, false, &ConfigEdit::Remove { path: key(p) }).unwrap();
        assert_eq!(rm(&["e", "1"]), SRC.replace("\"p\",\n    \"q\"", "\"p\""));
        assert_eq!(rm(&["b", "d", "0"]), SRC.replace("[1, 2]", "[2]"));
    }

    #[test]
    fn json5_et_erreurs() {
        let src = "// mod\n{\n  clef: 'a', /* c */ hex: 0x1F, inf: -Infinity,\n  liste: [.5, 2.,],\n}\n";
        let e = entries(src, true).unwrap();
        let get = |p: &[&str]| e.iter().find(|x| x.path == key(p)).and_then(|x| x.value.clone());
        assert_eq!(get(&["clef"]), Some(ConfigValue::Str("a".into())));
        assert_eq!(get(&["hex"]), Some(ConfigValue::Int(31)));
        assert_eq!(get(&["inf"]), Some(ConfigValue::Float(f64::NEG_INFINITY)));
        assert_eq!(get(&["liste", "0"]), Some(ConfigValue::Float(0.5)));
        let out =
            apply(src, true, &ConfigEdit::Set { path: key(&["clef"]), value: ConfigValue::Str("l'a".into()) }).unwrap();
        assert_eq!(out, src.replace("'a'", "'l\\'a'"));
        assert_eq!(entries(&out, true).unwrap()[0].value, Some(ConfigValue::Str("l'a".into())));
        // JSON strict : commentaire et virgule finale refusés, avec la ligne.
        assert_eq!(entries(src, false).unwrap_err().line, 1);
        assert_eq!(entries("{\n\"a\": [1,]\n}", false).unwrap_err().line, 2);
        assert_eq!(entries("{\n\"a\": tru\n}", true).unwrap_err().line, 2);
    }

    /// Commentaire `//` de JSON5 : s'arrête à chaque fin de ligne du format (`\r`, U+2028,
    /// U+2029), comme chez les lecteurs JSON5 des mods ; sinon la clé suivante disparaît du visuel.
    #[test]
    fn json5_fins_de_ligne_du_commentaire() {
        for eol in ["\r", "\u{2028}", "\u{2029}", "\n", "\r\n"] {
            let src = format!("{{a: 1, // note{eol}b: 2}}");
            let e = entries(&src, true).unwrap_or_else(|err| panic!("{eol:?} : {}", err.message));
            assert!(e.iter().any(|x| x.path == key(&["b"])), "{eol:?}");
        }
    }
}
