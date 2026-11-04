//! TOML (configurations de mods) : analyse par toml_edit (positions gardées) et éditions
//! CIBLÉES sur le texte (seule la valeur touchée est réécrite, dans son style de texte).

use super::{Budget, Lines, comment_above, error_at};
use rc_manager_shared::{ConfigEdit, ConfigEntry, ConfigError, ConfigSeg, ConfigValue, EntryKind};
use std::ops::Range;
use toml_edit::{Item, Table, Value};

#[derive(Debug, Clone)]
struct Node {
    entry: ConfigEntry,
    span: Option<Range<usize>>,
    literal: bool,
    /// Liste en ligne : `[` … `]` et éléments simples.
    list: Option<(Range<usize>, Option<Items>)>,
}

/// Portées des éléments simples d'une liste (`None` si l'un ne l'est pas).
type Items = Vec<Range<usize>>;

struct W<'a> {
    text: &'a str,
    lines: Lines<'a>,
    nodes: Vec<Node>,
    budget: Budget,
}

impl W<'_> {
    fn line_of(&self, span: Option<Range<usize>>, fallback: u32) -> u32 {
        span.map_or(fallback, |s| self.lines.pos(s.start).0)
    }

    fn add(&mut self, n: Node) -> Result<(), ConfigError> {
        self.budget.take(&n.entry)?;
        self.nodes.push(n);
        Ok(())
    }

    fn value(&mut self, path: Vec<ConfigSeg>, v: &Value, line: u32) -> Result<bool, ConfigError> {
        let comment = comment_above(&self.lines, line);
        let base = |kind, value: Option<ConfigValue>, raw: Option<String>| ConfigEntry {
            path: path.clone(),
            kind,
            value,
            raw,
            comment: comment.clone(),
            editable_list: false,
            line,
        };
        match v {
            Value::Array(a) => {
                let idx = self.nodes.len();
                self.add(Node { entry: base(EntryKind::List, None, None), span: None, literal: false, list: None })?;
                let mut items = Some(Vec::new());
                for (i, x) in a.iter().enumerate() {
                    let mut p = path.clone();
                    p.push(ConfigSeg::Index(i));
                    let l = self.line_of(x.span(), line);
                    let simple = self.value(p, x, l)?;
                    match (&mut items, simple, x.span()) {
                        (Some(v), true, Some(s)) => v.push(s),
                        _ => items = None,
                    }
                }
                let n = &mut self.nodes[idx];
                n.entry.editable_list = items.is_some() && a.span().is_some();
                n.list = a.span().map(|s| (s, items));
                Ok(false)
            }
            Value::InlineTable(t) => {
                self.add(Node { entry: base(EntryKind::Section, None, None), span: None, literal: false, list: None })?;
                for (k, x) in t.iter() {
                    let mut p = path.clone();
                    p.push(ConfigSeg::Key(k.to_string()));
                    let l = self.line_of(t.key(k).and_then(|k| k.span()), line);
                    self.value(p, x, l)?;
                }
                Ok(false)
            }
            other => {
                let (value, raw) = match other {
                    Value::String(s) => (Some(ConfigValue::Str(s.value().clone())), None),
                    Value::Integer(n) => (Some(ConfigValue::Int(*n.value())), None),
                    Value::Float(f) => (Some(ConfigValue::Float(*f.value())), None),
                    Value::Boolean(b) => (Some(ConfigValue::Bool(*b.value())), None),
                    // Date : affichée telle quelle, éditée en texte.
                    _ => (None, Some(other.to_string().trim().to_string())),
                };
                let span = other.span().filter(|_| value.is_some());
                let literal = span.as_ref().is_some_and(|s| self.text[s.clone()].starts_with('\''));
                self.add(Node { entry: base(EntryKind::Value, value, raw), span, literal, list: None })?;
                Ok(true)
            }
        }
    }

    fn table(&mut self, path: &[ConfigSeg], t: &Table) -> Result<(), ConfigError> {
        for (k, item) in t.iter() {
            let mut p = path.to_vec();
            p.push(ConfigSeg::Key(k.to_string()));
            let kspan = t.key(k).and_then(|k| k.span());
            match item {
                Item::Value(v) => {
                    let l = self.line_of(kspan.or_else(|| v.span()), 1);
                    self.value(p, v, l)?;
                }
                Item::Table(sub) => {
                    let l = self.line_of(sub.span().or(kspan), 1);
                    let comment = comment_above(&self.lines, l);
                    self.add(Node {
                        entry: ConfigEntry {
                            path: p.clone(),
                            kind: EntryKind::Section,
                            value: None,
                            raw: None,
                            comment,
                            editable_list: false,
                            line: l,
                        },
                        span: None,
                        literal: false,
                        list: None,
                    })?;
                    self.table(&p, sub)?;
                }
                Item::ArrayOfTables(a) => {
                    let l = self.line_of(a.span().or(kspan), 1);
                    self.add(Node {
                        entry: ConfigEntry {
                            path: p.clone(),
                            kind: EntryKind::List,
                            value: None,
                            raw: None,
                            comment: comment_above(&self.lines, l),
                            editable_list: false,
                            line: l,
                        },
                        span: None,
                        literal: false,
                        list: None,
                    })?;
                    for (i, sub) in a.iter().enumerate() {
                        let mut q = p.clone();
                        q.push(ConfigSeg::Index(i));
                        let l = self.line_of(sub.span(), l);
                        self.add(Node {
                            entry: ConfigEntry {
                                path: q.clone(),
                                kind: EntryKind::Section,
                                value: None,
                                raw: None,
                                comment: None,
                                editable_list: false,
                                line: l,
                            },
                            span: None,
                            literal: false,
                            list: None,
                        })?;
                        self.table(&q, sub)?;
                    }
                }
                Item::None => {}
            }
        }
        Ok(())
    }
}

fn analyze(text: &str) -> Result<Vec<Node>, ConfigError> {
    let doc = toml_edit::Document::parse(text).map_err(|e| {
        let (l, c) = e.span().map_or((0, 0), |s| Lines::new(text).pos(s.start));
        error_at(l, c, e.message().to_string())
    })?;
    let mut w = W { text, lines: Lines::new(text), nodes: Vec::new(), budget: Budget::default() };
    w.table(&[], doc.as_table())?;
    // Ordre du fichier (les tables d'en-tête peuvent être rangées autrement par toml_edit).
    w.nodes.sort_by_key(|n| n.entry.line);
    Ok(w.nodes)
}

pub fn entries(text: &str) -> Result<Vec<ConfigEntry>, ConfigError> {
    Ok(analyze(text)?.into_iter().map(|n| n.entry).collect())
}

fn render(v: &ConfigValue, literal: bool) -> Result<String, ConfigError> {
    Ok(match v {
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        ConfigValue::Float(f) => Value::from(*f).to_string().trim().to_string(),
        ConfigValue::Str(s) if literal && !s.contains(['\'', '\n', '\r']) && !s.chars().any(char::is_control) => {
            format!("'{s}'")
        }
        ConfigValue::Str(s) => Value::from(s.as_str()).to_string().trim().to_string(),
        ConfigValue::Null => return Err(error_at(0, 0, "TOML : pas de valeur nulle".into())),
    })
}

fn not_editable() -> ConfigError {
    error_at(0, 0, "valeur non éditable en mode visuel".into())
}

pub fn apply(text: &str, edit: &ConfigEdit) -> Result<String, ConfigError> {
    let nodes = analyze(text)?;
    let find = |p: &[ConfigSeg]| nodes.iter().find(|n| n.entry.path == p);
    let splice = |r: Range<usize>, s: &str| format!("{}{}{}", &text[..r.start], s, &text[r.end..]);
    match edit {
        ConfigEdit::Set { path, value } => {
            let n = find(path).ok_or_else(not_editable)?;
            let span = n.span.clone().ok_or_else(not_editable)?;
            Ok(splice(span, &render(value, n.literal)?))
        }
        ConfigEdit::Push { path, value } => {
            let n = find(path).filter(|n| n.entry.editable_list).ok_or_else(not_editable)?;
            let (arr, items) = n.list.clone().ok_or_else(not_editable)?;
            let items = items.ok_or_else(not_editable)?;
            let literal = items.first().is_some_and(|s| text[s.clone()].starts_with('\''));
            let v = render(value, literal)?;
            let Some(last) = items.last() else { return Ok(splice(arr.start + 1..arr.end - 1, &v)) };
            let lines = Lines::new(text);
            if lines.pos(last.start).0 != lines.pos(arr.start).0 {
                let ls = Lines::line_start(text, last.start);
                let indent = &text[ls..last.start];
                let indent = if indent.trim().is_empty() { indent } else { "" };
                let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
                return Ok(splice(last.end..last.end, &format!(",{nl}{indent}{v}")));
            }
            Ok(splice(last.end..last.end, &format!(", {v}")))
        }
        ConfigEdit::Remove { path } => {
            let (Some(ConfigSeg::Index(i)), Some(parent)) = (path.last(), path.get(..path.len().saturating_sub(1)))
            else {
                return Err(not_editable());
            };
            let n = find(parent).filter(|n| n.entry.editable_list).ok_or_else(not_editable)?;
            let items = n.list.clone().and_then(|l| l.1).ok_or_else(not_editable)?;
            let it = items.get(*i).ok_or_else(not_editable)?;
            let r = if let Some(next) = items.get(i + 1) {
                it.start..next.start
            } else if *i > 0 {
                items[i - 1].end..it.end
            } else {
                it.clone()
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

    const SRC: &str = "# Mod\ntitre = \"a\" # fin\n\n# Réglages\n[general]\nactif = true\nchemin = 'C:\\x'\nliste = [1, 2]\nnoms = [\n  \"p\",\n  \"q\",\n]\nf = 1.5\n[[regles]]\nnom = \"r1\"\n";

    #[test]
    fn arbre_toml() {
        let e = entries(SRC).unwrap();
        let get = |p: &[&str]| e.iter().find(|x| x.path == key(p)).cloned().unwrap();
        assert_eq!(get(&["titre"]).value, Some(ConfigValue::Str("a".into())));
        assert_eq!(get(&["titre"]).comment.as_deref(), Some("Mod"));
        assert_eq!(get(&["general"]).comment.as_deref(), Some("Réglages"));
        assert_eq!(get(&["general", "chemin"]).value, Some(ConfigValue::Str("C:\\x".into())));
        assert_eq!(get(&["general", "noms", "1"]).line, 11);
        assert_eq!(get(&["regles", "0", "nom"]).value, Some(ConfigValue::Str("r1".into())));
        assert!(get(&["general", "noms"]).editable_list);
    }

    #[test]
    fn editions_toml() {
        let set = |p: &[&str], v: ConfigValue| apply(SRC, &ConfigEdit::Set { path: key(p), value: v }).unwrap();
        assert_eq!(set(&["titre"], ConfigValue::Str("b\"".into())), SRC.replace("\"a\" # fin", "'b\"' # fin"));
        assert_eq!(set(&["general", "actif"], ConfigValue::Bool(false)), SRC.replace("actif = true", "actif = false"));
        assert_eq!(set(&["general", "chemin"], ConfigValue::Str("D:\\y".into())), SRC.replace("'C:\\x'", "'D:\\y'"));
        assert_eq!(set(&["general", "f"], ConfigValue::Float(2.0)), SRC.replace("f = 1.5", "f = 2.0"));
        let push = |p: &[&str], v: ConfigValue| apply(SRC, &ConfigEdit::Push { path: key(p), value: v }).unwrap();
        assert_eq!(push(&["general", "liste"], ConfigValue::Int(3)), SRC.replace("[1, 2]", "[1, 2, 3]"));
        assert_eq!(
            push(&["general", "noms"], ConfigValue::Str("r".into())),
            SRC.replace("  \"q\",\n", "  \"q\",\n  \"r\",\n")
        );
        let rm = |p: &[&str]| apply(SRC, &ConfigEdit::Remove { path: key(p) }).unwrap();
        assert_eq!(rm(&["general", "liste", "0"]), SRC.replace("[1, 2]", "[2]"));
        assert!(entries("a = \n").unwrap_err().line == 1);
    }
}
