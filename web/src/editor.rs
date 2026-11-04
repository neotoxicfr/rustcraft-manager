//! Éditeur de texte léger : zone de saisie transparente posée sur un `<pre>` coloré (aucune
//! bibliothèque JavaScript), numéros de ligne, ligne d'erreur marquée.

use rc_manager_shared::ConfigFormat;

fn esc(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
}

fn span(class: &str, s: &str, out: &mut String) {
    if s.is_empty() {
        return;
    }
    out.push_str("<span class=\"");
    out.push_str(class);
    out.push_str("\">");
    esc(s, out);
    out.push_str("</span>");
}

/// Classe d'un mot nu : nombre, booléen ou nul, sinon texte.
fn word_class(w: &str) -> &'static str {
    let t = w.trim();
    match t {
        "true" | "false" | "True" | "False" | "TRUE" | "FALSE" | "null" | "~" | "Null" | "NULL" => "hl-b",
        _ if !t.is_empty()
            && t.trim_start_matches(['-', '+']).starts_with(|c: char| c.is_ascii_digit() || c == '.')
            && t.parse::<f64>().is_ok() =>
        {
            "hl-n"
        }
        _ => "hl-s",
    }
}

/// Fin (exclue) d'un texte entre guillemets commençant en `i` (sur la ligne).
fn quoted_end(b: &[u8], i: usize) -> usize {
    let q = b[i];
    let mut j = i + 1;
    while j < b.len() {
        if b[j] == b'\\' && q == b'"' {
            j += 2;
            continue;
        }
        if b[j] == q {
            return j + 1;
        }
        j += 1;
    }
    b.len()
}

fn line_props(l: &str, out: &mut String) {
    let t = l.trim_start();
    if t.starts_with('#') || t.starts_with('!') {
        return span("hl-c", l, out);
    }
    match l.find(['=', ':']) {
        Some(i) => {
            span("hl-k", &l[..i], out);
            span("hl-p", &l[i..i + 1], out);
            span(word_class(&l[i + 1..]), &l[i + 1..], out);
        }
        None => span("hl-k", l, out),
    }
}

/// Valeur de YAML, TOML ou JSON sur le reste d'une ligne : textes, nombres, commentaires.
fn line_values(l: &str, comment: &[&str], out: &mut String) {
    let b = l.as_bytes();
    let mut i = 0;
    let mut word = String::new();
    let flush = |w: &mut String, out: &mut String| {
        if !w.is_empty() {
            let lead = w.len() - w.trim_start().len();
            esc(&w[..lead], out);
            span(word_class(w), &w[lead..], out);
            w.clear();
        }
    };
    while i < b.len() {
        let rest = &l[i..];
        if comment.iter().any(|c| rest.starts_with(c))
            && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t' || comment[0] != "#")
        {
            flush(&mut word, out);
            return span("hl-c", rest, out);
        }
        match b[i] {
            b'"' | b'\'' => {
                flush(&mut word, out);
                let e = quoted_end(b, i);
                span("hl-s", &l[i..e], out);
                i = e;
            }
            b'[' | b']' | b'{' | b'}' | b',' => {
                flush(&mut word, out);
                span("hl-p", &l[i..i + 1], out);
                i += 1;
            }
            _ => {
                let c = rest.chars().next().unwrap_or(' ');
                word.push(c);
                i += c.len_utf8();
            }
        }
    }
    flush(&mut word, out);
}

fn line_yaml(l: &str, out: &mut String) {
    let t = l.trim_start();
    let lead = l.len() - t.len();
    esc(&l[..lead], out);
    if t.starts_with('#') {
        return span("hl-c", t, out);
    }
    let mut t = t;
    while let Some(r) = t.strip_prefix("- ").or_else(|| (t == "-").then_some("")) {
        span("hl-p", "-", out);
        out.push(' ');
        t = r;
        if t.is_empty() {
            return;
        }
    }
    // Clé : jusqu'au premier « : » suivi d'un blanc (hors guillemets en tête).
    let key_end = if t.starts_with(['"', '\'']) {
        let e = quoted_end(t.as_bytes(), 0);
        t[e..].starts_with(':').then_some(e)
    } else {
        t.find(": ").or_else(|| t.ends_with(':').then(|| t.len() - 1)).filter(|&i| !t[..i].contains(" #"))
    };
    match key_end {
        Some(k) => {
            span("hl-k", &t[..k], out);
            span("hl-p", ":", out);
            line_values(&t[k + 1..], &["#"], out);
        }
        None => line_values(t, &["#"], out),
    }
}

fn line_toml(l: &str, out: &mut String) {
    let t = l.trim_start();
    let lead = l.len() - t.len();
    esc(&l[..lead], out);
    if t.starts_with('#') {
        return span("hl-c", t, out);
    }
    if t.starts_with('[') {
        let e = t.find(" #").unwrap_or(t.len());
        span("hl-h", &t[..e], out);
        return span("hl-c", &t[e..], out);
    }
    match t.find('=') {
        Some(i) if !t[..i].contains(['"', '\'']) || t.starts_with(['"', '\'']) => {
            span("hl-k", &t[..i], out);
            span("hl-p", "=", out);
            line_values(&t[i + 1..], &["#"], out);
        }
        _ => line_values(t, &["#"], out),
    }
}

fn line_json(l: &str, json5: bool, out: &mut String) {
    // Clés : textes (ou identifiants JSON5) suivis de « : ».
    let b = l.as_bytes();
    let mut i = 0;
    let comments: &[&str] = if json5 { &["//", "/*"] } else { &[] };
    while i < b.len() {
        let rest = &l[i..];
        if comments.iter().any(|c| rest.starts_with(c)) {
            return span("hl-c", rest, out);
        }
        match b[i] {
            b'"' | b'\'' => {
                let e = quoted_end(b, i);
                let is_key = l[e..].trim_start().starts_with(':');
                span(if is_key { "hl-k" } else { "hl-s" }, &l[i..e], out);
                i = e;
            }
            b'[' | b']' | b'{' | b'}' | b',' | b':' => {
                span("hl-p", &l[i..i + 1], out);
                i += 1;
            }
            b' ' | b'\t' => {
                out.push(b[i] as char);
                i += 1;
            }
            _ => {
                let e = rest.find([',', ']', '}', ':', ' ', '\t']).map_or(l.len(), |e| i + e.max(1));
                let w = &l[i..e];
                let is_key = json5 && l[e..].trim_start().starts_with(':');
                span(if is_key { "hl-k" } else { word_class(w) }, w, out);
                i = e;
            }
        }
    }
}

/// HTML coloré du texte (une ligne de sortie par ligne d'entrée, échappé).
pub fn highlight(format: ConfigFormat, text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for (n, line) in text.split('\n').enumerate() {
        if n > 0 {
            out.push('\n');
        }
        let l = line.strip_suffix('\r').unwrap_or(line);
        match format {
            ConfigFormat::Properties => line_props(l, &mut out),
            ConfigFormat::Yaml => line_yaml(l, &mut out),
            ConfigFormat::Toml => line_toml(l, &mut out),
            ConfigFormat::Json => line_json(l, false, &mut out),
            ConfigFormat::Json5 => line_json(l, true, &mut out),
            ConfigFormat::Text => {
                if l.trim_start().starts_with(['#', ';']) {
                    span("hl-c", l, &mut out)
                } else {
                    esc(l, &mut out)
                }
            }
        }
    }
    // Ligne vide finale : le `<pre>` garde la même hauteur que la zone de saisie.
    out.push_str("\n ");
    out
}
