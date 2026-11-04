//! `server.properties` (et tout fichier `.properties`) : analyse au format des propriétés Java
//! (`Properties.load` : lignes logiques, continuation par antislash, séparateurs `=`, `:` ou
//! blanc, échappements, `\uXXXX`), et mise à jour SANS perte : seules les lignes des clés
//! données changent (clé et séparateur d'origine gardés) ; commentaires, ordre, fins de ligne et
//! clés inconnues intacts ; une clé absente est ajoutée à la fin.

use rc_manager_shared::{ConfigEntry, ConfigError, ConfigSeg, ConfigValue, EntryKind};
use std::ops::Range;
use std::path::Path;

/// Une clé du fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    /// Valeur, échappements résolus.
    pub value: String,
    /// Ligne logique entière, sans la fin de ligne (octets dans le texte).
    pub span: Range<usize>,
    /// Texte brut de la clé et du séparateur (`level-type=`, `motd : `).
    pub head: Range<usize>,
    /// Ligne (à partir de 1).
    pub line: u32,
}

/// Fin de la ligne naturelle qui commence en `i` : (fin du contenu, début de la suivante).
fn line_end(t: &[u8], i: usize) -> (usize, usize) {
    let mut j = i;
    while j < t.len() && t[j] != b'\n' && t[j] != b'\r' {
        j += 1;
    }
    let next = if j < t.len() && t[j] == b'\r' && t.get(j + 1) == Some(&b'\n') { j + 2 } else { (j + 1).min(t.len()) };
    (j, next)
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | 0x0c)
}

fn err(line: u32, message: &str) -> ConfigError {
    ConfigError { line, col: 0, message: message.into(), ..Default::default() }
}

/// Résout les échappements d'un morceau de ligne logique (continuations déjà retirées).
fn unescape(s: &str, line: u32) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('u') => {
                let hex: String = it.by_ref().take(4).collect();
                let code = (hex.len() == 4 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                    .then(|| u32::from_str_radix(&hex, 16).ok())
                    .flatten()
                    .ok_or_else(|| err(line, "Malformed \\uxxxx encoding."))?;
                // Paire UTF-16 (`😀`) : un seul caractère, comme la chaîne Java ;
                // moitié seule : remplacée (une chaîne Rust ne la porte pas).
                if (0xD800..0xDC00).contains(&code) {
                    let mut look = it.clone();
                    let low = (look.next() == Some('\\') && look.next() == Some('u'))
                        .then(|| look.by_ref().take(4).collect::<String>())
                        .and_then(|h| (h.len() == 4).then(|| u32::from_str_radix(&h, 16).ok()).flatten())
                        .filter(|l| (0xDC00..0xE000).contains(l));
                    if let Some(lo) = low {
                        it = look;
                        out.push(
                            char::from_u32(0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00)).unwrap_or('\u{FFFD}'),
                        );
                        continue;
                    }
                }
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('f') => out.push('\u{0c}'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    Ok(out)
}

/// Analyse le fichier : clés dans l'ordre (doublons compris), ou l'erreur du chargeur Java.
pub fn parse(text: &str) -> Result<Vec<Entry>, ConfigError> {
    let t = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1u32;
    while i < t.len() {
        let start = i;
        let start_line = line;
        // Ligne logique : lignes naturelles jointes tant qu'elles finissent par un nombre impair
        // d'antislashs (la ligne suivante perd ses blancs de tête).
        let mut logical = String::new();
        let mut first = true;
        let mut end;
        loop {
            let (e, next) = line_end(t, i);
            end = e;
            let mut s = i;
            if !first {
                while s < e && is_ws(t[s]) {
                    s += 1;
                }
            }
            let piece = &text[s..e];
            line += u32::from(next > e);
            i = next;
            if first {
                let lead = piece.trim_start_matches([' ', '\t', '\u{0c}']);
                if lead.is_empty() || lead.starts_with('#') || lead.starts_with('!') {
                    break;
                }
            }
            first = false;
            let slashes = piece.bytes().rev().take_while(|&b| b == b'\\').count();
            if slashes % 2 == 1 {
                logical.push_str(&piece[..piece.len() - 1]);
                if i >= t.len() {
                    break;
                }
            } else {
                logical.push_str(piece);
                break;
            }
        }
        if logical.trim_start_matches([' ', '\t', '\u{0c}']).is_empty() {
            continue;
        }
        // Clé : jusqu'au premier `=`, `:` ou blanc non échappé.
        let lb = logical.as_bytes();
        let mut k = 0;
        while k < lb.len() && is_ws(lb[k]) {
            k += 1;
        }
        let key_start = k;
        let mut esc = false;
        while k < lb.len() {
            let b = lb[k];
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'=' || b == b':' || is_ws(b) {
                break;
            }
            k += 1;
        }
        let key_raw = &logical[key_start..k];
        while k < lb.len() && is_ws(lb[k]) {
            k += 1;
        }
        if k < lb.len() && (lb[k] == b'=' || lb[k] == b':') {
            k += 1;
            while k < lb.len() && is_ws(lb[k]) {
                k += 1;
            }
        }
        let key = unescape(key_raw, start_line)?;
        let value = unescape(&logical[k..], start_line)?;
        // Tête brute (clé et séparateur) prise dans le texte d'origine quand elle tient sur la
        // première ligne naturelle (toujours le cas pour un fichier écrit par le jeu).
        let first_end = line_end(t, start).0;
        let head_end = (start + k).min(first_end);
        out.push(Entry { key, value, span: start..end, head: start..head_end, line: start_line });
    }
    Ok(out)
}

/// Valeur d'une clé (la dernière occurrence l'emporte, comme dans Java), échappements résolus.
pub fn get(text: &str, key: &str) -> Option<String> {
    parse(text).ok()?.into_iter().rev().find(|e| e.key == key).map(|e| e.value)
}

/// Valeur sûre pour un fichier de propriétés : pas de retour à la ligne ni de caractère de
/// contrôle (une valeur ne peut pas injecter une autre clé).
pub fn value_ok(v: &str) -> bool {
    // Un antislash final continue la valeur sur la ligne suivante (format des propriétés Java) :
    // il avalerait la clé d'après.
    !v.chars().any(char::is_control) && !v.ends_with('\\')
}

/// Échappement commun aux clés et aux valeurs, comme `Properties.store` sur un flux d'octets :
/// antislash, `= : # !`, blancs de contrôle, autres caractères de contrôle et tout ce qui
/// n'est pas ASCII en `\uXXXX` (paires de substitution au-delà de U+FFFF). Lu à l'identique par
/// toutes les versions du jeu, qu'elles lisent le fichier en UTF-8 (1.20 et plus) ou en
/// ISO-8859-1 (versions anciennes, ou fichier déjà dans cet encodage).
fn escape(s: &str, key: bool) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        match c {
            ' ' if i == 0 || key => out.push_str("\\ "),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{0c}' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04X}"));
                }
            }
        }
    }
    out
}

/// Valeur écrite comme `Properties.store` (voir [`escape`]).
pub fn escape_value(v: &str) -> String {
    escape(v, false)
}

/// Clé écrite comme `Properties.store` : en plus, tout blanc échappé, caractères de contrôle
/// compris (une clé ne peut pas couper sa ligne).
fn escape_key(k: &str) -> String {
    escape(k, true)
}

/// Texte d'un `server.properties` lu en ISO-8859-1 (fichier pas en UTF-8) remis dans cet
/// encodage : caractères jusqu'à U+00FF en un octet, au-delà en `\uXXXX` (seule écriture que
/// les deux lecteurs du jeu comprennent). Un fichier UTF-8 garde l'UTF-8.
pub fn encode_like(original: &[u8], text: &str) -> Vec<u8> {
    if std::str::from_utf8(original).is_ok() {
        return text.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        match u8::try_from(c as u32) {
            Ok(b) => out.push(b),
            Err(_) => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.extend_from_slice(format!("\\u{u:04X}").as_bytes());
                }
            }
        }
    }
    out
}

/// Fin de ligne du fichier (`\r\n` si la première fin de ligne en est une).
fn eol(text: &str) -> &'static str {
    match text.find('\n') {
        Some(i) if i > 0 && text.as_bytes()[i - 1] == b'\r' => "\r\n",
        _ => "\n",
    }
}

/// Remplace ou ajoute des clés ; valeurs déjà écrites (échappées). La première occurrence d'une
/// clé reçoit la valeur, les doublons suivants sont retirés (le jeu lirait le dernier).
fn patch_raw(text: &str, entries: &[Entry], updates: &[(&str, String)]) -> String {
    let nl = eol(text);
    let mut out = String::with_capacity(text.len() + 64);
    let mut pos = 0;
    let mut done = vec![false; updates.len()];
    for e in entries {
        let Some(u) = updates.iter().position(|(k, _)| *k == e.key) else { continue };
        out.push_str(&text[pos..e.span.start]);
        if done[u] {
            // Doublon : la ligne entière part, fin de ligne comprise.
            pos = line_end(text.as_bytes(), e.span.end).1;
            continue;
        }
        done[u] = true;
        let head = &text[e.head.clone()];
        out.push_str(head);
        // Tête sans séparateur (`clé` seule en fin de ligne) : `=` ajouté.
        if !head.ends_with(['=', ':', ' ', '\t']) {
            out.push('=');
        }
        out.push_str(&updates[u].1);
        pos = e.span.end;
    }
    out.push_str(&text[pos..]);
    for (i, (k, v)) in updates.iter().enumerate() {
        if !done[i] {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push_str(nl);
            }
            out.push_str(&escape_key(k));
            out.push('=');
            out.push_str(v);
            out.push_str(nl);
        }
    }
    out
}

/// Remplace ou ajoute `clé=valeur` (valeurs brutes, déjà sûres : voir [`value_ok`]). Rend le
/// texte modifié ; un fichier illisible (échappement `\u` faux) garde ses lignes et reçoit les
/// clés à la fin.
pub fn patch(text: &str, updates: &[(&str, String)]) -> String {
    let entries = parse(text).unwrap_or_default();
    patch_raw(text, &entries, updates)
}

/// Remplace ou ajoute des clés avec des valeurs en clair (échappées ici).
pub fn set_values(text: &str, updates: &[(&str, &str)]) -> Result<String, ConfigError> {
    let entries = parse(text)?;
    let esc: Vec<(&str, String)> = updates.iter().map(|(k, v)| (*k, escape_value(v))).collect();
    Ok(patch_raw(text, &entries, &esc))
}

/// Met à jour le fichier (créé s'il manque), écriture atomique, rien si identique.
pub fn patch_file(path: &Path, updates: &[(&str, String)]) -> std::io::Result<()> {
    if updates.iter().any(|(_, v)| !value_ok(v)) {
        return Err(std::io::Error::other("valeur invalide pour server.properties"));
    }
    // Borné et sans suivre de lien : un lien posé par le serveur vers un fichier du gestionnaire
    // ne fait pas recopier ce fichier dans `server.properties`.
    let bytes = match crate::fsutil::read_bounded(path, rc_manager_shared::CONFIG_MAX_BYTES as u64) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    // Décodé comme le jeu (UTF-8, sinon ISO-8859-1) et réécrit dans le même encodage : un `é`
    // d'un fichier ISO-8859-1 ne devient pas `�`.
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    };
    crate::fsutil::write_atomic(path, &encode_like(&bytes, &patch(&text, updates))).map(|_| ())
}

/// Arbre du mode visuel : une entrée par clé (dernière occurrence : celle que le jeu lit), dans
/// l'ordre du fichier.
pub fn entries(text: &str) -> Result<Vec<ConfigEntry>, ConfigError> {
    let all = parse(text)?;
    Ok(all
        .iter()
        .enumerate()
        .filter(|(i, e)| !all[i + 1..].iter().any(|x| x.key == e.key))
        .map(|(_, e)| ConfigEntry {
            path: vec![ConfigSeg::Key(e.key.clone())],
            kind: EntryKind::Value,
            value: Some(ConfigValue::Str(e.value.clone())),
            raw: None,
            comment: None,
            editable_list: false,
            line: e.line,
        })
        .collect())
}

/// Clé gérée par le gestionnaire dont la valeur diffère entre deux textes.
pub fn managed_changed(old: &str, new: &str) -> Option<&'static str> {
    rc_manager_shared::MANAGED_PROPERTIES.iter().copied().find(|k| get(old, k) != get(new, k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mise_a_jour_sans_perte() {
        let src = "#Minecraft server properties\n#Mon Oct 20\nmotd=Salut \\u00E9\nserver-port=25565\ncustom-key=x\nenable-rcon=false\nserver-port=1\n";
        let out = patch(
            src,
            &[("server-port", "25570".into()), ("enable-rcon", "true".into()), ("rcon.port", "25580".into())],
        );
        assert_eq!(
            out,
            "#Minecraft server properties\n#Mon Oct 20\nmotd=Salut \\u00E9\nserver-port=25570\ncustom-key=x\nenable-rcon=true\nrcon.port=25580\n"
        );
        assert_eq!(get(&out, "server-port").as_deref(), Some("25570"));
        assert_eq!(get(&out, "motd").as_deref(), Some("Salut é"));
        assert_eq!(get("#server-port=1\n", "server-port"), None);
        assert_eq!(patch("", &[("a", "1".into())]), "a=1\n");
    }

    /// Non-ASCII écrit en `\uXXXX` (lu pareil en UTF-8 et en ISO-8859-1), clés aux caractères de
    /// contrôle échappées, encodage du fichier lu gardé à la réécriture.
    #[test]
    fn non_ascii_et_encodage() {
        let t = set_values("motd=x\n", &[("motd", "Salut é 😀")]).unwrap();
        assert_eq!(t, "motd=Salut \\u00E9 \\uD83D\\uDE00\n");
        assert_eq!(get(&t, "motd").as_deref(), Some("Salut é 😀"));
        assert!(t.is_ascii());
        let t = set_values("", &[("a\tb\u{1}c", "1")]).unwrap();
        assert_eq!(t, "a\\tb\\u0001c=1\n");
        assert_eq!(parse(&t).unwrap()[0].key, "a\tb\u{1}c");
        // Fichier ISO-8859-1 : `é` reste l'octet E9 (ni « � », ni UTF-8).
        let d = std::env::temp_dir().join(format!("rcm-props-enc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("server.properties");
        std::fs::write(&p, b"motd=caf\xE9\nserver-port=1\n").unwrap();
        patch_file(&p, &[("server-port", "2".into())]).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"motd=caf\xE9\nserver-port=2\n");
        assert_eq!(encode_like(b"a=\xE9", "a=\u{e9}\u{3b1}"), b"a=\xE9\\u03B1");
        assert_eq!(encode_like("a=é".as_bytes(), "a=é"), "a=é".as_bytes());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une valeur avec un retour à la ligne ne peut pas injecter de clé.
    #[test]
    fn injection_refusee() {
        let d = std::env::temp_dir().join(format!("rcm-props-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("server.properties");
        assert!(patch_file(&p, &[("motd", "a\nenable-rcon=true".into())]).is_err());
        // Antislash final : continuerait la valeur sur la clé suivante.
        assert!(patch_file(&p, &[("motd", "a\\".into()), ("enable-rcon", "false".into())]).is_err());
        assert!(!p.exists());
        patch_file(&p, &[("motd", "ok".into())]).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "motd=ok\n");
        // Valeur en clair échappée : ni retour à la ligne, ni séparateur, ni continuation.
        let t = set_values("motd=x\n", &[("motd", "a\nenable-rcon=true\\")]).unwrap();
        assert_eq!(t, "motd=a\\nenable-rcon\\=true\\\\\n");
        assert_eq!(get(&t, "motd").as_deref(), Some("a\nenable-rcon=true\\"));
        assert_eq!(get(&t, "enable-rcon"), None);
    }

    /// Format Java : séparateurs, continuation, échappements, fins de ligne `\r\n` gardées.
    #[test]
    fn format_des_proprietes_java() {
        let src = "! commentaire\r\n  a : 1\r\nb\\\r\n   c=2\r\nd 3\r\ne\r\nf=x\\:y\r\n";
        let e = parse(src).unwrap();
        let kv: Vec<(&str, &str)> = e.iter().map(|e| (e.key.as_str(), e.value.as_str())).collect();
        assert_eq!(kv, vec![("a", "1"), ("bc", "2"), ("d", "3"), ("e", ""), ("f", "x:y")]);
        assert_eq!(e[1].line, 3);
        assert_eq!(e[2].line, 5);
        let out = set_values(src, &[("a", "9"), ("e", "z"), ("f", "p:q"), ("g", "n")]).unwrap();
        assert_eq!(out, "! commentaire\r\n  a : 9\r\nb\\\r\n   c=2\r\nd 3\r\ne=z\r\nf=p\\:q\r\ng=n\r\n");
        // Fichier sans fin de ligne finale : la clé ajoutée passe à la ligne.
        assert_eq!(set_values("a=1", &[("b", "2")]).unwrap(), "a=1\nb=2\n");
        // Échappement `\u` faux : erreur de l'analyseur Java, avec la ligne.
        let err = parse("a=1\nb=\\u00G1\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.message.contains("Malformed"));
    }

    /// Clé gérée modifiée : repérée (ajout, retrait ou changement), autres clés libres.
    #[test]
    fn cles_gerees() {
        let a = "server-port=25565\nmotd=a\n";
        assert_eq!(managed_changed(a, "server-port=25565\nmotd=b\n"), None);
        assert_eq!(managed_changed(a, "server-port=25566\nmotd=a\n"), Some("server-port"));
        assert_eq!(managed_changed(a, "server-port=25565\nenable-rcon=true\n"), Some("enable-rcon"));
        assert_eq!(managed_changed(a, "motd=a\n"), Some("server-port"));
        // Doublon plus bas : c'est lui que le jeu lit.
        assert_eq!(managed_changed(a, "server-port=25565\nserver-port=1\n"), Some("server-port"));
    }
}
