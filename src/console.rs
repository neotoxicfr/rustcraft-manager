//! Console d'un serveur : événements reconnus dans le journal (vue lisible), historique borné en
//! mémoire et sur disque (`<serveur>/.rcm/console.jsonl`, une génération de plus en `.1`).
//!
//! Formes du journal lues : vanilla, Fabric, Quilt `[09:41:17] [Server thread/INFO]: …`, Paper et
//! dérivés `[09:41:17 INFO]: …` ; codes ANSI retirés.

use rc_manager_shared::{ConsoleEvent, ConsoleLine, LineSource};
use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// Lignes gardées en mémoire, et octets au plus.
pub const MEM_LINES: usize = 2000;
pub const MEM_BYTES: usize = 1024 * 1024;
/// Longueur maximale d'une ligne (au-delà : tronquée).
pub const LINE_MAX: usize = 8 * 1024;
/// Taille du fichier d'historique avant rotation.
pub const DISK_MAX: u64 = 4 * 1024 * 1024;

/// Retire les séquences ANSI (`ESC [ … lettre`) et les caractères de contrôle (sauf tabulation).
pub fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(LINE_MAX));
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() && c != '\t' {
            continue;
        }
        if out.len() + c.len_utf8() > LINE_MAX {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// Nom de joueur Minecraft plausible.
pub fn player_name_ok(s: &str) -> bool {
    (1..=16).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// (niveau, message) d'une ligne de journal ; `None` si la ligne n'a pas d'en-tête reconnu.
fn split_header(line: &str) -> Option<(&str, &str)> {
    if !line.starts_with('[') {
        return None;
    }
    let i = line.find("]: ")?;
    let header = &line[..i];
    let level = header.rsplit(['/', ' ']).next()?.trim_end_matches(']');
    Some((level, &line[i + 3..]))
}

/// Événement d'une ligne de sortie du serveur.
pub fn parse(line: &str) -> Option<ConsoleEvent> {
    let (level, msg) = split_header(line)?;
    let msg = msg.trim_end();
    if let Some(p) = msg.strip_suffix(" joined the game")
        && player_name_ok(p)
    {
        return Some(ConsoleEvent::Join { player: p.into() });
    }
    if let Some(p) = msg.strip_suffix(" left the game")
        && player_name_ok(p)
    {
        return Some(ConsoleEvent::Leave { player: p.into() });
    }
    let chat = msg.strip_prefix("[Not Secure] ").unwrap_or(msg);
    if let Some(rest) = chat.strip_prefix('<')
        && let Some((p, text)) = rest.split_once("> ")
        && player_name_ok(p)
    {
        return Some(ConsoleEvent::Chat { player: p.into(), text: text.into() });
    }
    for verb in [" has made the advancement [", " has completed the challenge [", " has reached the goal ["] {
        if let Some((p, rest)) = msg.split_once(verb)
            && player_name_ok(p)
        {
            return Some(ConsoleEvent::Advancement { player: p.into(), title: rest.trim_end_matches(']').into() });
        }
    }
    if msg == "Saved the game" || msg.starts_with("Saved the game") {
        return Some(ConsoleEvent::Saved);
    }
    if let Some(rest) = msg.strip_prefix("Can't keep up! Is the server overloaded? Running ") {
        let nums: Vec<u64> = rest.split(|c: char| !c.is_ascii_digit()).filter_map(|p| p.parse().ok()).collect();
        if let [ms, ticks, ..] = nums[..] {
            return Some(ConsoleEvent::Lag { ms, ticks });
        }
    }
    if let Some(rest) = msg.strip_prefix("Done (")
        && let Some((secs, _)) = rest.split_once("s)!")
        && let Ok(s) = secs.trim().parse::<f64>()
    {
        return Some(ConsoleEvent::Ready { ms: (s * 1000.0).round() as u64 });
    }
    if msg == "Stopping the server" || msg == "Stopping server" {
        return Some(ConsoleEvent::Stopping);
    }
    match level {
        "WARN" | "WARNING" => Some(ConsoleEvent::Warn { text: msg.into() }),
        "ERROR" | "FATAL" | "SEVERE" => Some(ConsoleEvent::Error { text: msg.into() }),
        _ => None,
    }
}

/// Historique d'un serveur.
pub struct History {
    lines: VecDeque<ConsoleLine>,
    bytes: usize,
    next_seq: u64,
    file: Option<PathBuf>,
    writer: Option<std::io::BufWriter<std::fs::File>>,
    written: u64,
}

fn line_cost(l: &ConsoleLine) -> usize {
    l.text.len() + 64
}

impl History {
    /// Historique d'un serveur, rechargé depuis son fichier (fin du fichier seulement).
    pub fn open(dir: &Path) -> History {
        let file = dir.join(".rcm").join("console.jsonl");
        let mut h = History {
            lines: VecDeque::new(),
            bytes: 0,
            next_seq: 1,
            file: Some(file.clone()),
            writer: None,
            written: 0,
        };
        if crate::files::internal_dir(dir, "", false).is_ok()
            && let Ok(f) = crate::files::open_file(&file)
        {
            h.written = f.metadata().map(|m| m.len()).unwrap_or(0);
            let reader = std::io::BufReader::new(f);
            for l in reader.lines().map_while(Result::ok) {
                if let Ok(line) = serde_json::from_str::<ConsoleLine>(&l) {
                    h.next_seq = h.next_seq.max(line.seq + 1);
                    h.keep(line);
                }
            }
        }
        h
    }

    /// Historique en mémoire seulement (tests).
    pub fn memory() -> History {
        History { lines: VecDeque::new(), bytes: 0, next_seq: 1, file: None, writer: None, written: 0 }
    }

    fn keep(&mut self, line: ConsoleLine) {
        self.bytes += line_cost(&line);
        self.lines.push_back(line);
        while self.lines.len() > MEM_LINES || self.bytes > MEM_BYTES {
            if let Some(old) = self.lines.pop_front() {
                self.bytes -= line_cost(&old);
            }
        }
    }

    /// Ajoute une ligne (numérotée, horodatée, événement reconnu) ; rend la ligne.
    pub fn push(&mut self, source: LineSource, raw: &str, event: Option<ConsoleEvent>) -> ConsoleLine {
        let text = clean(raw);
        let event =
            event.or_else(|| if matches!(source, LineSource::Out | LineSource::Err) { parse(&text) } else { None });
        let line = ConsoleLine { seq: self.next_seq, ts: now_ms(), source, text, event };
        self.next_seq += 1;
        self.append_disk(&line);
        self.keep(line.clone());
        line
    }

    fn append_disk(&mut self, line: &ConsoleLine) {
        let Some(path) = self.file.clone() else { return };
        // Jamais au travers d'un lien posé par le serveur (`.rcm` ou le fichier lui-même) : ni
        // rotation (le renommage suivrait un lien posé à la place de `.rcm`), ni réouverture.
        let rcm_ok =
            || path.parent().and_then(Path::parent).is_some_and(|d| crate::files::internal_dir(d, "", true).is_ok());
        if self.written > DISK_MAX {
            self.writer = None;
            if !rcm_ok() {
                return;
            }
            let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
            self.written = 0;
        }
        if self.writer.is_none() {
            if !rcm_ok() {
                return;
            }
            self.writer = crate::files::open_append(&path).ok().map(std::io::BufWriter::new);
        }
        if let Some(w) = self.writer.as_mut()
            && let Ok(mut s) = serde_json::to_string(line)
        {
            s.push('\n');
            if w.write_all(s.as_bytes()).is_ok() {
                self.written += s.len() as u64;
            }
        }
    }

    /// Écrit sur le disque ce qui attend dans le tampon.
    pub fn flush(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
    }

    /// Dernières lignes (au plus `n`), avant `before` si donné.
    pub fn tail(&self, n: usize, before: Option<u64>) -> Vec<ConsoleLine> {
        let it = self.lines.iter().filter(|l| before.is_none_or(|b| l.seq < b));
        let v: Vec<&ConsoleLine> = it.collect();
        v[v.len().saturating_sub(n)..].iter().map(|l| (*l).clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

impl Drop for History {
    fn drop(&mut self) {
        self.flush();
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(s: &str) -> Option<ConsoleEvent> {
        parse(s)
    }

    /// Formes réelles (vanilla 26.3, Paper) : connexion, départ, chat (signé ou non), progrès,
    /// sauvegarde, retard, prêt, arrêt, alertes ; une ligne sans en-tête n'est rien.
    #[test]
    fn evenements_reconnus() {
        assert_eq!(
            ev("[09:41:17] [Server thread/INFO]: Steve joined the game"),
            Some(ConsoleEvent::Join { player: "Steve".into() })
        );
        assert_eq!(ev("[09:41:17 INFO]: Alex left the game"), Some(ConsoleEvent::Leave { player: "Alex".into() }));
        assert_eq!(
            ev("[09:42:03] [Server thread/INFO]: <Steve> on va au village ?"),
            Some(ConsoleEvent::Chat { player: "Steve".into(), text: "on va au village ?".into() })
        );
        assert_eq!(
            ev("[09:42:03] [Server thread/INFO]: [Not Secure] <neo> salut"),
            Some(ConsoleEvent::Chat { player: "neo".into(), text: "salut".into() })
        );
        assert_eq!(
            ev("[09:44:56] [Server thread/INFO]: Alex has made the advancement [Stone Age]"),
            Some(ConsoleEvent::Advancement { player: "Alex".into(), title: "Stone Age".into() })
        );
        assert_eq!(ev("[09:42:30] [Server thread/INFO]: Saved the game"), Some(ConsoleEvent::Saved));
        assert_eq!(
            ev(
                "[09:46:08] [Server thread/WARN]: Can't keep up! Is the server overloaded? Running 2100ms or 42 ticks behind"
            ),
            Some(ConsoleEvent::Lag { ms: 2100, ticks: 42 })
        );
        assert_eq!(
            ev("[09:40:00] [Server thread/INFO]: Done (4.215s)! For help, type \"help\""),
            Some(ConsoleEvent::Ready { ms: 4215 })
        );
        assert_eq!(ev("[10:00:00 INFO]: Stopping the server"), Some(ConsoleEvent::Stopping));
        assert_eq!(
            ev("[10:00:00] [Server thread/WARN]: Ambiguity between arguments"),
            Some(ConsoleEvent::Warn { text: "Ambiguity between arguments".into() })
        );
        assert!(matches!(ev("[10:00:00] [main/ERROR]: Failed to start"), Some(ConsoleEvent::Error { .. })));
        assert_eq!(ev("Starting net.minecraft.server.Main"), None);
        assert_eq!(ev("[09:41:17] [Server thread/INFO]: Steve Bob joined the game"), None, "nom invalide");
        assert_eq!(ev("[09:41:17] [Server thread/INFO]: Preparing spawn area: 2%"), None);
    }

    #[test]
    fn nettoyage_ansi_et_controle() {
        assert_eq!(clean("\u{1b}[0;32mDone\u{1b}[m\r"), "Done");
        assert_eq!(clean("a\u{7}b\tc"), "ab\tc");
        assert!(clean(&"x".repeat(LINE_MAX * 2)).len() <= LINE_MAX + 3);
    }

    /// Historique borné, numéroté, rechargé depuis le disque après un redémarrage.
    #[test]
    fn historique_borne_et_persistant() {
        let d = std::env::temp_dir().join(format!("rcm-console-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        {
            let mut h = History::open(&d);
            for i in 0..(MEM_LINES + 10) {
                h.push(LineSource::Out, &format!("[00:00:00] [Server thread/INFO]: ligne {i}"), None);
            }
            assert_eq!(h.len(), MEM_LINES);
            assert_eq!(h.tail(2, None).iter().map(|l| l.seq).collect::<Vec<_>>(), vec![2009, 2010]);
            assert_eq!(h.tail(1, Some(2009))[0].seq, 2008);
            h.push(LineSource::Out, "[0] [Server thread/INFO]: neo joined the game", None);
        }
        let h = History::open(&d);
        let last = h.tail(1, None).pop().unwrap();
        assert_eq!(last.seq, 2011);
        assert_eq!(last.event, Some(ConsoleEvent::Join { player: "neo".into() }));
        let mut h = h;
        assert_eq!(h.push(LineSource::Input, "list", None).seq, 2012, "numérotation reprise");
        // Gros texte : la mémoire reste bornée en octets.
        let mut m = History::memory();
        for _ in 0..1000 {
            m.push(LineSource::Out, &"y".repeat(LINE_MAX), None);
        }
        assert!(m.len() * (LINE_MAX + 64) <= MEM_BYTES + LINE_MAX + 64);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `.rcm` remplacé par un lien (processus du serveur) : l'historique n'est ni lu ni écrit au
    /// travers.
    #[test]
    fn historique_jamais_au_travers_d_un_lien() {
        let d = std::env::temp_dir().join(format!("rcm-console-lien-{}", std::process::id()));
        let outside = d.with_extension("dehors");
        for p in [&d, &outside] {
            let _ = std::fs::remove_dir_all(p);
            std::fs::create_dir_all(p).unwrap();
        }
        let line = serde_json::to_string(&History::memory().push(LineSource::Out, "secret", None)).unwrap();
        std::fs::write(outside.join("console.jsonl"), format!("{line}\n")).unwrap();
        assert!(crate::files::tests::link_dir(&outside, &d.join(".rcm")));
        let mut h = History::open(&d);
        assert_eq!(h.len(), 0, "rien lu au travers du lien");
        h.push(LineSource::Out, "x", None);
        drop(h);
        assert_eq!(std::fs::read_to_string(outside.join("console.jsonl")).unwrap(), format!("{line}\n"));
        let _ = std::fs::remove_dir(d.join(".rcm")).or_else(|_| std::fs::remove_file(d.join(".rcm")));
        // Lien posé APRÈS l'ouverture, au moment de la rotation : rien n'est renommé au travers.
        let mut h = History::open(&d);
        h.push(LineSource::Out, "avant", None);
        h.flush();
        // Windows : un dossier qui contient un fichier ouvert ne se renomme pas.
        h.writer = None;
        std::fs::rename(d.join(".rcm"), d.join("ancien")).unwrap();
        std::fs::write(outside.join("console.jsonl.1"), "B").unwrap();
        assert!(crate::files::tests::link_dir(&outside, &d.join(".rcm")));
        h.written = DISK_MAX + 1;
        h.push(LineSource::Out, "après", None);
        drop(h);
        assert_eq!(std::fs::read_to_string(outside.join("console.jsonl")).unwrap(), format!("{line}\n"));
        assert_eq!(std::fs::read_to_string(outside.join("console.jsonl.1")).unwrap(), "B");
        let _ = std::fs::remove_dir(d.join(".rcm")).or_else(|_| std::fs::remove_file(d.join(".rcm")));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
