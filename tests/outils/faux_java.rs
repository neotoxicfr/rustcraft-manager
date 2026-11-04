//! Faux `java` des tests du pilotage (aucun réseau, aucun vrai serveur) : imite la console d'un
//! serveur Minecraft. Copié sous le nom `java(.exe)` dans un dossier de test.
//!
//! - `-version` : répond comme un JDK 25 ;
//! - sinon : lit `faux.txt` (mode) et `server.properties` (port) dans le dossier courant, écrit
//!   son environnement dans `faux-env.txt`, ouvre le port (sauf `noport`), annonce « Done », puis
//!   lit l'entrée standard : `stop` (ignoré en mode `ignore_stop`), `save-all`, `crash`, le reste
//!   en écho ; chaque commande reçue est ajoutée à `faux-recu.txt`.
//! - mode `crash` : s'arrête avec le code 1 juste après « Done ».

use std::io::{BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-version") {
        eprintln!("openjdk version \"25.0.1\" 2026-01-20\nOpenJDK Runtime Environment (faux)");
        return;
    }
    let mode = std::fs::read_to_string("faux.txt").unwrap_or_default().trim().to_string();
    let props = std::fs::read_to_string("server.properties").unwrap_or_default();
    let port: u16 =
        props.lines().find_map(|l| l.strip_prefix("server-port=")).and_then(|p| p.trim().parse().ok()).unwrap_or(25565);
    let env: Vec<String> = std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
    let _ = std::fs::write("faux-env.txt", env.join("\n"));
    let _ = std::fs::write("faux-args.txt", args.join("\n"));
    let out = std::io::stdout();
    let say = |s: &str| {
        let mut o = out.lock();
        let _ = writeln!(o, "[00:00:00] [Server thread/INFO]: {s}");
        let _ = o.flush();
    };
    say("Starting minecraft server version 26.3");
    let _listener = if mode == "noport" { None } else { std::net::TcpListener::bind(("127.0.0.1", port)).ok() };
    say("Done (0.123s)! For help, type \"help\"");
    if mode == "crash" {
        std::thread::sleep(std::time::Duration::from_millis(300));
        eprintln!("Exception in server tick loop");
        std::process::exit(1);
    }
    // Banc : `flood:N` écrit N lignes de journal d'un coup (débit d'ingestion de la console).
    if let Some(n) = mode.strip_prefix("flood:").and_then(|n| n.parse::<u64>().ok()) {
        let mut o = std::io::BufWriter::new(out.lock());
        for i in 0..n {
            let _ =
                writeln!(o, "[00:00:00] [Server thread/INFO]: <neo> message de banc numéro {i} avec un peu de texte");
        }
        let _ = o.flush();
    }
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim().to_string();
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("faux-recu.txt") {
            let _ = writeln!(f, "{line}");
        }
        match line.as_str() {
            "stop" if mode == "ignore_stop" => say("ignoré"),
            "stop" => {
                say("Stopping the server");
                return;
            }
            "save-all" => say("Saved the game"),
            "crash" => std::process::exit(3),
            "list" => say("System chat: There are 1 of a max of 20 players online: neo"),
            "tick query" => {
                say("The game is running normally");
                say("Average time per tick: 4.1ms (Target: 50.0ms)");
            }
            other => say(&format!("<faux> {other}")),
        }
    }
}
