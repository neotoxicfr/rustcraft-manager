//! Banc des réglages : analyse et édition ciblée sur les fichiers réels (`tests/fixtures/configs`).
//! `cargo run --release --example banc_configs` ; machine calme.

use rc_manager::configs::check;
use rc_manager_shared::{ConfigEdit, ConfigFormat, ConfigValue, EntryKind};
use std::path::Path;
use std::time::Instant;

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() { walk(&p, out) } else { out.push(p) }
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/configs");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    println!("{:<52} {:>8} {:>10} {:>12}", "fichier", "octets", "analyse µs", "édition µs");
    for p in files {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&p).unwrap();
        let format = ConfigFormat::from_name(&rel).unwrap();
        let n = 200;
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(check(format, &text, &[]));
        }
        let analyse = t.elapsed().as_secs_f64() * 1e6 / n as f64;
        // Dernière valeur du fichier (pire cas pour une édition).
        let tree = check(format, &text, &[]).entries;
        let last = tree.iter().rev().find(|e| e.kind == EntryKind::Value && e.value.is_some());
        let edit = last.map(|e| {
            let v = match e.value.clone().unwrap() {
                ConfigValue::Bool(b) => ConfigValue::Bool(!b),
                ConfigValue::Int(i) => ConfigValue::Int(i + 1),
                ConfigValue::Float(f) => ConfigValue::Float(f + 1.0),
                ConfigValue::Str(s) => ConfigValue::Str(format!("{s}x")),
                ConfigValue::Null => ConfigValue::Str("x".into()),
            };
            let edits = [ConfigEdit::Set { path: e.path.clone(), value: v }];
            let t = Instant::now();
            for _ in 0..n {
                std::hint::black_box(check(format, &text, &edits));
            }
            t.elapsed().as_secs_f64() * 1e6 / n as f64
        });
        println!(
            "{rel:<52} {:>8} {analyse:>10.0} {:>12}",
            text.len(),
            edit.map_or_else(|| "—".into(), |e| format!("{e:.0}"))
        );
    }
}
