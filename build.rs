//! Embarque l'interface construite (`web/dist`, sortie de `trunk build --release`) dans le binaire.
//!
//! Pour chaque fichier : octets bruts, version gzip calculée ici une fois pour toutes (rien à
//! compresser à l'exécution), empreinte SHA-256 pour l'ETag. Les scripts en ligne de
//! `index.html` (amorce de `trunk`) reçoivent leur empreinte pour la politique CSP, qui interdit
//! tout autre script en ligne.
//!
//! Sans `web/dist` (interface pas encore construite), une page d'explication est embarquée : le
//! workspace natif compile sans `trunk`. `RC_MANAGER_WEB_DIST` remplace le dossier source.

use base64::Engine;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

const FALLBACK: &str = "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Rustcraft Manager</title></head>\
<body><h1>Rustcraft Manager</h1><p lang=\"fr\">L'interface n'est pas embarquée dans ce binaire : construisez-la avec \
<code>trunk build --release</code> dans <code>web</code>, puis recompilez \
<code>rc-manager</code>. L'API reste disponible sous <code>/api</code>.</p>\
<p lang=\"en\">The web interface is not embedded in this binary: build it with \
<code>trunk build --release</code> in <code>web</code>, then rebuild \
<code>rc-manager</code>. The API is still available under <code>/api</code>.</p></body></html>";

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=RC_MANAGER_WEB_DIST");
    let dist =
        std::env::var_os("RC_MANAGER_WEB_DIST").map(PathBuf::from).unwrap_or_else(|| manifest.join("web").join("dist"));
    // Le dossier `web` existe toujours (sources) : le surveiller suffit à voir apparaître `dist`.
    println!("cargo:rerun-if-changed={}", dist.display());
    println!("cargo:rerun-if-changed={}", manifest.join("web").display());

    let gen_dir = out.join("web");
    let _ = std::fs::remove_dir_all(&gen_dir);
    std::fs::create_dir_all(&gen_dir).unwrap();

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let built = dist.join("index.html").is_file();
    if built {
        collect(&dist, &dist, &mut files);
    } else {
        let p = gen_dir.join("index.html");
        std::fs::write(&p, FALLBACK).unwrap();
        files.push(("/index.html".into(), p));
    }
    files.sort();

    // Empreinte de l'interface : tous les fichiers sauf le service worker (qui la reçoit). Elle
    // nomme le cache du service worker et `/version` la renvoie : une interface reconstruite
    // purge l'ancien cache et les onglets ouverts se rechargent.
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for (url, path) in files.iter().filter(|(u, _)| u != SW_PATH) {
        ctx.update(url.as_bytes());
        ctx.update(&std::fs::read(path).unwrap());
    }
    let ui_version: String = ctx.finish().as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect();

    commit_env(&manifest);

    let mut code = String::new();
    let mut csp_hashes = String::new();
    writeln!(code, "pub const WEB_BUILT: bool = {built};").unwrap();
    writeln!(code, "pub const UI_VERSION: &str = {ui_version:?};").unwrap();
    writeln!(code, "pub static ASSETS: &[Asset] = &[").unwrap();
    for (i, (url, path)) in files.iter_mut().enumerate() {
        if url == SW_PATH {
            let sw = std::fs::read_to_string(&*path).unwrap();
            assert!(sw.contains(SW_PLACEHOLDER), "sw.js : {SW_PLACEHOLDER} absent");
            let p = gen_dir.join("sw.js");
            std::fs::write(&p, sw.replace(SW_PLACEHOLDER, &ui_version)).unwrap();
            *path = p;
        }
        let (url, path) = (&*url, &*path);
        let raw = std::fs::read(path).unwrap();
        let digest = ring::digest::digest(&ring::digest::SHA256, &raw);
        let etag: String = digest.as_ref()[..12].iter().map(|b| format!("{b:02x}")).collect();
        let mime = mime_of(url);
        if url == "/index.html" {
            for script in inline_scripts(&String::from_utf8_lossy(&raw)) {
                let h = ring::digest::digest(&ring::digest::SHA256, script.as_bytes());
                let b64 = base64::engine::general_purpose::STANDARD.encode(h.as_ref());
                write!(csp_hashes, " 'sha256-{b64}'").unwrap();
            }
        }
        let gz = if compressible(mime) {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            enc.write_all(&raw).unwrap();
            let z = enc.finish().unwrap();
            // Gardée seulement si elle fait gagner au moins 5 %.
            if z.len() * 100 < raw.len() * 95 {
                let gp = gen_dir.join(format!("{i}.gz"));
                std::fs::write(&gp, &z).unwrap();
                Some(gp)
            } else {
                None
            }
        } else {
            None
        };
        let gz_expr = match gz {
            Some(p) => format!("Some(include_bytes!({:?}))", p.display().to_string()),
            None => "None".into(),
        };
        writeln!(
            code,
            "    Asset {{ path: {url:?}, mime: {mime:?}, body: include_bytes!({:?}), gzip: {gz_expr}, etag: \"\\\"{etag}\\\"\", etag_gz: \"\\\"{etag}-gz\\\"\", immutable: {} }},",
            path.display().to_string(),
            immutable(url)
        )
        .unwrap();
    }
    writeln!(code, "];").unwrap();
    writeln!(code, "pub const CSP_SCRIPT_HASHES: &str = {csp_hashes:?};").unwrap();
    std::fs::write(out.join("assets_gen.rs"), code).unwrap();
}

const SW_PATH: &str = "/sw.js";
/// Remplacé dans `sw.js` par l'empreinte de l'interface.
const SW_PLACEHOLDER: &str = "__RCM_UI_VERSION__";

/// `RCM_COMMIT` : `RCM_GIT_COMMIT` (construction Docker, sans `.git`), sinon `git rev-parse`.
fn commit_env(manifest: &Path) {
    println!("cargo:rerun-if-env-changed=RCM_GIT_COMMIT");
    let git = manifest.join(".git");
    if git.is_dir() {
        println!("cargo:rerun-if-changed={}", git.join("HEAD").display());
        println!("cargo:rerun-if-changed={}", git.join("refs").join("heads").display());
    }
    let commit = std::env::var("RCM_GIT_COMMIT")
        .ok()
        .filter(|c| !c.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .current_dir(manifest)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "inconnu".into());
    let commit: String = commit.chars().filter(|c| c.is_ascii_alphanumeric()).take(40).collect();
    println!("cargo:rustc-env=RCM_COMMIT={commit}");
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if p.is_dir() {
            collect(root, &p, out);
        } else {
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            out.push((format!("/{rel}"), p));
        }
    }
}

fn mime_of(url: &str) -> &'static str {
    let ext = url.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn compressible(mime: &str) -> bool {
    mime.starts_with("text/") || mime.contains("json") || mime == "application/wasm" || mime == "image/svg+xml"
}

/// Fichiers dont le nom porte l'empreinte du contenu (`trunk` : `nom-<hash>.ext` ou
/// `nom-<hash>_bg.wasm`, empreinte de 64 bits en hexadécimal sans zéros de tête, donc parfois
/// moins de 16 chiffres) : gardés en cache un an. Les autres (index, manifeste, service worker,
/// icônes) sont revalidés à chaque fois (ETag).
fn immutable(url: &str) -> bool {
    let name = url.rsplit('/').next().unwrap_or("");
    let stem = name.split('.').next().unwrap_or("");
    let stem = stem.strip_suffix("_bg").unwrap_or(stem);
    match stem.rsplit_once('-') {
        Some((_, h)) => h.len() >= 12 && h.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// Contenu exact des `<script>` en ligne (sans `src`) d'une page.
fn inline_scripts(html: &str) -> Vec<String> {
    let mut res = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        let after = &rest[start..];
        let Some(tag_end) = after.find('>') else { break };
        let tag = &after[..tag_end];
        let body_start = tag_end + 1;
        let Some(close) = after[body_start..].find("</script>") else {
            break;
        };
        if !tag.contains("src=") {
            res.push(after[body_start..body_start + close].to_string());
        }
        rest = &after[body_start + close..];
    }
    res
}
