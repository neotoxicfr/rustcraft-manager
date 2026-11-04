//! Routes des fichiers de configuration d'un serveur (`/api/servers/{id}/configs`, `…/config…`).
//!
//! Lecture : session. Vérification et enregistrement : session + CSRF ([`Auth`] sur un POST) ;
//! l'enregistrement écrit une ligne d'audit. Chemins : liste blanche et confinement
//! ([`crate::configs::resolve`], 404 sinon). Corps bornés par route (voir `crate::router`).

use crate::AppState;
use crate::api::ApiJson;
use crate::configs::{self, ReadError};
use crate::error::AppError;
use crate::http::{Auth, ClientInfo};
use crate::servers::Server;
use crate::servers_api::{audit, is_admin, server};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use rc_manager_shared::*;
use serde::Deserialize;
use std::sync::Arc;

type St = State<Arc<AppState>>;

/// Corps maximal des routes qui portent un fichier (texte de 1 Mio échappé en JSON).
pub const BODY_MAX: usize = 3 * CONFIG_MAX_BYTES;

/// Un enregistrement à la fois (lecture de l'empreinte, historique, écriture) ; pris aussi par
/// le lancement d'un serveur quand il réécrit `server.properties`.
pub(crate) static SAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Analyses simultanées (vérification, enregistrement) : chacune peut tenir quelques arbres de
/// [`configs::MAX_TREE_BYTES`] ; au-delà, on attend une place, puis 503.
pub const PARSE_SLOTS: usize = 2;
pub(crate) static PARSE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(PARSE_SLOTS);
const PARSE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Tests qui tiennent toutes les places d'analyse : un à la fois.
#[cfg(test)]
pub(crate) static PARSE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) async fn parse_slot() -> Result<tokio::sync::SemaphorePermit<'static>, AppError> {
    slot_within(PARSE_WAIT).await
}

/// Travail bloquant qui analyse un fichier (vrai analyseur, gardes) : une place d'analyse est
/// prise avant, puis tenue par le fil jusqu'à sa fin (une requête abandonnée ne la libère pas).
pub(crate) async fn parse_blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, AppError> {
    let slot = parse_slot().await?;
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        f()
    })
    .await
    .map_err(|_| AppError::internal())
}

/// Travail bloquant fait sous `guard` (verrou des enregistrements) : la garde passe dans le fil
/// et n'est rendue qu'à la fin du travail, même si la requête est abandonnée entre-temps (délai
/// global de la requête) ; sinon elle revient à l'appelant, qui finit l'opération (historique)
/// sous le verrou. Tenue par le futur, elle serait rendue à l'abandon alors que le fil écrit
/// encore : un lancement pourrait démarrer Java pendant une modification admise avant lui.
/// `parsed` : une place d'analyse est tenue aussi ([`parse_blocking`]).
pub(crate) async fn blocking_held<G: Send + 'static, T: Send + 'static>(
    parsed: bool,
    guard: G,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<(T, G), AppError> {
    let f = move || (f(), guard);
    if parsed {
        parse_blocking(f).await
    } else {
        tokio::task::spawn_blocking(f).await.map_err(|_| AppError::internal())
    }
}

async fn slot_within(wait: std::time::Duration) -> Result<tokio::sync::SemaphorePermit<'static>, AppError> {
    match tokio::time::timeout(wait, PARSE.acquire()).await {
        Ok(Ok(p)) => Ok(p),
        _ => Err(AppError::busy()),
    }
}

fn not_found() -> AppError {
    AppError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound)
}

fn too_large() -> AppError {
    AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::FileTooLarge)
}

#[derive(Deserialize)]
pub struct PathQuery {
    path: String,
}

/// Fichier demandé : chemin résolu et format.
fn target(srv: &Server, rel: &str) -> Result<(std::path::PathBuf, ConfigFormat), AppError> {
    let sw = srv.row().software;
    let p = configs::resolve(&srv.dir, sw, rel).or_else(|| absent_list(&srv.dir, rel)).ok_or_else(not_found)?;
    let f = ConfigFormat::from_name(rel).ok_or_else(not_found)?;
    Ok((p, f))
}

/// Liste d'accès absente du dossier du serveur (le jeu la crée au premier démarrage) : ouverte
/// vide, créée par l'enregistrement ; une lecture n'écrit jamais rien.
fn absent_list(dir: &std::path::Path, rel: &str) -> Option<std::path::PathBuf> {
    AccessList::from_file(rel)?;
    let p = dir.join(rel);
    std::fs::symlink_metadata(&p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound).then_some(p)
}

fn read_file(p: &std::path::Path, f: ConfigFormat) -> Result<(Vec<u8>, String), AppError> {
    if let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str()))
        && absent_list(dir, name).is_some()
    {
        // Texte d'une liste vide, valide pour l'analyseur JSON (un texte vide serait une erreur de
        // syntaxe dès l'ouverture) ; l'empreinte reste celle du fichier absent (octets vides).
        return Ok((Vec::new(), "[]".to_string()));
    }
    configs::read(p, f).map_err(|e| match e {
        ReadError::TooLarge => too_large(),
        ReadError::NotText => AppError::unprocessable(ErrorCode::ConfigInvalid),
        ReadError::Io => not_found(),
    })
}

fn aad(server: i64, path: &str) -> String {
    format!("server_config_history:content:{server}:{path}")
}

pub async fn list(State(st): St, _auth: Auth, Path(id): Path<String>) -> Result<Json<Vec<ConfigFileInfo>>, AppError> {
    let srv = server(&st, &id)?;
    let (dir, sw) = (srv.dir.clone(), srv.row().software);
    let list =
        tokio::task::spawn_blocking(move || configs::discover(&dir, sw)).await.map_err(|_| AppError::internal())?;
    Ok(Json(list))
}

pub async fn read(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<ConfigFile>, AppError> {
    let srv = server(&st, &id)?;
    let (p, format) = target(&srv, &q.path)?;
    let (bytes, text) =
        tokio::task::spawn_blocking(move || read_file(&p, format)).await.map_err(|_| AppError::internal())??;
    // Ces fichiers portent des secrets (mot de passe RCON, secret du mandataire Velocity…) :
    // chaque lecture est tracée.
    audit(&st, "config_read", &info, &auth, format!("{} {}", srv.id, q.path));
    Ok(Json(ConfigFile { path: q.path, format, text, hash: configs::hash(&bytes) }))
}

/// Contrôles d'un texte valide par rapport au disque, dans l'ordre : clé gérée changée
/// (`server.properties`), valeur qui sort du dossier du serveur (tout compte), réglage réservé aux
/// administrateurs changé (autres comptes). Rend aussi la liste des réglages réservés changés.
pub(crate) fn guard(
    format: ConfigFormat,
    rel: &str,
    old: &str,
    new: &str,
    admin: bool,
) -> (Option<ConfigError>, Vec<String>) {
    // Noms comparés sans casse : sous Windows, `Server.Properties` EST `server.properties`.
    let rel = &crate::files::rule_rel(rel);
    if AccessList::from_file(rel).is_some() && !crate::access::shape_ok(new) {
        let message = "liste d'objets attendue ([{…}, …])".to_string();
        return (Some(ConfigError { message, ..Default::default() }), Vec::new());
    }
    if format == ConfigFormat::Properties
        && rel == "server.properties"
        && let Some(k) = crate::props::managed_changed(old, new)
    {
        return (Some(ConfigError { managed_key: Some(k.to_string()), ..Default::default() }), Vec::new());
    }
    // Chemin hors du dossier, ou arbre non vérifiable dans un fichier qui en désigne : refusé pour
    // tous, avec la construction en cause.
    if let Some(k) = configs::unsafe_value(format, rel, new) {
        let unverifiable = configs::unverifiable(format, new);
        return (Some(ConfigError { unsafe_key: Some(k), unverifiable, ..Default::default() }), Vec::new());
    }
    let sensitive = configs::sensitive_changes(format, rel, old, new);
    // Arbre non représentable par des chemins (clé complexe, plusieurs documents…) : les réglages
    // réservés n'y sont pas vérifiables, la modification entière est réservée aux administrateurs.
    let err = (!admin).then(|| sensitive.first()).flatten().map(|k| ConfigError {
        admin_key: Some(k.clone()),
        // Texte proposé vérifiable : c'est la version du disque qui ne l'est pas.
        unverifiable: (k == configs::UNKNOWN_KEY)
            .then(|| configs::unverifiable(format, new).unwrap_or(Unverifiable::OnDisk)),
        ..Default::default()
    });
    (err, sensitive)
}

pub async fn check(
    State(st): St,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ConfigCheckRequest>,
) -> Result<Json<ConfigCheck>, AppError> {
    let srv = server(&st, &id)?;
    if req.text.len() > CONFIG_MAX_BYTES || req.edits.len() > 64 {
        return Err(too_large());
    }
    let (p, format) = target(&srv, &req.path)?;
    let admin = is_admin(&st, auth.user_id).await?;
    let slot = parse_slot().await?;
    let res = tokio::task::spawn_blocking(move || -> Result<ConfigCheck, AppError> {
        // La place suit le fil bloquant : une requête abandonnée ne la libère pas avant la fin.
        let _slot = slot;
        let mut c = configs::check(format, &req.text, &req.edits);
        if c.error.is_none() {
            let (_, old) = read_file(&p, format)?;
            let new = c.text.as_deref().unwrap_or(&req.text);
            (c.error, c.sensitive) = guard(format, &req.path, &old, new, admin);
            // Avertissement dès l'ouverture (le refus, lui, porte déjà la cause).
            if c.error.is_none() {
                c.unverifiable = configs::unverifiable(format, new);
            }
        }
        Ok(c)
    })
    .await
    .map_err(|_| AppError::internal())??;
    Ok(Json(res))
}

pub async fn save(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ConfigSaveRequest>,
) -> Result<Json<ConfigSaved>, AppError> {
    let srv = server(&st, &id)?;
    if req.text.len() > CONFIG_MAX_BYTES {
        return Err(too_large());
    }
    let (p, format) = target(&srv, &req.path)?;
    let lock = SAVE_LOCK.lock().await;
    // Ni pendant un démarrage, ni pendant un arrêt, ni pendant une installation : le serveur
    // (ou le gestionnaire) écrit lui-même ces fichiers à ces moments-là.
    let busy = |s: &Server| matches!(s.state(), ServerState::Starting | ServerState::Stopping) || s.info().op.is_some();
    if busy(&srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    // Listes d'accès serveur en marche : le jeu les tient en mémoire et les réécrit ; seule la
    // liste blanche se relit (`whitelist reload`), les autres se règlent serveur arrêté (ou par
    // le mode visuel, qui passe par la console).
    let list = AccessList::from_file(&req.path);
    if list.is_some_and(|l| l != AccessList::Whitelist) && srv.state() == ServerState::Running {
        return Err(AppError::conflict(ErrorCode::StopFirst));
    }
    let (p2, rel) = (p.clone(), req.path.clone());
    let (old_bytes, old_text) =
        tokio::task::spawn_blocking(move || read_file(&p2, format)).await.map_err(|_| AppError::internal())??;
    if configs::hash(&old_bytes) != req.base_hash {
        return Err(AppError::conflict(ErrorCode::ConfigChanged));
    }
    // Vrai analyseur avant toute écriture.
    // Analyse dans un fil bloquant (jusqu'à 1 Mio de texte).
    let (text, rel2) = (req.text, rel.clone());
    let admin = is_admin(&st, auth.user_id).await?;
    let slot = parse_slot().await?;
    let checked = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        if configs::check(format, &text, &[]).error.is_some() {
            return Err(AppError::unprocessable(ErrorCode::ConfigInvalid));
        }
        match guard(format, &rel2, &old_text, &text, admin) {
            (Some(e), _) if e.admin_key.is_some() => Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden)),
            (Some(_), _) => Err(AppError::unprocessable(ErrorCode::ConfigInvalid)),
            (None, sensitive) => Ok((text, sensitive)),
        }
    })
    .await
    .map_err(|_| AppError::internal())?;
    let (text, sensitive) = match checked {
        Ok(t) => t,
        Err(e) => {
            if e.code == ErrorCode::Forbidden {
                audit(&st, "config_refused", &info, &auth, format!("{} {rel} : réglage réservé", srv.id));
            }
            return Err(e);
        }
    };
    // `server.properties` lu en ISO-8859-1 : réécrit dans cet encodage (UTF-8 sinon).
    let new_bytes = if format == ConfigFormat::Properties {
        crate::props::encode_like(&old_bytes, &text)
    } else {
        text.into_bytes()
    };
    let hash = configs::hash(&new_bytes);
    let restart_needed = srv.state() == ServerState::Running;
    if new_bytes == old_bytes {
        return Ok(Json(ConfigSaved { hash, restart_needed: false, unchanged: true }));
    }
    // Écriture atomique (temporaire dans le même dossier, fsync, renommage, fsync du dossier).
    // Dernier contrôle juste avant : le serveur n'a pas commencé à démarrer entre-temps.
    if busy(&srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    // Verrou passé au fil de l'écriture (rendu à sa fin même si la requête est abandonnée), puis
    // repris pour l'historique.
    let (written, _lock) = blocking_held(false, lock, move || crate::fsutil::write_atomic(&p, &new_bytes)).await?;
    written.map_err(|e| {
        tracing::warn!("serveur {} : écriture de {rel} impossible : {e}", srv.id);
        AppError::internal()
    })?;
    // Fichier créé (liste absente) : pas de version précédente.
    if !old_bytes.is_empty() {
        keep_version(&st, srv.id.get(), auth.user_id, &rel, old_bytes).await;
    }
    // Liste blanche modifiée serveur en marche : relue tout de suite par le jeu.
    let restart_needed = if list == Some(AccessList::Whitelist) && restart_needed {
        let _ = st.servers.command(&srv, &auth.username, "whitelist reload").await;
        false
    } else {
        restart_needed
    };
    let detail = if sensitive.is_empty() {
        format!("{} {}", srv.id, rel)
    } else {
        let keys: String = sensitive.join(", ").chars().take(300).collect();
        format!("{} {} (réglages réservés : {keys})", srv.id, rel)
    };
    audit(&st, "config_saved", &info, &auth, detail);
    Ok(Json(ConfigSaved { hash, restart_needed, unchanged: false }))
}

/// Garde l'état du disque avant une écriture réussie (chiffré) ; au plus CONFIG_HISTORY_MAX
/// versions par fichier et HISTORY_TOTAL_BYTES pour tout le gestionnaire (les plus anciennes
/// partent). Appelé APRÈS l'écriture : une écriture ratée ne laisse pas de version fantôme.
pub(crate) async fn keep_version(st: &AppState, sid: i64, uid: i64, rel: &str, old_bytes: Vec<u8>) {
    let path_db = rel.to_string();
    let saved = st
        .db
        .call(move |c, keys| {
            let enc = keys.encrypt(&aad(sid, &path_db), &old_bytes);
            c.execute(
                "INSERT INTO server_config_history (server_id, path, ts, user_id, size, content_enc)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![sid, path_db, crate::db::now(), uid, old_bytes.len() as i64, enc],
            )?;
            c.execute(
                "DELETE FROM server_config_history WHERE server_id = ?1 AND path = ?2 AND id NOT IN
                 (SELECT id FROM server_config_history WHERE server_id = ?1 AND path = ?2 ORDER BY id DESC LIMIT ?3)",
                rusqlite::params![sid, path_db, CONFIG_HISTORY_MAX as i64],
            )?;
            c.execute(
                "DELETE FROM server_config_history WHERE id IN (SELECT id FROM
                 (SELECT id, SUM(size) OVER (ORDER BY id DESC) AS cum FROM server_config_history) WHERE cum > ?1)",
                [HISTORY_TOTAL_BYTES as i64],
            )?;
            Ok(())
        })
        .await;
    if saved.is_err() {
        tracing::warn!("serveur {sid} : version précédente de {rel} non gardée dans l'historique");
    }
}

/// Taille totale de l'historique des réglages (tous serveurs, tous fichiers).
pub const HISTORY_TOTAL_BYTES: usize = 256 * 1024 * 1024;

pub async fn history(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<Vec<ConfigVersion>>, AppError> {
    let srv = server(&st, &id)?;
    if !configs::rel_allowed(srv.row().software, &q.path) {
        return Err(not_found());
    }
    let sid = srv.id.get();
    let list = st
        .db
        .call(move |c, _| {
            let mut s = c.prepare(
                "SELECT h.id, h.ts, u.username, h.size FROM server_config_history h
                 LEFT JOIN users u ON u.id = h.user_id
                 WHERE h.server_id = ?1 AND h.path = ?2 ORDER BY h.id DESC LIMIT ?3",
            )?;
            let rows = s
                .query_map(rusqlite::params![sid, q.path, CONFIG_HISTORY_MAX as i64], |r| {
                    Ok(ConfigVersion {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        user: r.get(2)?,
                        size: r.get::<_, i64>(3)?.max(0) as u64,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(list))
}

pub async fn version(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path((id, vid)): Path<(String, i64)>,
) -> Result<Json<ConfigVersionContent>, AppError> {
    let srv = server(&st, &id)?;
    let sid = srv.id.get();
    let row = st
        .db
        .call(move |c, keys| {
            let r: Option<(String, String)> = c
                .query_row(
                    "SELECT path, content_enc FROM server_config_history WHERE id = ?1 AND server_id = ?2",
                    rusqlite::params![vid, sid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();
            Ok(r.map(|(path, enc)| {
                let plain = keys.decrypt(&aad(sid, &path), &enc).ok();
                (path, plain)
            }))
        })
        .await?;
    let (path, plain) = row.ok_or_else(not_found)?;
    let plain = plain.ok_or_else(AppError::internal)?;
    let text = match String::from_utf8(plain) {
        Ok(s) => s,
        Err(e) => e.into_bytes().iter().map(|&b| b as char).collect(),
    };
    audit(&st, "config_version_read", &info, &auth, format!("{} {path} #{vid}", srv.id));
    Ok(Json(ConfigVersionContent { id: vid, path, text }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arbre que le mode visuel ne représente pas (ancre, alias, étiquette, fusion, clé complexe,
    /// plusieurs documents, racine en liste) : les réglages réservés restent vérifiés, sur l'arbre
    /// complet, ou la modification entière est réservée (jamais « aucune clé »).
    #[test]
    fn arbre_non_representable_verifie() {
        let y = ConfigFormat::Yaml;
        let cases: &[(&str, &str)] = &[
            // Ancre sur la section.
            ("settings: &s\n  bungeecord: false\n", "settings: &s\n  bungeecord: true\n"),
            // Alias : la valeur change à l'ancre, loin de la clé réservée.
            ("base: &b false\nsettings:\n  bungeecord: *b\n", "base: &b true\nsettings:\n  bungeecord: *b\n"),
            // Étiquette sur la section.
            ("settings: !!map\n  bungeecord: false\n", "settings: !!map\n  bungeecord: true\n"),
            // Étiquette sur la valeur : texte « true » contre booléen.
            ("settings:\n  bungeecord: !!str true\n", "settings:\n  bungeecord: true\n"),
            // Fusion `<<` (appliquée par SnakeYAML).
            ("b: &b {bungeecord: false}\nsettings:\n  <<: *b\n", "b: &b {bungeecord: true}\nsettings:\n  <<: *b\n"),
            // Clé complexe ailleurs dans le fichier.
            ("? [x]\n: 1\nsettings:\n  bungeecord: false\n", "? [x]\n: 1\nsettings:\n  bungeecord: true\n"),
            // Plusieurs documents.
            ("settings: {bungeecord: false}\n---\na: 1\n", "settings: {bungeecord: true}\n---\na: 1\n"),
        ];
        for (old, new) in cases {
            let (e, sensitive) = guard(y, "bukkit.yml", old, new, false);
            let e = e.unwrap_or_else(|| panic!("non-admin accepté : {new:?}"));
            assert!(e.admin_key.is_some(), "{new:?} {e:?}");
            assert!(!sensitive.is_empty());
            let (e, _) = guard(y, "bukkit.yml", old, new, true);
            assert!(e.is_none(), "administrateur : permis ({new:?})");
        }
        // Fusion par étiquette sur un réglage réservé de spigot.yml (hors mots réservés).
        let old = "b: &b {restart-on-crash: true}\nsettings:\n  !!merge m: *b\n";
        let (e, _) = guard(y, "spigot.yml", old, &old.replace("true", "false"), false);
        assert_eq!(e.and_then(|e| e.admin_key).as_deref(), Some("settings.restart-on-crash"));
        // `!!pairs` : non représentable, réservé.
        let (e, _) = guard(y, "bukkit.yml", "a: !!pairs\n  - x: 1\n", "a: !!pairs\n  - x: 2\n", false);
        assert!(e.is_some_and(|e| e.admin_key.as_deref() == Some("*")));
        // Construction en cause rendue (l'interface dit pourquoi et quoi faire).
        let (e, _) = guard(y, "bukkit.yml", cases[5].0, cases[5].1, false);
        assert_eq!(e.unwrap().unverifiable, Some(Unverifiable::ComplexKey), "{:?}", cases[5]);
        for (bad, why) in [
            ("a: 1\n---\nb: 2\n", Unverifiable::ManyDocuments),
            ("a: !!set {x: null}\n", Unverifiable::CollectionTag),
            ("a: &s\n  b: *s\n", Unverifiable::UnknownAlias),
            ("a: *nulle\n", Unverifiable::Syntax),
            ("a:\n  <<: 1\n", Unverifiable::BadMerge),
        ] {
            let (e, _) = guard(y, "bukkit.yml", "a: 0\n", bad, false);
            assert_eq!(e.and_then(|e| e.unverifiable), Some(why), "{bad:?}");
            // Disque non vérifiable, texte proposé lisible : la version du disque est en cause.
            let (e, _) = guard(y, "bukkit.yml", bad, "a: 0\n", false);
            assert_eq!(e.and_then(|e| e.unverifiable), Some(Unverifiable::OnDisk), "{bad:?}");
        }
        // spigot.yml non vérifiable : refusé pour tous, administrateurs compris, cause rendue.
        let (e, _) = guard(y, "spigot.yml", "settings: {}\n", "settings: !!omap []\n", true);
        let e = e.expect("refusé même à un administrateur");
        assert_eq!(
            (e.unsafe_key.as_deref(), e.unverifiable),
            (Some("settings.restart-script"), Some(Unverifiable::CollectionTag))
        );
        // Vrai chemin hors du dossier : pas de cause « non vérifiable ».
        let (e, _) = guard(y, "spigot.yml", "settings: {}\n", "settings:\n  restart-script: /bin/x\n", true);
        assert_eq!(e.map(|e| (e.unsafe_key.is_some(), e.unverifiable)), Some((true, None)));
        // Ailleurs que sur un réglage réservé : libre (ancre, alias, fusion résolus).
        let (e, _) = guard(y, "bukkit.yml", "a: &a 1\nb: *a\n", "a: &a 2\nb: *a\n", false);
        assert!(e.is_none(), "{e:?}");
        // JSON dont la racine est une liste (mode texte seulement).
        let (e, _) =
            guard(ConfigFormat::Json, "config/x.json", r#"[{"webhook_url":"a"}]"#, r#"[{"webhook_url":"b"}]"#, false);
        assert!(e.is_some_and(|e| e.admin_key.as_deref() == Some("0.webhook_url")));
        // TOML : table en ligne, tableau de tables, clé pointée.
        for (old, new) in [
            ("a = {webhook_url = \"x\"}\n", "a = {webhook_url = \"y\"}\n"),
            ("[[h]]\nwebhook_url = \"x\"\n", "[[h]]\nwebhook_url = \"y\"\n"),
            ("a.webhook_url = \"x\"\n", "a.webhook_url = \"y\"\n"),
        ] {
            let (e, _) = guard(ConfigFormat::Toml, "config/x.toml", old, new, false);
            assert!(e.is_some_and(|e| e.admin_key.is_some()), "{new}");
        }
    }

    /// Chemin hors du dossier caché derrière une ancre, un alias, une étiquette ou une fusion :
    /// refusé pour tout compte, à l'enregistrement comme au lancement ; arbre non représentable :
    /// refusé aussi.
    #[test]
    fn chemin_cache_refuse() {
        let ok = "settings:\n  restart-script: ./start.sh\n";
        for bad in [
            "settings: &s\n  restart-script: ../../evil.sh\n",
            "settings: !!map\n  restart-script: ../../evil.sh\n",
            "settings:\n  restart-script: !!str ../../evil.sh\n",
            "x: &x ../../evil.sh\nsettings:\n  restart-script: *x\n",
            "b: &b {restart-script: ../../evil.sh}\nsettings:\n  <<: *b\n",
            "? [x]\n: 1\nsettings:\n  restart-script: ./start.sh\n",
            "settings:\n  restart-script: ./start.sh\n---\nsettings:\n  restart-script: ./start.sh\n",
            // Fusion par étiquette, quel que soit le texte de la clé (SnakeYAML).
            "b: &b {restart-script: ../../evil.sh}\nsettings:\n  !!merge m: *b\n",
            "b: &b {restart-script: ../../evil.sh}\nsettings:\n  !<tag:yaml.org,2002:merge> m: *b\n",
            // Étiquette de collection hors schéma de base : non représentable.
            "settings: !!omap\n  - restart-script: ../../evil.sh\n",
        ] {
            let (e, _) = guard(ConfigFormat::Yaml, "spigot.yml", ok, bad, true);
            assert_eq!(e.and_then(|e| e.unsafe_key).as_deref(), Some("settings.restart-script"), "{bad}");
            let d = std::env::temp_dir().join(format!("rcm-lancement-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("spigot.yml"), ok).unwrap();
            assert!(!crate::servers::launch_paths_unsafe(&d), "valeur sûre : lancement permis");
            std::fs::write(d.join("spigot.yml"), bad).unwrap();
            assert!(crate::servers::launch_paths_unsafe(&d), "lancement refusé : {bad}");
            let r = crate::servers::launch_refusal(&d).unwrap();
            assert_eq!(r.file, "spigot.yml", "le fichier en cause est nommé");
            let _ = std::fs::remove_dir_all(&d);
        }
        assert!(guard(ConfigFormat::Yaml, "spigot.yml", ok, ok, true).0.is_none());
        // Cause nommée : valeur refusée (et laquelle), arbre non vérifiable (pourquoi), illisible.
        use rc_manager_shared::{LaunchCause, Unverifiable};
        let d = std::env::temp_dir().join(format!("rcm-lancement-cause-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("server.properties"), "level-name=../autre\n").unwrap();
        let r = crate::servers::launch_refusal(&d).unwrap();
        assert_eq!(
            (r.file.as_str(), r.cause, r.key.as_deref()),
            ("server.properties", LaunchCause::UnsafeValue, Some("level-name"))
        );
        std::fs::remove_file(d.join("server.properties")).unwrap();
        std::fs::write(d.join("spigot.yml"), "x: &x ../a.sh\nsettings:\n  restart-script: *x\n---\nb: 1\n").unwrap();
        let r = crate::servers::launch_refusal(&d).unwrap();
        assert_eq!(r.cause, LaunchCause::Unverifiable(Unverifiable::ManyDocuments));
        std::fs::write(d.join("spigot.yml"), vec![b'#'; 2 * 1024 * 1024]).unwrap();
        assert_eq!(crate::servers::launch_refusal(&d).unwrap().cause, LaunchCause::Unreadable);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Casse des noms (Windows ouvre `Server.Properties` comme `server.properties`) : clés gérées,
    /// réglages réservés et chemins surveillés s'appliquent quelle que soit la casse demandée ;
    /// nom court 8.3 refusé dans une valeur de chemin (`level-name`).
    #[test]
    fn casse_des_noms() {
        let p = ConfigFormat::Properties;
        let (e, _) = guard(p, "Server.Properties", "online-mode=true\n", "online-mode=false\n", false);
        assert_eq!(e.and_then(|e| e.admin_key).as_deref(), Some("online-mode"));
        let (e, _) = guard(p, "SERVER.PROPERTIES", "level-name=world\n", "level-name=../x\n", true);
        assert_eq!(e.and_then(|e| e.unsafe_key).as_deref(), Some("level-name"));
        let (e, _) = guard(p, "Server.properties", "server-port=1\n", "server-port=2\n", true);
        assert_eq!(e.and_then(|e| e.managed_key).as_deref(), Some("server-port"));
        // `ſ` (s long) : ramené à `s` (règle appliquée plus large, jamais moins).
        let (e, _) = guard(p, "ſerver.properties", "online-mode=true\n", "online-mode=false\n", false);
        assert_eq!(e.and_then(|e| e.admin_key).as_deref(), Some("online-mode"));
        let y = ConfigFormat::Yaml;
        let ok = "settings:\n  restart-script: ./start.sh\n  restart-on-crash: true\n";
        let (e, _) = guard(y, "Spigot.YML", ok, "settings:\n  restart-script: ../x.sh\n", true);
        assert_eq!(e.and_then(|e| e.unsafe_key).as_deref(), Some("settings.restart-script"));
        let off = ok.replace("crash: true", "crash: false");
        let (e, _) = guard(y, "SPIGOT.yml", ok, &off, false);
        assert_eq!(e.and_then(|e| e.admin_key).as_deref(), Some("settings.restart-on-crash"));
        let (e, _) = guard(ConfigFormat::Json, "OPS.json", "[]", "{}", true);
        assert!(e.is_some(), "liste d'accès reconnue sans casse");
        let (e, _) = guard(p, "server.properties", "level-name=world\n", "level-name=WORLD~1\n", true);
        assert_eq!(e.and_then(|e| e.unsafe_key).as_deref(), Some("level-name"));
    }

    /// Au plus [`PARSE_SLOTS`] analyses à la fois ; la suivante attend puis reçoit 503.
    #[tokio::test]
    async fn analyses_simultanees_bornees() {
        let _t = PARSE_TEST_LOCK.lock().await;
        let short = std::time::Duration::from_millis(50);
        let held: Vec<_> = (0..PARSE_SLOTS).map(|_| PARSE.try_acquire().expect("place libre")).collect();
        let e = slot_within(short).await.expect_err("plus de place");
        assert_eq!(e.code, ErrorCode::Busy);
        drop(held);
        assert!(slot_within(short).await.is_ok());
    }

    /// Requête abandonnée (délai global) pendant une écriture sous le verrou des enregistrements :
    /// le verrou reste pris jusqu'à la fin du fil (un lancement ne démarre pas Java pendant ce
    /// temps), puis il est rendu.
    #[tokio::test]
    async fn verrou_tenu_jusqu_a_la_fin_du_fil() {
        let _t = PARSE_TEST_LOCK.lock().await;
        let lock = SAVE_LOCK.lock().await;
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let work = blocking_held(false, lock, move || {
            let _ = rx.recv_timeout(std::time::Duration::from_secs(10));
        });
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), work).await.is_err(), "abandonnée");
        assert!(SAVE_LOCK.try_lock().is_err(), "verrou tenu par le fil après l'abandon");
        tx.send(()).unwrap();
        let back = tokio::time::timeout(std::time::Duration::from_secs(5), SAVE_LOCK.lock()).await;
        assert!(back.is_ok(), "rendu à la fin du fil");
    }
}
