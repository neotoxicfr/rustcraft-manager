//! Routes du gestionnaire de fichiers (`/api/servers/{id}/files…`, onglet « Fichiers »).
//!
//! Lecture : session ; lecture d'un fichier sensible et tout téléchargement tracés dans
//! l'audit. Actions : session + CSRF, audit, bornes (chemin, taille d'envoi par configuration).
//! Confinement : [`crate::files`] (forme du chemin, puis disque AU MOMENT de l'opération).
//! Règles en plus :
//! - démarrage, arrêt, installation en cours : aucune modification (le serveur écrit) ;
//! - monde (`level-name` et ses dimensions) : aucune modification serveur en marche ;
//! - `eula.txt` : écran de l'EULA seulement ; listes d'accès : onglet « Joueurs » serveur en marche ;
//! - fichiers de format connu : vrai analyseur et gardes des réglages (clés gérées, réglages
//!   réservés aux administrateurs, chemins), que le texte vienne de l'éditeur, d'un envoi ou d'un
//!   renommage ;
//! - programmes et code (`.jar`, `.sh`, `.bat`…) : créés, remplacés ou renommés par les
//!   administrateurs seulement ;
//! - fichiers sans analyseur des dossiers de réglages (`plugins/`, `mods/`, `config/`, racine) :
//!   règle par ligne du format texte ;
//! - supprimer ou déplacer = écrire vide, restaurer = créer (réglages réservés compris) ;
//! - suppression vers la corbeille ; dossier : nom recopié.

use crate::AppState;
use crate::api::ApiJson;
use crate::configs_api::guard;
use crate::error::AppError;
use crate::files::{self, FsErr};
use crate::http::{Auth, ClientInfo};
use crate::servers::Server;
use crate::servers_api::{audit, is_admin, server};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rc_manager_shared::*;
use serde::Deserialize;
use std::sync::Arc;

type St = State<Arc<AppState>>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, AppError> {
    tokio::task::spawn_blocking(f).await.map_err(|_| AppError::internal())
}

/// Fichier de format connu : son contenu passe le vrai analyseur et les gardes des réglages.
fn known_format(rel: &str) -> bool {
    ConfigFormat::from_name(&files::rule_rel(rel)).is_some()
}

/// Travail bloquant ; `parsed` : il analyse un fichier, une place d'analyse est tenue (bornée
/// comme dans l'onglet « Réglages », 503 au-delà de l'attente).
async fn run<T: Send + 'static>(parsed: bool, f: impl FnOnce() -> T + Send + 'static) -> Result<T, AppError> {
    if parsed { crate::configs_api::parse_blocking(f).await } else { blocking(f).await }
}

fn fs_err(e: FsErr) -> AppError {
    match e {
        FsErr::Invalid => AppError::unprocessable(ErrorCode::InvalidPath),
        FsErr::NotFound => AppError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        FsErr::Exists => AppError::conflict(ErrorCode::AlreadyExists),
        FsErr::WrongKind => AppError::unprocessable(ErrorCode::InvalidPath),
        FsErr::TooLarge => AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::FileTooLarge),
        FsErr::NotText => AppError::unprocessable(ErrorCode::NotText),
        FsErr::Io => AppError::internal(),
        FsErr::TrashTooLarge => AppError::new(StatusCode::INSUFFICIENT_STORAGE, ErrorCode::TrashTooLarge),
        FsErr::TrashFull => AppError::new(StatusCode::INSUFFICIENT_STORAGE, ErrorCode::TrashFull),
    }
}

/// Travail bloquant sous le verrou des enregistrements : le verrou est tenu par le fil jusqu'à la
/// fin du travail (même requête abandonnée), puis rendu à l'appelant ([`crate::configs_api::blocking_held`]).
async fn run_locked<T: Send + 'static>(
    parsed: bool,
    lock: tokio::sync::MutexGuard<'static, ()>,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<(T, tokio::sync::MutexGuard<'static, ()>), AppError> {
    crate::configs_api::blocking_held(parsed, lock, f).await
}

fn busy(s: &Server) -> bool {
    matches!(s.state(), ServerState::Starting | ServerState::Stopping) || s.info().op.is_some()
}

fn forbidden() -> AppError {
    AppError::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden)
}

/// Chemin dont la forme est acceptée (sinon 422 tout de suite, sans disque).
fn rel_ok(rel: &str) -> Result<(), AppError> {
    files::parse_rel(rel).map(|_| ()).ok_or_else(|| AppError::unprocessable(ErrorCode::InvalidPath))
}

/// Règles communes à toute modification touchant `rels` ; `created` : chemins créés ou remplacés
/// (programmes réservés aux administrateurs).
async fn may_modify(
    st: &AppState,
    srv: &Server,
    auth: &Auth,
    rels: &[&str],
    created: &[&str],
) -> Result<bool, AppError> {
    for r in rels {
        rel_ok(r)?;
    }
    if busy(srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    if rels.iter().any(|r| files::managed_rel(r)) {
        return Err(AppError::unprocessable(ErrorCode::ManagedFile));
    }
    let running = srv.state() == ServerState::Running;
    if running {
        let dir = srv.dir.clone();
        let worlds = blocking(move || files::world_dirs(&dir)).await?;
        if rels.iter().any(|r| files::under_any(r, &worlds)) {
            return Err(AppError::conflict(ErrorCode::WorldInUse));
        }
        if rels.iter().any(|r| AccessList::from_file(&files::rule_rel(r)).is_some()) {
            return Err(AppError::conflict(ErrorCode::StopFirst));
        }
    }
    let admin = is_admin(st, auth.user_id).await?;
    if !admin && created.iter().any(|r| files::executable_name(r)) {
        return Err(forbidden());
    }
    Ok(admin)
}

/// Verrou des enregistrements pris, PUIS règles de [`may_modify`] vérifiées sous lui : le lancement
/// d'un serveur prend le même verrou avant de démarrer Java, donc une modification admise se
/// termine avant tout lancement (vérifiées avant le verrou, un démarrage pouvait commencer entre
/// la vérification et l'opération). Le verrou est rendu avec l'opération.
async fn modify_locked(
    st: &AppState,
    srv: &Server,
    auth: &Auth,
    rels: &[&str],
    created: &[&str],
) -> Result<(tokio::sync::MutexGuard<'static, ()>, bool), AppError> {
    let lock = crate::configs_api::SAVE_LOCK.lock().await;
    let admin = may_modify(st, srv, auth, rels, created).await?;
    Ok((lock, admin))
}

/// Texte destiné à un fichier de format connu : vrai analyseur, puis gardes des réglages
/// (clés gérées, chemins, réglages réservés aux administrateurs) par rapport à `old`.
fn check_content(rel: &str, old: &str, new: &str, admin: bool) -> Result<Vec<String>, AppError> {
    // Règles sur la forme sans casse (Windows) : `Server.Properties` est `server.properties`.
    let rel = &files::rule_rel(rel);
    let Some(format) = ConfigFormat::from_name(rel) else {
        if !line_checked(rel) {
            return Ok(Vec::new());
        }
        // Sans analyseur (`.conf`, `.ini`, `.txt`…) : règle par ligne du format texte (chaque ligne
        // qui porte un mot réservé, comme pour `.cfg`).
        return match guard(ConfigFormat::Text, rel, old, new, admin) {
            (Some(_), _) => Err(forbidden()),
            (None, sensitive) => Ok(sensitive),
        };
    };
    if crate::configs::check(format, new, &[]).error.is_some() {
        return Err(AppError::unprocessable(ErrorCode::ConfigInvalid));
    }
    match guard(format, rel, old, new, admin) {
        (Some(e), _) if e.admin_key.is_some() => Err(forbidden()),
        (Some(_), _) => Err(AppError::unprocessable(ErrorCode::ConfigInvalid)),
        (None, sensitive) => Ok(sensitive),
    }
}

/// Réglages de greffons et de mods (`plugins/`, `mods/`, `config/`) : un contenu qui n'y est pas
/// lisible comme texte (binaire, trop grand) ne peut pas être vérifié.
fn settings_area(rel: &str) -> bool {
    matches!(files::rule_rel(rel).split('/').next(), Some("plugins" | "mods" | "config"))
}

/// Fichier sans analyseur soumis à la règle par ligne : là où le jeu, les greffons et les mods
/// lisent leurs réglages (dossiers des réglages, racine du serveur) ; ailleurs (monde, journaux),
/// un texte n'est pas un réglage.
fn line_checked(rel: &str) -> bool {
    settings_area(rel) || !rel.contains('/')
}

/// Bornes de [`check_tree`] : entrées parcourues et octets lus ; au-delà, non vérifiable.
const TREE_ENTRIES_MAX: usize = 10_000;
const TREE_BYTES_MAX: u64 = 32 * 1024 * 1024;

/// Compte non administrateur : le contenu de `p` (fichier ou dossier, parcouru sans suivre de
/// lien) quitte `from` (suppression, départ d'un renommage) et arrive à `to` (renommage,
/// restauration) ; chaque fichier qui porte un réglage réservé à l'un de ces chemins (toutes ses
/// valeurs réservées changent : elles disparaissent ou apparaissent) est refusé (403), comme un
/// contenu illisible là où il devrait être vérifié, ou un dossier trop grand pour l'être (code
/// dédié : la cause est la taille, pas le contenu). Seuls les fichiers soumis à une règle (format
/// connu, ou règle par ligne) sont lus et comptés : un dossier de journaux n'a rien à vérifier.
fn check_tree(p: &std::path::Path, from: Option<&str>, to: Option<&str>) -> Result<(), AppError> {
    let too_large = || AppError::new(StatusCode::FORBIDDEN, ErrorCode::TreeTooLarge);
    let mut stack = vec![(p.to_path_buf(), String::new())];
    let (mut entries, mut bytes) = (0usize, 0u64);
    while let Some((path, sub)) = stack.pop() {
        let Ok(m) = std::fs::symlink_metadata(&path) else { continue };
        if files::is_link(&m) {
            continue;
        }
        if m.is_dir() {
            for e in std::fs::read_dir(&path).map_err(|_| AppError::internal())?.flatten() {
                entries += 1;
                if entries > TREE_ENTRIES_MAX {
                    return Err(too_large());
                }
                let name = e.file_name().to_string_lossy().into_owned();
                stack.push((e.path(), if sub.is_empty() { name } else { format!("{sub}/{name}") }));
            }
            continue;
        }
        let at = |base: &str| if sub.is_empty() { base.to_string() } else { format!("{base}/{sub}") };
        // Règle de chaque chemin (départ, arrivée) AVANT toute lecture.
        let rules: Vec<(String, ConfigFormat)> = from
            .iter()
            .chain(to.iter())
            .map(|b| files::rule_rel(&at(b)))
            .filter_map(|rel| {
                let format = ConfigFormat::from_name(&rel).or_else(|| line_checked(&rel).then_some(ConfigFormat::Text));
                format.map(|f| (rel, f))
            })
            .collect();
        if rules.is_empty() {
            continue;
        }
        let text = if m.len() <= FILE_EDIT_MAX && !rules.iter().all(|(r, _)| files::binary_name(r)) {
            bytes += m.len();
            if bytes > TREE_BYTES_MAX {
                return Err(too_large());
            }
            files::read_text_at(&path).ok().map(|(_, t)| t)
        } else {
            None
        };
        for (rel, format) in &rules {
            let flagged = match &text {
                Some(t) => !crate::configs::sensitive_present(*format, rel, t).is_empty(),
                None => known_format(rel) || settings_area(rel),
            };
            if flagged {
                return Err(forbidden());
            }
        }
    }
    Ok(())
}

/// Texte actuel d'un fichier pour comparer les réglages réservés ; absent : le texte d'un
/// fichier vide de son format (`{}` en JSON : un texte vide, illisible pour l'analyseur, ferait
/// de toute création un changement réservé).
fn current_text(root: &std::path::Path, rel: &str) -> Result<String, FsErr> {
    match files::read_text(root, rel) {
        Ok((_, t)) => Ok(t),
        Err(FsErr::NotFound) => Ok(ConfigFormat::new_file_text(rel.rsplit('/').next().unwrap_or(rel)).to_string()),
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    path: String,
}

pub async fn list(
    State(st): St,
    _auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<FileList>, AppError> {
    let srv = server(&st, &id)?;
    rel_ok(&q.path)?;
    let dir = srv.dir.clone();
    let mut l = blocking(move || {
        let worlds = files::world_dirs(&dir);
        files::list(&dir, &q.path).map(|mut l| {
            l.world = !l.path.is_empty() && files::under_any(&l.path, &worlds) && {
                let lp = l.path.to_lowercase();
                worlds.iter().any(|w| lp == w.to_lowercase() || lp.starts_with(&format!("{}/", w.to_lowercase())))
            };
            l
        })
    })
    .await?
    .map_err(fs_err)?;
    l.entries.truncate(FILE_LIST_MAX);
    Ok(Json(l))
}

pub async fn read(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<FileText>, AppError> {
    let srv = server(&st, &id)?;
    rel_ok(&q.path)?;
    let (dir, rel) = (srv.dir.clone(), q.path.clone());
    let (bytes, text) = blocking(move || files::read_text(&dir, &rel)).await?.map_err(fs_err)?;
    let sensitive = files::sensitive_name(&q.path);
    if sensitive {
        audit(&st, "file_read", &info, &auth, format!("{} {}", srv.id, q.path));
    }
    Ok(Json(FileText {
        format: ConfigFormat::from_name(&files::rule_rel(&q.path)),
        hash: crate::configs::hash(&bytes),
        path: q.path,
        text,
        sensitive,
    }))
}

pub async fn check(
    State(st): St,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FileCheckRequest>,
) -> Result<Json<ConfigCheck>, AppError> {
    let srv = server(&st, &id)?;
    rel_ok(&req.path)?;
    if req.text.len() > CONFIG_MAX_BYTES {
        return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::FileTooLarge));
    }
    let Some(format) = ConfigFormat::from_name(&files::rule_rel(&req.path)) else {
        return Ok(Json(ConfigCheck::default()));
    };
    let admin = is_admin(&st, auth.user_id).await?;
    let dir = srv.dir.clone();
    let c = run(true, move || {
        let mut c = crate::configs::check(format, &req.text, &[]);
        // Le texte n'est pas renvoyé (l'éditeur l'a déjà), ni l'arbre (pas de mode visuel ici).
        c.entries.clear();
        if c.error.is_none() {
            let old = current_text(&dir, &req.path).unwrap_or_default();
            (c.error, c.sensitive) = guard(format, &req.path, &old, &req.text, admin);
            if c.error.is_none() {
                c.unverifiable = crate::configs::unverifiable(format, &req.text);
            }
        }
        c
    })
    .await?;
    Ok(Json(c))
}

pub async fn write(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FileWriteRequest>,
) -> Result<Json<FileWritten>, AppError> {
    let srv = server(&st, &id)?;
    if req.text.len() > CONFIG_MAX_BYTES {
        return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::FileTooLarge));
    }
    let (lock, admin) = modify_locked(&st, &srv, &auth, &[&req.path], &[&req.path]).await?;
    let dir = srv.dir.clone();
    let rel = req.path.clone();
    let (res, _lock) =
        run_locked(known_format(&rel), lock, move || -> Result<(String, Vec<String>, Vec<u8>), AppError> {
            if files::binary_name(&req.path) {
                return Err(AppError::unprocessable(ErrorCode::NotText));
            }
            let old = current_text(&dir, &req.path).map_err(fs_err)?;
            let sensitive = check_content(&req.path, &old, &req.text, admin)?;
            let data = req.text.into_bytes();
            let old_bytes = files::write_text(&dir, &req.path, &data, &req.base_hash).map_err(fs_err)?;
            Ok((crate::configs::hash(&data), sensitive, old_bytes))
        })
        .await?;
    let (hash, sensitive, old_bytes) = res?;
    // Fichier des réglages : version précédente dans leur historique ; serveur en marche : le
    // jeu ne le relit qu'au démarrage (même avertissement que l'onglet « Réglages »).
    let settings_file = crate::configs::rel_allowed(srv.row().software, &files::rule_rel(&rel));
    if settings_file && !old_bytes.is_empty() {
        crate::configs_api::keep_version(&st, srv.id.get(), auth.user_id, &files::rule_rel(&rel), old_bytes).await;
    }
    let restart_needed = settings_file && srv.state() == ServerState::Running;
    let extra = if sensitive.is_empty() {
        String::new()
    } else {
        format!(" (réglages réservés : {})", sensitive.join(", "))
    };
    audit(&st, "file_written", &info, &auth, format!("{} {rel}{extra}", srv.id));
    Ok(Json(FileWritten { hash, restart_needed }))
}

pub async fn mkdir(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FilePathRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let srv = server(&st, &id)?;
    let (lock, _) = modify_locked(&st, &srv, &auth, &[&req.path], &[]).await?;
    let dir = srv.dir.clone();
    let rel = req.path.clone();
    run_locked(false, lock, move || files::mkdir(&dir, &rel)).await?.0.map_err(fs_err)?;
    audit(&st, "file_mkdir", &info, &auth, format!("{} {}", srv.id, req.path));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rename(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FileMoveRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let srv = server(&st, &id)?;
    let (lock, admin) = modify_locked(&st, &srv, &auth, &[&req.from, &req.to], &[&req.to]).await?;
    // Un programme renommé en texte, modifié, puis renommé en programme : le départ compte aussi.
    if !admin && files::executable_name(&req.from) {
        return Err(forbidden());
    }
    let dir = srv.dir.clone();
    let (from, to) = (req.from.clone(), req.to.clone());
    run_locked(known_format(&to) || !admin, lock, move || -> Result<(), AppError> {
        let src = files::resolve(&dir, &from, true).map_err(fs_err)?;
        let is_dir = std::fs::symlink_metadata(&src).is_ok_and(|m| m.is_dir());
        // Le contenu quitte `from` (comme une suppression) et arrive à `to` (comme une création) :
        // réglages réservés de l'un ou l'autre côté, administrateurs seulement.
        if !admin {
            check_tree(&src, Some(&from), Some(&to))?;
        }
        // Destination de format connu : son nouveau contenu passe les mêmes gardes qu'une écriture.
        if known_format(&to) && !is_dir {
            let (_, new) = files::read_text(&dir, &from).map_err(|e| match e {
                FsErr::TooLarge | FsErr::NotText if !admin => forbidden(),
                e => fs_err(e),
            })?;
            let old = current_text(&dir, &to).map_err(fs_err)?;
            check_content(&to, &old, &new, admin)?;
        }
        files::rename(&dir, &from, &to).map_err(fs_err)
    })
    .await?
    .0?;
    audit(&st, "file_moved", &info, &auth, format!("{} {} -> {}", srv.id, req.from, req.to));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<FileDeleteRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let srv = server(&st, &id)?;
    let (lock, admin) = modify_locked(&st, &srv, &auth, &[&req.path], &[]).await?;
    let dir = srv.dir.clone();
    let (rel, user, confirm) = (req.path.clone(), auth.username.clone(), req.confirm.clone());
    let (id_trash, _lock) = run_locked(!admin, lock, move || -> Result<String, AppError> {
        let p = files::resolve(&dir, &rel, true).map_err(fs_err)?;
        // Dossier : son nom recopié, vérifié par le serveur.
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
            let name = rel.rsplit('/').next().unwrap_or(&rel);
            if confirm != name {
                return Err(AppError::unprocessable(ErrorCode::NameMismatch));
            }
        }
        // Supprimer = écrire vide : les réglages réservés du fichier (ou du dossier) disparaissent.
        if !admin {
            check_tree(&p, Some(&rel), None)?;
        }
        // Corbeille pleine : seul un administrateur fait partir les plus anciens.
        files::trash(&dir, &rel, &user, crate::db::now(), admin).map_err(fs_err)
    })
    .await?;
    let id_trash = id_trash?;
    audit(&st, "file_trashed", &info, &auth, format!("{} {} ({id_trash})", srv.id, req.path));
    Ok(StatusCode::NO_CONTENT)
}

impl crate::api::NeedsReauth for FileEraseRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
    fn validate(&self) -> Result<(), AppError> {
        rel_ok(&self.path)
    }
}

/// Effacement définitif d'un fichier ou d'un dossier (trop grand pour la corbeille) :
/// irréversible, donc administrateurs seulement (vérifié avant la ré-authentification), puis
/// ré-authentification ; mêmes règles qu'une suppression (verrou, monde, état du serveur) ;
/// dossier : nom recopié. Audit `file_erased`.
pub async fn erase(
    State(st): St,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Result<axum::http::StatusCode, AppError> {
    use axum::extract::FromRequestParts;
    let srv = server(&st, &id)?;
    let (mut parts, body) = req.into_parts();
    let auth = Auth::from_request_parts(&mut parts, &st).await?;
    if !is_admin(&st, auth.user_id).await? {
        return Err(forbidden());
    }
    let req = axum::extract::Request::from_parts(parts, body);
    let crate::api::Reauthed { auth, info, body } =
        crate::api::reauthed_checked::<FileEraseRequest>(req, &st, |_| Ok(())).await?;
    if body.path.is_empty() {
        return Err(AppError::unprocessable(ErrorCode::InvalidPath));
    }
    let (lock, _) = modify_locked(&st, &srv, &auth, &[&body.path], &[]).await?;
    let dir = srv.dir.clone();
    let (rel, confirm) = (body.path.clone(), body.confirm.clone());
    run_locked(false, lock, move || -> Result<(), AppError> {
        let p = files::resolve(&dir, &rel, true).map_err(fs_err)?;
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) && confirm != rel.rsplit('/').next().unwrap_or(&rel)
        {
            return Err(AppError::unprocessable(ErrorCode::NameMismatch));
        }
        files::erase(&dir, &rel).map_err(fs_err)
    })
    .await?
    .0?;
    audit(&st, "file_erased", &info, &auth, format!("{} {}", srv.id, body.path));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn trash_list(State(st): St, _auth: Auth, Path(id): Path<String>) -> Result<Json<Vec<TrashItem>>, AppError> {
    let srv = server(&st, &id)?;
    let dir = srv.dir.clone();
    Ok(Json(blocking(move || files::trash_list(&dir, crate::db::now())).await?))
}

pub async fn trash_restore(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<TrashRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let srv = server(&st, &id)?;
    if busy(&srv) {
        return Err(AppError::conflict(ErrorCode::ServerBusy));
    }
    // Restauration dans le monde ou d'un programme : mêmes règles qu'une création.
    let dir = srv.dir.clone();
    let rid = req.id.clone();
    let path =
        blocking(move || files::trash_list(&dir, crate::db::now()).into_iter().find(|t| t.id == rid).map(|t| t.path))
            .await?
            .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound))?;
    let (lock, admin) = modify_locked(&st, &srv, &auth, &[&path], &[&path]).await?;
    let dir = srv.dir.clone();
    let rid = req.id.clone();
    let (restored, _lock) = run_locked(!admin, lock, move || -> Result<String, AppError> {
        // Restaurer = créer : les réglages réservés de l'élément réapparaissent.
        if !admin {
            let (item, path) = files::trash_item(&dir, &rid).map_err(fs_err)?;
            check_tree(&item, None, Some(&path))?;
        }
        files::trash_restore(&dir, &rid).map_err(fs_err)
    })
    .await?;
    let restored = restored?;
    audit(&st, "file_restored", &info, &auth, format!("{} {restored}", srv.id));
    Ok(StatusCode::NO_CONTENT)
}

impl crate::api::NeedsReauth for TrashPurgeRequest {
    fn reauth(&self) -> &Reauth {
        &self.reauth
    }
    fn validate(&self) -> Result<(), AppError> {
        if (1..=40).contains(&self.id.len()) { Ok(()) } else { Err(AppError::unprocessable(ErrorCode::InvalidValue)) }
    }
}

/// Effacement définitif d'un élément de la corbeille : irréversible, donc administrateurs
/// seulement (vérifié avant la ré-authentification : un compte ordinaire ne consomme aucun
/// code), puis ré-authentification (mot de passe, + code TOTP s'il est actif).
pub async fn trash_purge(
    State(st): St,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Result<axum::http::StatusCode, AppError> {
    use axum::extract::FromRequestParts;
    let srv = server(&st, &id)?;
    let (mut parts, body) = req.into_parts();
    let auth = Auth::from_request_parts(&mut parts, &st).await?;
    if !is_admin(&st, auth.user_id).await? {
        return Err(forbidden());
    }
    let req = axum::extract::Request::from_parts(parts, body);
    let crate::api::Reauthed { auth, info, body } =
        crate::api::reauthed_checked::<TrashPurgeRequest>(req, &st, |_| Ok(())).await?;
    let dir = srv.dir.clone();
    let rid = body.id.clone();
    // Sous le verrou des enregistrements, comme la restauration et l'entretien de la corbeille.
    let lock = crate::configs_api::SAVE_LOCK.lock().await;
    run_locked(false, lock, move || files::trash_purge(&dir, &rid)).await?.0.map_err(fs_err)?;
    audit(&st, "file_purged", &info, &auth, format!("{} {}", srv.id, body.id));
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Téléchargement (fichier, ou dossier en zip) en flux

/// Flux de morceaux reçus d'un fil bloquant.
struct ChanStream(tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>);

impl futures_core::Stream for ChanStream {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// Morceaux d'un téléchargement : 64 Kio.
const CHUNK: usize = 64 * 1024;
/// Délai au plus pour remettre un morceau au client (client lent ou figé : envoi abandonné).
const SEND_WAIT: std::time::Duration = std::time::Duration::from_secs(60);
/// Débit moyen minimal d'un transfert (envoi ou téléchargement), mesuré depuis son début après
/// un délai de grâce : un client qui ne lâche qu'un octet par minute ne garde pas sa place.
pub const MIN_RATE: u64 = 32 * 1024;
const RATE_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// Allure d'un transfert : attente permise pour le prochain morceau, bornée par `idle` et par
/// le débit minimal ([`MIN_RATE`]) ; `None` : transfert trop lent, abandonné.
#[derive(Clone, Copy)]
struct Pace(std::time::Instant);

impl Pace {
    fn start() -> Pace {
        Pace(std::time::Instant::now())
    }
    fn wait(&self, done: u64, idle: std::time::Duration) -> Option<std::time::Duration> {
        Self::wait_at(self.0.elapsed(), done, idle)
    }
    /// `done` octets passés en `elapsed` : le débit moyen doit rester au-dessus du minimum.
    fn wait_at(elapsed: std::time::Duration, done: u64, idle: std::time::Duration) -> Option<std::time::Duration> {
        let deadline = RATE_GRACE.max(std::time::Duration::from_secs(done / MIN_RATE));
        deadline.checked_sub(elapsed).filter(|d| !d.is_zero()).map(|d| d.min(idle))
    }
}

/// Places de transferts simultanés : en tout, et par compte (plusieurs sessions d'un même compte
/// partagent ses places) ; au-delà, 503.
pub struct Slots {
    all: tokio::sync::Semaphore,
    per_user: usize,
    by_user: std::sync::Mutex<std::collections::BTreeMap<i64, usize>>,
}

impl Slots {
    const fn new(all: usize, per_user: usize) -> Slots {
        Slots {
            all: tokio::sync::Semaphore::const_new(all),
            per_user,
            by_user: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }
}

pub const DOWNLOADS_MAX: usize = 8;
pub const DOWNLOADS_PER_USER: usize = 2;
static DOWNLOADS: Slots = Slots::new(DOWNLOADS_MAX, DOWNLOADS_PER_USER);
/// Envois simultanés : chacun écrit jusqu'à `upload_max_mb` sur le disque.
pub const UPLOADS_MAX: usize = 4;
pub const UPLOADS_PER_USER: usize = 2;
static UPLOADS: Slots = Slots::new(UPLOADS_MAX, UPLOADS_PER_USER);

/// Place d'un transfert, tenue jusqu'à sa fin (rendue même si le client part).
struct Ticket {
    _permit: tokio::sync::SemaphorePermit<'static>,
    slots: &'static Slots,
    user: i64,
}

impl Ticket {
    fn take(slots: &'static Slots, user: i64) -> Result<Ticket, AppError> {
        let permit = slots.all.try_acquire().map_err(|_| AppError::busy())?;
        let mut m = slots.by_user.lock().unwrap_or_else(|p| p.into_inner());
        let n = m.entry(user).or_insert(0);
        if *n >= slots.per_user {
            return Err(AppError::busy());
        }
        *n += 1;
        Ok(Ticket { _permit: permit, slots, user })
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut m = self.slots.by_user.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.user);
            }
        }
    }
}

type Chunks = tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>;

/// Fichier simple lu en asynchrone, `len` octets au plus (la taille annoncée : un fichier qui
/// grandit pendant l'envoi ne déborde pas de `Content-Length`). Abandon si le client ne reçoit
/// plus rien pendant `wait`, ou si son débit moyen tombe sous [`MIN_RATE`].
async fn send_file(f: tokio::fs::File, len: u64, tx: Chunks, wait: std::time::Duration) {
    use tokio::io::AsyncReadExt;
    let mut f = f.take(len);
    let mut buf = vec![0u8; CHUNK];
    let pace = Pace::start();
    let mut sent = 0u64;
    loop {
        let item = match f.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => Ok(Bytes::copy_from_slice(&buf[..n])),
            Err(e) => Err(e),
        };
        let failed = item.is_err();
        sent += item.as_ref().map_or(0, |b| b.len() as u64);
        let Some(wait) = pace.wait(sent, wait) else { break };
        if !matches!(tokio::time::timeout(wait, tx.send(item)).await, Ok(Ok(()))) || failed {
            break;
        }
    }
}

/// Écrivain (fil bloquant du zip) qui envoie des morceaux de 64 Kio au flux ; erreur si le client
/// est parti, ne reçoit plus rien pendant `wait`, ou si son débit moyen tombe sous [`MIN_RATE`].
struct ChanWriter {
    tx: Chunks,
    buf: Vec<u8>,
    rt: tokio::runtime::Handle,
    wait: std::time::Duration,
    pace: Pace,
    sent: u64,
}

impl ChanWriter {
    fn new(tx: Chunks, rt: tokio::runtime::Handle, wait: std::time::Duration) -> ChanWriter {
        ChanWriter { tx, buf: Vec::with_capacity(CHUNK), rt, wait, pace: Pace::start(), sent: 0 }
    }

    fn push(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let b = Bytes::from(std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK)));
        self.sent += b.len() as u64;
        let slow = || std::io::Error::new(std::io::ErrorKind::TimedOut, "client trop lent");
        let wait = self.pace.wait(self.sent, self.wait).ok_or_else(slow)?;
        match self.rt.block_on(tokio::time::timeout(wait, self.tx.send(Ok(b)))) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(std::io::Error::other("client parti")),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "client trop lent")),
        }
    }
}

impl std::io::Write for ChanWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.push()?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.push()
    }
}

/// `Content-Disposition` d'un nom quelconque (RFC 6266 : `filename*` encodé, repli ASCII).
fn disposition(name: &str) -> HeaderValue {
    let ascii: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    let enc: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"._-".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }
        })
        .collect();
    HeaderValue::from_str(&format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{enc}"))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

pub async fn download(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Response, AppError> {
    let srv = server(&st, &id)?;
    rel_ok(&q.path)?;
    // Place prise avant tout travail : au-delà, 503 (rendue à la fin de l'envoi).
    let ticket = Ticket::take(&DOWNLOADS, auth.user_id)?;
    let dir = srv.dir.clone();
    let rel = q.path.clone();
    // Ouverture (et nature) vérifiées avant de répondre : les erreurs restent des codes HTTP.
    let opened = blocking(move || -> Result<Option<(std::fs::File, u64)>, FsErr> {
        let p = files::resolve(&dir, &rel, true)?;
        if std::fs::symlink_metadata(&p)?.is_dir() {
            return Ok(None);
        }
        let f = files::open_file(&p)?;
        let len = f.metadata()?.len();
        Ok(Some((f, len)))
    })
    .await?
    .map_err(fs_err)?;
    let name = if q.path.is_empty() {
        format!("serveur-{}", srv.id)
    } else {
        q.path.rsplit('/').next().unwrap_or("").to_string()
    };
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut res = Response::new(Body::from_stream(ChanStream(rx)));
    let h = res.headers_mut();
    match opened {
        Some((f, len)) => {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            h.insert(header::CONTENT_DISPOSITION, disposition(&name));
            // Lecture asynchrone : aucun fil bloquant tenu par un client lent.
            tokio::spawn(async move {
                let _ticket = ticket;
                send_file(tokio::fs::File::from_std(f), len, tx, SEND_WAIT).await;
            });
        }
        None => {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
            h.insert(header::CONTENT_DISPOSITION, disposition(&format!("{name}.zip")));
            let (dir, rel) = (srv.dir.clone(), q.path.clone());
            let rt = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                let _ticket = ticket;
                let mut w = ChanWriter::new(tx.clone(), rt.clone(), SEND_WAIT);
                if files::zip_dir(&dir, &rel, &mut w).is_err() || std::io::Write::flush(&mut w).is_err() {
                    let err = Err(std::io::Error::other("zip interrompu"));
                    let _ = rt.block_on(tokio::time::timeout(SEND_WAIT, tx.send(err)));
                }
            });
        }
    }
    let what = if q.path.is_empty() { "/".to_string() } else { q.path.clone() };
    audit(&st, "file_downloaded", &info, &auth, format!("{} {what}", srv.id));
    Ok(res.into_response())
}

// ---------------------------------------------------------------------------------------------
// Envoi en flux

#[derive(Deserialize)]
pub struct UploadQuery {
    /// Dossier de destination.
    #[serde(default)]
    path: String,
    name: String,
    #[serde(default)]
    overwrite: bool,
}

/// Temporaire d'un envoi, effacé quoi qu'il arrive (fin, erreur, client parti).
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Délai sans rien recevoir avant d'abandonner un envoi.
const UPLOAD_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

pub async fn upload(
    State(st): St,
    Extension(info): Extension<ClientInfo>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Result<Json<FileWritten>, AppError> {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let srv = server(&st, &id)?;
    if !files::segment_ok(&q.name) {
        return Err(AppError::unprocessable(ErrorCode::InvalidPath));
    }
    let rel = if q.path.is_empty() { q.name.clone() } else { format!("{}/{}", q.path, q.name) };
    may_modify(&st, &srv, &auth, &[&rel], &[&rel]).await?;
    // Place prise avant tout travail : au-delà, 503 (rendue à la fin de l'envoi).
    let _ticket = Ticket::take(&UPLOADS, auth.user_id)?;
    let max = st.config.upload_max_mb * 1024 * 1024;
    let too_large = || AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::FileTooLarge);
    let disk_full = || AppError::new(StatusCode::INSUFFICIENT_STORAGE, ErrorCode::DiskFull);
    // Taille annoncée : refusée tout de suite si elle dépasse la borne ou la place libre (une
    // réserve reste libre) ; vérifiée ensuite au fil de l'eau.
    let announced: u64 =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(0);
    if announced > max {
        return Err(too_large());
    }
    let room = |need: u64| {
        let dir = srv.dir.clone();
        async move { blocking(move || crate::fsutil::room_for(&dir, need)).await }
    };
    if !room(announced).await? {
        return Err(disk_full());
    }
    // Temporaire dans le dossier interne du serveur (même volume : renommage final atomique).
    let root = srv.dir.clone();
    let tmp_dir = blocking(move || files::internal_dir(&root, "tmp", true)).await?.map_err(|_| AppError::internal())?;
    let tmp = TempFile(tmp_dir.join(format!(
        "upload-{}.part",
        crate::crypto::base32(&crate::crypto::random_bytes::<8>()).to_ascii_lowercase()
    )));
    let mut f = tokio::fs::File::create(&tmp.0).await.map_err(|_| AppError::internal())?;
    let mut written: u64 = 0;
    // Empreinte calculée au fil de l'eau : rien n'est relu sous le verrou.
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut body = body;
    // Débit moyen minimal : un envoi au compte-gouttes ne garde pas sa place indéfiniment.
    let pace = Pace::start();
    loop {
        let wait = pace.wait(written, UPLOAD_IDLE).ok_or_else(AppError::timeout)?;
        let frame = match tokio::time::timeout(wait, body.frame()).await {
            Err(_) => return Err(AppError::timeout()),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(AppError::bad_request()),
            Ok(Some(Ok(fr))) => fr,
        };
        let Ok(data) = frame.into_data() else { continue };
        let before = written;
        written += data.len() as u64;
        if written > max {
            return Err(too_large());
        }
        // Place libre revérifiée tous les 64 Mio reçus.
        if written >> 26 != before >> 26 && !room(0).await? {
            return Err(disk_full());
        }
        digest.update(&data);
        f.write_all(&data).await.map_err(|_| AppError::internal())?;
    }
    let hash: String = digest.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
    f.sync_all().await.map_err(|_| AppError::internal())?;
    drop(f);
    // Revérifié sous le verrou juste avant de poser le fichier (l'envoi a pu durer) : état du
    // serveur compris.
    let (lock, admin) = modify_locked(&st, &srv, &auth, &[&rel], &[&rel]).await?;
    let dir = srv.dir.clone();
    let (rel2, overwrite, user) = (rel.clone(), q.overwrite, auth.username.clone());
    let settings_file = crate::configs::rel_allowed(srv.row().software, &files::rule_rel(&rel));
    let (old_bytes, _lock) = run_locked(known_format(&rel2), lock, move || -> Result<Vec<u8>, AppError> {
        let tmp = tmp;
        let dst = files::resolve(&dir, &rel2, false).map_err(fs_err)?;
        let exists = match std::fs::symlink_metadata(&dst) {
            Ok(m) if m.is_dir() => return Err(fs_err(FsErr::WrongKind)),
            Ok(_) if !overwrite => return Err(fs_err(FsErr::Exists)),
            Ok(_) => true,
            Err(_) => false,
        };
        let data_len = written;
        // Format connu : mêmes gardes qu'une écriture depuis l'éditeur.
        if ConfigFormat::from_name(&files::rule_rel(&rel2)).is_some() {
            if data_len > CONFIG_MAX_BYTES as u64 {
                return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::FileTooLarge));
            }
            let new = String::from_utf8(std::fs::read(&tmp.0).map_err(|_| AppError::internal())?)
                .map_err(|_| AppError::unprocessable(ErrorCode::ConfigInvalid))?;
            let old = current_text(&dir, &rel2).map_err(fs_err)?;
            check_content(&rel2, &old, &new, admin)?;
        } else if !admin && line_checked(&rel2) {
            // Sans analyseur : règle par ligne si les deux côtés se lisent comme du texte ; sinon,
            // dans les dossiers des réglages, rien n'est vérifiable (administrateurs seulement).
            let new = (data_len <= FILE_EDIT_MAX).then(|| files::read_text_at(&tmp.0).ok()).flatten();
            let old = current_text(&dir, &rel2).ok();
            match (old, new) {
                (Some(old), Some((_, new))) => {
                    check_content(&rel2, &old, &new, admin)?;
                }
                _ if settings_area(&rel2) => return Err(forbidden()),
                _ => {}
            }
        }
        // Écrasement : l'ancien fichier part à la corbeille (récupérable comme une suppression),
        // et un fichier de réglages garde aussi sa version dans leur historique.
        let old_bytes = if exists && settings_file {
            current_text(&dir, &rel2).map(String::into_bytes).unwrap_or_default()
        } else {
            Vec::new()
        };
        let trashed = if exists {
            Some(files::trash(&dir, &rel2, &user, crate::db::now(), admin).map_err(fs_err)?)
        } else {
            None
        };
        // Jamais de remplacement, même d'un fichier apparu entre-temps ; raté : l'ancien revient.
        if let Err(e) = files::move_no_replace(&tmp.0, &dst) {
            if let Some(id) = trashed {
                let _ = files::trash_restore(&dir, &id);
            }
            return Err(fs_err(e));
        }
        crate::fsutil::sync_dir(dst.parent().unwrap_or(&dir));
        files::resolve(&dir, &rel2, true).map_err(fs_err)?;
        Ok(old_bytes)
    })
    .await?;
    let old_bytes = old_bytes?;
    if !old_bytes.is_empty() {
        crate::configs_api::keep_version(&st, srv.id.get(), auth.user_id, &files::rule_rel(&rel), old_bytes).await;
    }
    audit(&st, "file_uploaded", &info, &auth, format!("{} {rel} ({written} o)", srv.id));
    let restart_needed = settings_file && srv.state() == ServerState::Running;
    Ok(Json(FileWritten { hash, restart_needed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Analyse d'un fichier de format connu (vérification, écriture, renommage, envoi) : elle
    /// attend une place d'analyse comme l'onglet « Réglages » ; le reste n'en prend pas.
    #[tokio::test]
    async fn analyses_bornees_dans_le_gestionnaire() {
        use crate::configs_api::{PARSE, PARSE_SLOTS, PARSE_TEST_LOCK};
        let _t = PARSE_TEST_LOCK.lock().await;
        let short = std::time::Duration::from_millis(200);
        let held: Vec<_> = (0..PARSE_SLOTS).map(|_| PARSE.try_acquire().expect("place libre")).collect();
        assert!(tokio::time::timeout(short, run(true, || 1)).await.is_err(), "attend une place");
        assert_eq!(tokio::time::timeout(short, run(false, || 2)).await.unwrap().unwrap(), 2);
        assert!(known_format("Spigot.YML") && known_format("config/a.json5") && !known_format("a.txt"));
        drop(held);
        assert_eq!(run(true, || 3).await.unwrap(), 3);
    }

    /// Téléchargements et envois bornés : par compte (toutes ses sessions), en tout ; place rendue
    /// à la fin ; débit moyen minimal après le délai de grâce.
    #[test]
    fn transferts_bornes() {
        for (slots, max, per) in
            [(&DOWNLOADS, DOWNLOADS_MAX, DOWNLOADS_PER_USER), (&UPLOADS, UPLOADS_MAX, UPLOADS_PER_USER)]
        {
            let (a, b) = (1i64, 2i64);
            let mut held: Vec<_> = (0..per).map(|_| Ticket::take(slots, a).unwrap()).collect();
            assert_eq!(Ticket::take(slots, a).err().map(|e| e.code), Some(ErrorCode::Busy), "par compte");
            let others: Vec<_> = (0..max - per).map(|i| Ticket::take(slots, 10 + i as i64).unwrap()).collect();
            assert_eq!(Ticket::take(slots, b).err().map(|e| e.code), Some(ErrorCode::Busy), "en tout");
            drop(others);
            held.pop();
            assert!(Ticket::take(slots, a).is_ok(), "place rendue");
            drop(held);
            assert!(slots.by_user.lock().unwrap().is_empty());
        }
        let s = std::time::Duration::from_secs;
        let idle = s(60);
        assert_eq!(Pace::wait_at(s(0), 0, idle), Some(s(60)), "grâce au début");
        assert_eq!(Pace::wait_at(s(59), 2, idle), Some(s(1)), "un octet par minute : plus qu'une seconde");
        assert_eq!(Pace::wait_at(s(61), 2, idle), None, "trop lent : abandon");
        assert_eq!(Pace::wait_at(s(600), 600 * MIN_RATE, idle), None);
        assert_eq!(Pace::wait_at(s(600), 700 * MIN_RATE, idle), Some(idle), "au-dessus du minimum");
    }

    /// Fichier qui grandit pendant l'envoi : la taille annoncée seulement (`Content-Length`).
    /// Client qui ne lit plus : l'envoi s'arrête au bout du délai (fichier comme zip).
    #[tokio::test]
    async fn envoi_borne() {
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("rcm-envoi-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("a.log");
        std::fs::write(&p, b"0123456789").unwrap();
        let f = tokio::fs::File::open(&p).await.unwrap();
        std::fs::write(&p, b"0123456789ABCDEF").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        send_file(f, 10, tx, std::time::Duration::from_secs(5)).await;
        let mut got = Vec::new();
        while let Some(Ok(b)) = rx.recv().await {
            got.extend_from_slice(&b);
        }
        assert_eq!(got, b"0123456789");
        // Client figé : canal plein, jamais lu.
        std::fs::write(&p, vec![7u8; 4 * CHUNK]).unwrap();
        let f = tokio::fs::File::open(&p).await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let wait = std::time::Duration::from_millis(100);
        let done = tokio::time::timeout(std::time::Duration::from_secs(5), send_file(f, 4 * CHUNK as u64, tx, wait));
        assert!(done.await.is_ok(), "fichier : abandon au bout du délai");
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let rt = tokio::runtime::Handle::current();
        let res = tokio::task::spawn_blocking(move || {
            let mut w = ChanWriter::new(tx, rt, wait);
            for _ in 0..4 {
                std::io::Write::write_all(&mut w, &vec![0u8; CHUNK])?;
            }
            Ok::<(), std::io::Error>(())
        });
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), res).await.expect("zip : abandon").unwrap();
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Règles vérifiées SOUS le verrou des enregistrements (celui que prend le lancement) : un
    /// démarrage commencé pendant l'attente du verrou est vu, la modification est refusée.
    #[tokio::test]
    async fn regles_sous_le_verrou() {
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("rcm-verrou-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let db = crate::db::Db::open_memory().unwrap();
        let enc = db.keys().encrypt(&crate::crypto::aad("servers", "rcon_password", 1), b"x");
        db.with(|c| {
            c.execute(
                "INSERT INTO users (id, username, password_hash, is_admin, created_at) VALUES (1, 'admin', 'x', 1, 0)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO servers (id, name, software, game_version, memory_mb, port, rcon_port, rcon_password_enc,
                  java_major, created_at) VALUES (1, 'Survie', 'paper', '26.3', 1024, 25565, 25575, ?1, 25, 0)",
                [enc],
            )
            .unwrap();
        });
        let (st, _) = crate::new_state(crate::config::Config::with_data_dir(d.clone()), db);
        let srv = server(&st, "1").unwrap();
        let auth = Auth { user_id: 1, username: "admin".into(), token_hash: [0; 32], csrf: String::new() };
        let held = crate::configs_api::SAVE_LOCK.lock().await;
        let task = {
            let (st, srv) = (st.clone(), srv.clone());
            tokio::spawn(async move { modify_locked(&st, &srv, &auth, &["notes.txt"], &[]).await.map(|(_, a)| a) })
        };
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let op = st.servers.begin(&srv, OpKind::Start).unwrap();
        drop(held);
        let res = task.await.unwrap();
        assert_eq!(res.err().map(|e| e.code), Some(ErrorCode::ServerBusy));
        drop(op);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Fichiers sans analyseur : règle par ligne dans les dossiers des réglages et à la racine ;
    /// rien d'autre (monde, journaux) n'est un réglage.
    #[test]
    fn texte_sans_analyseur_par_ligne() {
        let forbidden = |r: Result<Vec<String>, AppError>| assert_eq!(r.unwrap_err().code, ErrorCode::Forbidden);
        let conf = "plugins/dynmap/configuration.conf";
        forbidden(check_content(conf, "zoom = 3\n", "zoom = 3\nwebserver-port = 8124\n", false));
        forbidden(check_content("mods/carte.ini", "", "bind-address=0.0.0.0\n", false));
        forbidden(check_content("Config/Bot.TXT", "token=a\n", "token=b\n", false));
        forbidden(check_content("relais.conf", "", "proxy = 1.2.3.4\n", false));
        assert_eq!(check_content(conf, "", "webserver-port = 8124\n", true).unwrap(), ["webserver-port = 8124"]);
        assert!(check_content(conf, "zoom = 3\n", "zoom = 4\n", false).is_ok());
        assert!(check_content("logs/notes.txt", "", "command port token\n", false).is_ok());
    }

    /// Supprimer, déplacer, restaurer : le contenu qui part ou arrive compte comme une écriture
    /// (réglages réservés présents = administrateurs seulement), dossiers compris ; ce qui n'est
    /// pas lisible comme texte dans les dossiers des réglages n'est pas vérifiable.
    #[test]
    fn depart_et_arrivee_des_reglages() {
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("rcm-depart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let w = |rel: &str, data: &[u8]| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
        };
        w("server.properties", b"online-mode=true\nmotd=a\n");
        w("config/paper-global.yml", b"proxies:\n  velocity:\n    secret: abc\n");
        w("plugins/x/donnees.db", b"\0\x01");
        w("plugins/y/config.yml", b"zoom: 3\n");
        w("logs/latest.log", b"Alex issued server command: /op Bob\n");
        w("world/stats/u.json", b"{\"stats\":{}}");
        w("copie.txt", b"online-mode=false\n");
        let f = |e: Result<(), AppError>| assert_eq!(e.unwrap_err().code, ErrorCode::Forbidden);
        let p = |rel: &str| d.join(rel);
        f(check_tree(&p("server.properties"), Some("server.properties"), None));
        f(check_tree(&p("config"), Some("config"), None));
        f(check_tree(&p("plugins/x"), Some("plugins/x"), None));
        f(check_tree(&p("copie.txt"), None, Some("server.properties")));
        w("sauvegarde/donnees.bin", b"\0\x02");
        f(check_tree(&p("sauvegarde"), Some("sauvegarde"), Some("plugins/s")));
        assert!(check_tree(&p("sauvegarde"), Some("sauvegarde"), Some("vieux")).is_ok());
        assert!(check_tree(&p("plugins/y"), Some("plugins/y"), Some("plugins/z")).is_ok());
        assert!(check_tree(&p("logs"), Some("logs"), None).is_ok());
        assert!(check_tree(&p("world"), Some("world"), Some("monde")).is_ok());
        assert!(check_tree(&p("copie.txt"), Some("copie.txt"), Some("notes/copie.txt")).is_ok());
        // Journaux : aucune règle, rien n'est lu ni compté (33 Mio de texte, au-delà du budget).
        let mio = vec![b'a'; 1024 * 1024];
        for i in 0..33 {
            w(&format!("logs/vieux-{i}.log"), &mio);
        }
        assert!(check_tree(&p("logs"), Some("logs"), None).is_ok());
        // Dossier trop grand pour être vérifié : code dédié, pas « réservé aux administrateurs ».
        // Sans `latest.log` (ligne réservée) : l'ordre de `read_dir` dépend du système de fichiers,
        // et ce fichier lu avant le dépassement du budget donnerait l'autre refus.
        std::fs::remove_file(p("logs/latest.log")).unwrap();
        let e = check_tree(&p("logs"), Some("logs"), Some("plugins/journaux")).unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, ErrorCode::TreeTooLarge));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Gestionnaire de fichiers : la casse demandée ne contourne ni les gardes des réglages
    /// (format reconnu, clés réservées, chemins), ni les listes d'accès.
    #[test]
    fn casse_dans_le_gestionnaire() {
        let e = check_content("Server.Properties", "online-mode=true\n", "online-mode=false\n", false).unwrap_err();
        assert_eq!(e.code, ErrorCode::Forbidden);
        let e = check_content("SPIGOT.YML", "a: 1\n", "settings:\n  restart-script: ../x.sh\n", true).unwrap_err();
        assert_eq!(e.code, ErrorCode::ConfigInvalid);
        assert!(check_content("Server.Properties", "motd=a\n", "motd=b\n", false).is_ok());
    }

    /// « Nouveau fichier » : le texte de départ passe l'analyseur de chaque format (un fichier
    /// `.json` vide serait refusé et jamais créé), y compris pour un compte ordinaire (fichier
    /// absent : aucun réglage réservé avant).
    #[test]
    fn nouveau_fichier_valide() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("rcm-nouveau-absent");
        for name in [
            "plugins/MonPlugin/config.json",
            "config/a.JSON5",
            "whitelist.json",
            "plugins/x/c.yml",
            "config/c.toml",
            "a.properties",
            "plugins/x/c.cfg",
            "notes.txt",
        ] {
            let text = ConfigFormat::new_file_text(name.rsplit('/').next().unwrap());
            let old = current_text(&root, name).unwrap();
            let r = check_content(name, &old, text, false);
            assert!(r.is_ok(), "{name} : {text:?} {:?}", r.err().map(|e| e.code));
        }
    }
}
