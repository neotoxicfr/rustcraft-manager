//! Base SQLite : ouverture, migrations numérotées (`PRAGMA user_version`), accès asynchrone.
//!
//! Une seule connexion derrière un verrou, utilisée depuis le réservoir de fils bloquants de
//! tokio : les requêtes du gestionnaire durent des microsecondes et viennent de quelques
//! utilisateurs, un réservoir de connexions n'apporterait rien (mesuré sous 50 connexions, voir
//! `docs/perf.md`). Le hachage des mots de passe se fait HORS du verrou.
//!
//! Toute transaction d'écriture s'ouvre par [`write_tx`] (`BEGIN IMMEDIATE`) : une transaction
//! différée qui lit puis écrit peut échouer en `SQLITE_BUSY_SNAPSHOT` sans que `busy_timeout`
//! n'attende.

use crate::crypto::{Keys, aad};
use crate::error::AppError;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Une étape de migration : du SQL, ou du code (migration de données qui a besoin des clés).
enum Step {
    Sql(&'static str),
    Code(fn(&Transaction, &Keys) -> rusqlite::Result<()>),
}

/// Migrations dans l'ordre ; la n-ième amène la base à la version n. Ne jamais modifier une
/// migration publiée : en ajouter une.
const MIGRATIONS: &[Step] = &[
    // 1 : comptes, codes de secours, sessions, journal d'audit, réglages.
    Step::Sql(
        "CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        totp_secret BLOB,
        totp_pending BLOB,
        totp_last_step INTEGER,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE recovery_codes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash BLOB NOT NULL,
        used_at INTEGER
    );
    CREATE INDEX recovery_codes_user ON recovery_codes(user_id);
    CREATE TABLE sessions (
        token_hash BLOB PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf TEXT NOT NULL,
        pending_totp INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        ip TEXT
    ) WITHOUT ROWID;
    CREATE INDEX sessions_user ON sessions(user_id);
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        detail TEXT,
        ip TEXT
    );
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;",
    ),
    // 2 : secrets TOTP chiffrés (`v1:` AES-256-GCM), schéma des codes de secours (0 = SHA-256
    // historique, 1 = HMAC à clé dérivée), essais TOTP par session provisoire, échecs agrégés
    // de l'audit (compte), index de rétention.
    Step::Sql(
        "ALTER TABLE users ADD COLUMN totp_secret_enc TEXT;
    ALTER TABLE users ADD COLUMN totp_pending_enc TEXT;
    ALTER TABLE recovery_codes ADD COLUMN scheme INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sessions ADD COLUMN totp_failures INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE audit_log ADD COLUMN count INTEGER NOT NULL DEFAULT 1;
    CREATE INDEX audit_log_ts ON audit_log(ts);
    CREATE INDEX sessions_expires ON sessions(expires_at);",
    ),
    // 3 : chiffrement des secrets TOTP existants (en clair dans la version 1).
    Step::Code(encrypt_plain_totp),
    // 4 : colonnes en clair retirées.
    Step::Sql(
        "ALTER TABLE users DROP COLUMN totp_secret;
    ALTER TABLE users DROP COLUMN totp_pending;",
    ),
    // 5 : User-Agent dans l'audit (chiffré) ; adresse des sessions retirée (jamais relue : rien à
    // garder en base).
    Step::Sql(
        "ALTER TABLE audit_log ADD COLUMN user_agent TEXT;
    ALTER TABLE sessions DROP COLUMN ip;",
    ),
    // 6 : adresses de l'audit chiffrées (en clair jusqu'à la version 5).
    Step::Code(encrypt_plain_audit),
    // 7 : passkeys (clés publiques, compteur, transports, nom, dates) ; identifiant WebAuthn du
    // compte (16 octets aléatoires, jamais l'id SQL).
    Step::Sql(
        "ALTER TABLE users ADD COLUMN webauthn_id BLOB;
    CREATE UNIQUE INDEX users_webauthn_id ON users(webauthn_id);
    CREATE TABLE passkeys (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        cred_id BLOB NOT NULL UNIQUE,
        name TEXT NOT NULL,
        data TEXT NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        transports TEXT,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
    );
    CREATE INDEX passkeys_user ON passkeys(user_id);",
    ),
    // 8 : ordre de création des sessions (plafond par compte : les plus anciennes partent).
    Step::Sql("ALTER TABLE sessions ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;"),
    // 9 (phase 2) : serveurs pilotés (mot de passe RCON chiffré, état voulu, EULA acceptée par
    // qui et quand), commandes favorites par compte et serveur, thème par compte.
    Step::Sql(
        "CREATE TABLE servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        software TEXT NOT NULL,
        game_version TEXT NOT NULL,
        build TEXT,
        memory_mb INTEGER NOT NULL,
        port INTEGER NOT NULL,
        rcon_port INTEGER NOT NULL,
        rcon_password_enc TEXT NOT NULL,
        java_major INTEGER NOT NULL DEFAULT 0,
        java_path TEXT,
        launch TEXT,
        auto_restart INTEGER NOT NULL DEFAULT 0,
        desired_running INTEGER NOT NULL DEFAULT 0,
        eula_accepted_at INTEGER,
        eula_accepted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at INTEGER NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE server_favorites (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        label TEXT NOT NULL,
        command TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX server_favorites_user ON server_favorites(user_id, server_id);
    ALTER TABLE users ADD COLUMN theme TEXT;",
    ),
    // 10 (phase 3) : historique des fichiers de configuration (état du disque avant chaque
    // écriture par le gestionnaire), contenu chiffré (il peut porter des secrets).
    Step::Sql(
        "CREATE TABLE server_config_history (
        id INTEGER PRIMARY KEY,
        server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        ts INTEGER NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        size INTEGER NOT NULL,
        content_enc TEXT NOT NULL
    );
    CREATE INDEX server_config_history_file ON server_config_history(server_id, path, id);",
    ),
    // 11 : nom public et mode d'accès de chaque serveur (enregistrement direct ou aiguilleur).
    Step::Sql(
        "CREATE TABLE server_addresses (
        server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        hostname TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );",
    ),
];

fn encrypt_plain_audit(tx: &Transaction, keys: &Keys) -> rusqlite::Result<()> {
    let rows: Vec<(i64, String)> = {
        let mut s = tx.prepare("SELECT id, ip FROM audit_log WHERE ip IS NOT NULL")?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
    };
    let mut up = tx.prepare("UPDATE audit_log SET ip = ?1 WHERE id = ?2")?;
    for (id, ip) in rows {
        up.execute(rusqlite::params![crate::audit::seal(keys, "ip", id, &ip), id])?;
    }
    Ok(())
}

fn encrypt_plain_totp(tx: &Transaction, keys: &Keys) -> rusqlite::Result<()> {
    type Row = (i64, Option<Vec<u8>>, Option<Vec<u8>>);
    let rows: Vec<Row> = {
        let mut s = tx.prepare(
            "SELECT id, totp_secret, totp_pending FROM users WHERE totp_secret IS NOT NULL OR totp_pending IS NOT NULL",
        )?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?
    };
    for (id, secret, pending) in rows {
        let enc = |col: &str, v: Option<Vec<u8>>| v.map(|v| keys.encrypt(&aad("users", col, id), &v));
        tx.execute(
            "UPDATE users SET totp_secret_enc = ?1, totp_pending_enc = ?2, totp_secret = NULL, totp_pending = NULL WHERE id = ?3",
            rusqlite::params![enc("totp_secret", secret), enc("totp_pending", pending), id],
        )?;
    }
    Ok(())
}

/// Version de schéma attendue par ce binaire.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// Valeur témoin chiffrée à l'ouverture : une autre clé que celle de la base est refusée au
/// démarrage plutôt qu'à la première connexion TOTP.
const KEY_CHECK: &str = "key_check";
const KEY_CHECK_PLAIN: &[u8] = b"rustcraft-manager key check v1";

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    keys: Arc<Keys>,
}

impl Db {
    /// Ouvre (ou crée en 0600 sous Unix) la base, sauvegarde avant migration, migre, vérifie la
    /// clé.
    pub fn open(path: &Path, keys: Keys) -> Result<Db, String> {
        let err = |e: rusqlite::Error| format!("base {} : {e}", path.display());
        if !path.exists() {
            crate::datadir::create_private(path, b"").map_err(|e| format!("base {} : {e}", path.display()))?;
        }
        let conn = Connection::open(path).map_err(err)?;
        let current: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(err)?;
        let migrating = current > 0 && current < SCHEMA_VERSION;
        let backup = if migrating { Some(backup_before_migration(&conn, path, current)?) } else { None };
        let db = Self::init(conn, keys).map_err(|e| format!("base {} : {e}", path.display()))?;
        if migrating {
            // Les migrations de données ont remplacé des valeurs en clair (secrets TOTP, adresses)
            // et retiré des colonnes : `secure_delete` efface les pages libérées, VACUUM réécrit
            // la base, le checkpoint vide le journal WAL ; la copie d'avant migration (en clair)
            // est supprimée une fois la migration réussie et la clé vérifiée (revue I-A). En cas
            // d'échec, elle reste pour la restauration.
            db.with(|c| c.execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")).map_err(err)?;
            if let Some(bak) = backup {
                std::fs::remove_file(&bak).map_err(|e| format!("{} : suppression impossible ({e})", bak.display()))?;
                tracing::info!("migration réussie : copie d'avant migration supprimée ({})", bak.display());
            }
        }
        // Droits posés à chaque ouverture (une base créée par une ancienne version reste sinon
        // lisible par tous) ; SQLite crée les fichiers -wal et -shm avec les droits de la base.
        for suffix in ["", "-wal", "-shm"] {
            let p = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            if p.exists() {
                crate::datadir::restrict_file(&p)
                    .map_err(|e| format!("{} : droits 0600 impossibles ({e})", p.display()))?;
            }
        }
        Ok(db)
    }

    /// Base en mémoire avec des clés jetables (tests).
    pub fn open_memory() -> rusqlite::Result<Db> {
        Self::init(Connection::open_in_memory()?, Keys::ephemeral()).map_err(rusqlite::Error::InvalidParameterName)
    }

    fn init(mut conn: Connection, keys: Keys) -> Result<Db, String> {
        // WAL : lectures pendant une écriture, une écriture = un ajout séquentiel ; `NORMAL` suffit
        // en WAL (pas de corruption possible, au pire la dernière transaction perdue sur coupure).
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(|e| e.to_string())?;
        migrate(&mut conn, &keys).map_err(|e| e.to_string())?;
        check_key(&mut conn, &keys)?;
        Ok(Db { conn: Arc::new(Mutex::new(conn)), keys: Arc::new(keys) })
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Exécute `f` sur la connexion, dans un fil bloquant.
    pub async fn call<R, F>(&self, f: F) -> Result<R, AppError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Connection, &Keys) -> Result<R, AppError> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = db.conn.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut conn, &db.keys)
        })
        .await
        .map_err(|_| AppError::internal())?
    }

    /// Accès direct, hors moteur asynchrone (démarrage, tests).
    pub fn with<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> R {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut conn)
    }
}

/// La base contient-elle déjà des données chiffrées (témoin de clé posé) ? Lecture seule, sans
/// migrer : décide si une clé manquante peut être créée.
pub fn has_encrypted_data(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(c) = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return true; // illisible : prudence, ne pas créer de nouvelle clé
    };
    let has_table: bool = c
        .query_row("SELECT count(*) FROM sqlite_master WHERE name = 'settings'", [], |r| r.get::<_, i64>(0))
        .map(|n| n > 0)
        .unwrap_or(false);
    has_table
        && c.query_row("SELECT 1 FROM settings WHERE key = ?1", [KEY_CHECK], |_| Ok(()))
            .optional()
            .ok()
            .flatten()
            .is_some()
}

/// Copie `VACUUM INTO` avant une migration (jamais écrasée : une boucle de plantage ne remplace
/// pas une copie saine).
fn backup_before_migration(conn: &Connection, path: &Path, from: u32) -> Result<std::path::PathBuf, String> {
    let bak = std::path::PathBuf::from(format!("{}.v{from}.bak", path.display()));
    if bak.exists() {
        return Ok(bak);
    }
    conn.execute("VACUUM INTO ?1", [bak.to_string_lossy()])
        .map_err(|e| format!("sauvegarde avant migration {} : {e}", bak.display()))?;
    crate::datadir::restrict_file(&bak).map_err(|e| format!("{} : {e}", bak.display()))?;
    tracing::info!("base sauvegardée avant migration : {}", bak.display());
    Ok(bak)
}

fn check_key(conn: &mut Connection, keys: &Keys) -> Result<(), String> {
    let stored: Option<String> = conn
        .query_row("SELECT value FROM settings WHERE key = ?1", [KEY_CHECK], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    match stored {
        Some(v) => match keys.decrypt(&aad("settings", KEY_CHECK, 0), &v) {
            Ok(p) if p == KEY_CHECK_PLAIN => Ok(()),
            _ => Err("la clé de chiffrement ne correspond pas à cette base (RCM_ENCRYPTION_KEY ou \
                      manager.key d'une autre installation ?)"
                .into()),
        },
        None => conn
            .execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                [KEY_CHECK, &keys.encrypt(&aad("settings", KEY_CHECK, 0), KEY_CHECK_PLAIN)],
            )
            .map(|_| ())
            .map_err(|e| e.to_string()),
    }
}

/// Transaction d'écriture : `BEGIN IMMEDIATE` (verrou d'écriture pris dès le début).
pub fn write_tx(c: &mut Connection) -> rusqlite::Result<Transaction<'_>> {
    c.transaction_with_behavior(TransactionBehavior::Immediate)
}

/// Applique les migrations manquantes, chacune dans sa transaction.
pub fn migrate(conn: &mut Connection, keys: &Keys) -> rusqlite::Result<()> {
    let current: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "base en version {current}, plus récente que ce binaire ({SCHEMA_VERSION})"
        )));
    }
    for (i, step) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let tx = write_tx(conn)?;
        match step {
            Step::Sql(sql) => tx.execute_batch(sql)?,
            Step::Code(f) => f(&tx, keys)?,
        }
        tx.pragma_update(None, "user_version", (i + 1) as u32)?;
        tx.commit()?;
    }
    Ok(())
}

/// Instant Unix en secondes.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Purge périodique : sessions expirées, audit plus vieux que la rétention. Rend (sessions,
/// lignes d'audit) effacées.
pub fn purge(c: &Connection, now: i64, audit_retention_days: u32) -> rusqlite::Result<(usize, usize)> {
    let s = c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
    let a = c.execute("DELETE FROM audit_log WHERE ts < ?1", [now - i64::from(audit_retention_days) * 86_400])?;
    Ok((s, a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_appliquees_une_fois() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            let v: u32 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            assert_eq!(v, SCHEMA_VERSION);
            // Rejouer ne fait rien.
            migrate(c, &Keys::ephemeral()).unwrap();
            let n: i64 =
                c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table'", [], |r| r.get(0)).unwrap();
            // users, recovery_codes, sessions, audit_log, settings, passkeys, servers,
            // server_favorites, sqlite_sequence (AUTOINCREMENT), server_config_history,
            // server_addresses.
            assert_eq!(n, 11);
        });
    }

    #[test]
    fn base_plus_recente_refusee() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        assert!(migrate(&mut c, &Keys::ephemeral()).is_err());
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rcm-db-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Toute la chaîne depuis une base de la version 1 (secrets TOTP en clair) : sauvegarde,
    /// secrets chiffrés et liés à leur ligne, colonnes en clair disparues, clé vérifiée.
    #[test]
    fn chaine_depuis_la_version_1() {
        let d = tmp("v1");
        let path = d.join("manager.db");
        {
            let c = Connection::open(&path).unwrap();
            let Step::Sql(v1) = &MIGRATIONS[0] else { unreachable!() };
            c.execute_batch(v1).unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
            c.execute(
                "INSERT INTO users (id, username, password_hash, totp_secret, totp_pending, created_at)
                 VALUES (7, 'admin', 'x', CAST('SECRET-TOTP-CONNU-42' AS BLOB), x'0909', 0), (8, 'b', 'x', NULL, NULL, 0)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf, created_at, last_seen, expires_at, ip)
                 VALUES (x'01', 7, 'c', 0, 0, 9999999999, '198.51.100.77')",
                [],
            )
            .unwrap();
            c.execute("INSERT INTO audit_log (id, ts, action, ip) VALUES (3, 0, 'login', '198.51.100.77')", [])
                .unwrap();
            // Volume réaliste : des centaines de lignes, pour que les réécritures libèrent des
            // pages et des cellules (où l'ancien contenu resterait sans effacement).
            for i in 10..1010 {
                c.execute(
                    "INSERT INTO audit_log (id, ts, action, detail, ip) VALUES (?1, 0, 'login', ?2, '198.51.100.77')",
                    rusqlite::params![i, "d".repeat(150)],
                )
                .unwrap();
            }
            for i in 20..220 {
                c.execute(
                    "INSERT INTO users (id, username, password_hash, totp_secret, created_at)
                     VALUES (?1, ?2, ?3, CAST('SECRET-TOTP-CONNU-42' AS BLOB), 0)",
                    rusqlite::params![i, format!("u{i}"), "p".repeat(100)],
                )
                .unwrap();
            }
        }
        let master = crate::crypto::MasterKey::generate();
        let db = Db::open(&path, Keys::derive(&master)).unwrap();
        assert!(!d.join("manager.db.v1.bak").exists(), "copie en clair supprimée après succès");
        let keys = Keys::derive(&master);
        db.with(|c| {
            let (s, p): (String, String) = c
                .query_row("SELECT totp_secret_enc, totp_pending_enc FROM users WHERE id = 7", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
            assert_eq!(keys.decrypt(&aad("users", "totp_secret", 7), &s).unwrap(), b"SECRET-TOTP-CONNU-42");
            assert_eq!(keys.decrypt(&aad("users", "totp_pending", 7), &p).unwrap(), [9, 9]);
            let cols: Vec<String> = c
                .prepare("SELECT name FROM pragma_table_info('users')")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(!cols.iter().any(|c| c == "totp_secret" || c == "totp_pending"), "{cols:?}");
            let none: Option<String> =
                c.query_row("SELECT totp_secret_enc FROM users WHERE id = 8", [], |r| r.get(0)).unwrap();
            assert!(none.is_none());
            // Adresse de l'audit chiffrée et liée à sa ligne ; adresse des sessions disparue.
            let ip: String = c.query_row("SELECT ip FROM audit_log WHERE id = 3", [], |r| r.get(0)).unwrap();
            assert!(ip.starts_with("v1:"), "{ip}");
            assert_eq!(crate::audit::open(&keys, "ip", 3, Some(&ip)).as_deref(), Some("198.51.100.77"));
            let has_ip: i64 = c
                .query_row("SELECT count(*) FROM pragma_table_info('sessions') WHERE name = 'ip'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(has_ip, 0);
            let n: i64 = c.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "sessions gardées");
        });
        drop(db);
        // Revue I-A : ni le secret ni l'adresse ne restent lisibles dans AUCUN fichier du dossier
        // (base, journal WAL, copie d'avant migration).
        for e in std::fs::read_dir(&d).unwrap() {
            let f = e.unwrap().path();
            let bytes = std::fs::read(&f).unwrap();
            for needle in [&b"SECRET-TOTP-CONNU-42"[..], &b"198.51.100.77"[..]] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle),
                    "{} contient encore une valeur en clair",
                    f.display()
                );
            }
        }
        assert!(has_encrypted_data(&path));
        // Rouverte avec une autre clé : refus au démarrage.
        let e = Db::open(&path, Keys::ephemeral()).err().unwrap();
        assert!(e.contains("ne correspond pas"), "{e}");
        // Avec la bonne : acceptée, sans nouvelle sauvegarde.
        assert!(Db::open(&path, Keys::derive(&master)).is_ok());
    }

    /// `write_tx` prend le verrou d'écriture dès `BEGIN` : une seconde connexion ne peut pas
    /// commencer à écrire (avec une transaction différée, elle le pourrait).
    #[test]
    fn transactions_d_ecriture_immediates() {
        let d = tmp("immediate");
        let path = d.join("t.db");
        let mut a = Connection::open(&path).unwrap();
        a.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE t (x INTEGER);").unwrap();
        let b = Connection::open(&path).unwrap();
        b.busy_timeout(std::time::Duration::ZERO).unwrap();
        let tx = write_tx(&mut a).unwrap();
        let r = b.execute_batch("BEGIN IMMEDIATE; COMMIT;");
        assert!(r.is_err(), "le verrou d'écriture doit être tenu dès BEGIN");
        drop(tx);
        b.execute_batch("BEGIN IMMEDIATE; COMMIT;").unwrap();
    }

    /// Aucune transaction différée dans le code : toutes passent par `write_tx`.
    #[test]
    fn aucune_transaction_differee_dans_les_sources() {
        for (name, src) in [
            ("api.rs", include_str!("api.rs")),
            ("audit.rs", include_str!("audit.rs")),
            ("http.rs", include_str!("http.rs")),
            ("lib.rs", include_str!("lib.rs")),
            ("servers.rs", include_str!("servers.rs")),
            ("servers_api.rs", include_str!("servers_api.rs")),
        ] {
            assert!(!src.contains(".transaction()"), "{name} : utiliser db::write_tx");
        }
    }

    #[test]
    fn purge_et_retention() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            let now = 1_000_000_000;
            for ts in [now - 91 * 86_400, now - 89 * 86_400, now] {
                c.execute("INSERT INTO audit_log (ts, action) VALUES (?1, 'x')", [ts]).unwrap();
            }
            c.execute("INSERT INTO users (id, username, password_hash, created_at) VALUES (1, 'a', 'x', 0)", [])
                .unwrap();
            for (h, exp) in [(1u8, now - 1), (2, now + 10)] {
                c.execute(
                    "INSERT INTO sessions (token_hash, user_id, csrf, created_at, last_seen, expires_at) VALUES (?1, 1, '', 0, 0, ?2)",
                    rusqlite::params![vec![h], exp],
                )
                .unwrap();
            }
            assert_eq!(purge(c, now, 90).unwrap(), (1, 1));
            let n: i64 = c.query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2);
        });
    }
}
