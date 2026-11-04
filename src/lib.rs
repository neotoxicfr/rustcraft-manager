//! Rustcraft Manager : gestionnaire web de serveurs Minecraft (phase 2 : serveurs pilotés).
//!
//! Le binaire (`main.rs`) lit la configuration, ouvre la base et appelle [`serve`]. Les tests
//! construisent le routeur avec [`router`] sur une base en mémoire.

pub mod access;
pub mod access_api;
pub mod api;
pub mod assets;
pub mod audit;
pub mod config;
pub mod configs;
pub mod configs_api;
pub mod console;
pub mod crypto;
pub mod datadir;
pub mod db;
pub mod download;
pub mod env;
pub mod error;
pub mod files;
pub mod files_api;
pub mod fsutil;
pub mod http;
pub mod java;
pub mod lang;
pub mod minecraft;
pub mod network;
pub mod network_api;
pub mod passkey;
pub mod password;
pub mod paths;
pub mod props;
pub mod proxies;
pub mod ratelimit;
pub mod rcon;
pub mod server;
pub mod servers;
pub mod servers_api;
pub mod totp;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use config::Config;
use db::Db;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub use server::serve;

/// Fils bloquants du moteur : SQLite (une connexion) et Argon2 (4 places) n'en occupent que
/// quelques-uns ; de la marge pour une rafale sans en lancer 512.
pub const MAX_BLOCKING_THREADS: usize = 32;

/// Commit construit (injecté par `build.rs` : `RCM_GIT_COMMIT` ou `git rev-parse`).
pub const COMMIT: &str = env!("RCM_COMMIT");

/// État partagé par toutes les routes.
pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub hasher: password::Hasher,
    /// Limiteurs séparés : mot de passe (et jeton du premier compte), second facteur,
    /// ré-authentification des actions sensibles.
    pub login_limiter: ratelimit::RateLimiter,
    /// Défis de connexion par passkey demandés, par réseau (anonymes).
    pub passkey_start_limiter: ratelimit::RateLimiter,
    pub second_factor_limiter: ratelimit::RateLimiter,
    pub reauth_limiter: ratelimit::RateLimiter,
    pub audit: audit::Audit,
    pub proxies: proxies::TrustedProxies,
    /// Passkeys (`None` : pas d'adresse publique configurée).
    pub passkeys: Option<passkey::Passkeys>,
    /// `X-Forwarded-For` d'un pair non déclaré déjà signalé (une seule fois).
    pub xff_warned: AtomicBool,
    /// Arrêt demandé : les WebSocket ouverts se ferment.
    pub closing: tokio::sync::watch::Sender<bool>,
    /// WebSocket ouverts par session (empreinte du jeton).
    pub ws_open: std::sync::Mutex<HashMap<[u8; 32], usize>>,
    /// Empreinte SHA-256 du jeton de création du premier compte (`None` : déjà consommé, ou des
    /// comptes existent).
    pub setup_token: tokio::sync::Mutex<Option<[u8; 32]>>,
    /// Serveurs Minecraft pilotés.
    pub servers: Arc<servers::Manager>,
    /// Adresses publiques, DNS, aiguilleur.
    pub network: network::Network,
}

/// Fils utiles (configuration, sinon cœurs logiques), bornés à 4 × les cœurs : une valeur
/// aberrante (mesuré : `RCM_THREADS=124832` lançait 124 832 fils, 2,8 Go au repos) ne doit pas
/// faire tomber la machine.
pub fn thread_count(config: &Config) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    if config.threads > 0 { config.threads.min(cores * 4) } else { cores }
}

/// Construit l'état (dans le moteur tokio : lance la tâche du journal d'audit). Rend aussi le
/// jeton de création du premier compte, en clair, quand aucun compte n'existe : à afficher dans
/// la console, jamais dans un journal persistant.
pub fn new_state(config: Config, db: Db) -> (Arc<AppState>, Option<String>) {
    let users: i64 = db.with(|c| c.query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap_or(0));
    let clear = (users == 0).then(|| crypto::base32(&crypto::random_bytes::<20>()));
    let hashed = clear.as_ref().map(|t| crypto::sha256(t.as_bytes()));
    let limiter = |max| ratelimit::RateLimiter::new(max, config.login_window, config.auth_inflight_per_ip);
    let state = AppState {
        hasher: password::Hasher::new(thread_count(&config).min(password::MAX_CONCURRENT_HASHES), config.hash_wait),
        login_limiter: limiter(config.login_max_failures),
        passkey_start_limiter: limiter(passkey::LOGIN_STARTS_PER_WINDOW),
        second_factor_limiter: limiter(config.login_max_failures).with_account_cap(ratelimit::ACCOUNT_HARD_CAP),
        reauth_limiter: limiter(config.login_max_failures).with_account_cap(ratelimit::ACCOUNT_HARD_CAP),
        audit: audit::Audit::spawn(db.clone()),
        proxies: proxies::TrustedProxies::new(&config.trusted_proxies),
        passkeys: passkey::Passkeys::new(&config).expect("adresse publique validée par la configuration"),
        xff_warned: AtomicBool::new(false),
        closing: tokio::sync::watch::channel(false).0,
        ws_open: std::sync::Mutex::new(HashMap::new()),
        setup_token: tokio::sync::Mutex::new(hashed),
        servers: servers::Manager::load(
            db.clone(),
            config.data_dir.clone(),
            download::Http::new(),
            servers::Limits {
                max_servers: config.max_servers,
                max_memory_mb: config.max_memory_mb,
                max_installs: config.max_installs,
                reserved_port: config.router.map(|r| r.port),
            },
        ),
        network: network::Network::new(&config, &db),
        config,
        db,
    };
    (Arc::new(state), clear)
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health", get(api::health))
        .route("/version", get(api::version))
        .route("/api/setup", get(api::setup_status).post(api::setup))
        .route("/api/auth/login", post(api::login))
        .route("/api/auth/totp", post(api::login_totp))
        .route("/api/auth/logout", post(api::logout))
        .route("/api/auth/me", get(api::me))
        .route("/api/account/password", post(api::change_password))
        .route("/api/account/totp/setup", post(api::totp_setup))
        .route("/api/account/totp/enable", post(api::totp_enable))
        .route("/api/account/totp/disable", post(api::totp_disable))
        .route("/api/account/recovery/regenerate", post(api::recovery_regenerate))
        .route("/api/auth/passkey/start", post(passkey::login_start))
        .route("/api/auth/passkey/finish", post(passkey::login_finish))
        .route("/api/account/passkeys", get(passkey::list))
        .route("/api/account/passkeys/start", post(passkey::register_start))
        .route("/api/account/passkeys/finish", post(passkey::register_finish))
        .route("/api/account/passkeys/delete", post(passkey::delete))
        .route("/api/ws", get(api::ws))
        .route("/api/account/theme", post(servers_api::theme))
        .route("/api/catalog/{software}", get(servers_api::catalog))
        .route("/api/java", get(servers_api::java))
        .route("/api/servers", get(servers_api::list).post(servers_api::create))
        .route("/api/servers/{id}", get(servers_api::get))
        .route("/api/servers/{id}/start", post(servers_api::start))
        .route("/api/servers/{id}/stop", post(servers_api::stop))
        .route("/api/servers/{id}/restart", post(servers_api::restart))
        .route("/api/servers/{id}/install", post(servers_api::install))
        .route("/api/servers/{id}/eula", post(servers_api::eula))
        .route("/api/servers/{id}/settings", post(servers_api::settings))
        .route("/api/servers/{id}/delete", post(servers_api::delete))
        .route("/api/servers/{id}/command", post(servers_api::command))
        .route("/api/servers/{id}/console", get(servers_api::console))
        .route("/api/servers/{id}/suggest/items", get(servers_api::suggest_items))
        .route("/api/servers/{id}/suggest/players", get(servers_api::suggest_players))
        .route("/api/servers/{id}/favorites", get(servers_api::favorites).post(servers_api::favorite_add))
        .route("/api/servers/{id}/favorites/delete", post(servers_api::favorite_delete))
        .route("/api/servers/{id}/address", get(network_api::get).post(network_api::apply))
        .route("/api/servers/{id}/address/preview", post(network_api::preview))
        .route("/api/servers/{id}/address/test", post(network_api::test))
        .route("/api/servers/{id}/configs", get(configs_api::list))
        .route("/api/servers/{id}/config", get(configs_api::read))
        // Seules routes qui portent un fichier entier : corps borné à part (le reste : 64 Kio).
        .route(
            "/api/servers/{id}/config/check",
            post(configs_api::check).layer(DefaultBodyLimit::max(configs_api::BODY_MAX)),
        )
        .route(
            "/api/servers/{id}/config/save",
            post(configs_api::save).layer(DefaultBodyLimit::max(configs_api::BODY_MAX)),
        )
        .route("/api/servers/{id}/config/history", get(configs_api::history))
        .route("/api/servers/{id}/config/history/{version}", get(configs_api::version))
        .route("/api/servers/{id}/access", get(access_api::get))
        .route("/api/servers/{id}/access/resolve", get(access_api::resolve))
        .route("/api/servers/{id}/access/add", post(access_api::add))
        .route("/api/servers/{id}/access/remove", post(access_api::remove))
        .route("/api/servers/{id}/access/whitelist", post(access_api::whitelist_mode))
        .route("/api/servers/{id}/files", get(files_api::list))
        .route("/api/servers/{id}/files/read", get(files_api::read))
        .route("/api/servers/{id}/files/download", get(files_api::download))
        .route(
            "/api/servers/{id}/files/check",
            post(files_api::check).layer(DefaultBodyLimit::max(configs_api::BODY_MAX)),
        )
        .route(
            "/api/servers/{id}/files/write",
            post(files_api::write).layer(DefaultBodyLimit::max(configs_api::BODY_MAX)),
        )
        // Envoi en flux : taille bornée par la route elle-même (`upload_max_mb`).
        .route("/api/servers/{id}/files/upload", post(files_api::upload).layer(DefaultBodyLimit::disable()))
        .route("/api/servers/{id}/files/mkdir", post(files_api::mkdir))
        .route("/api/servers/{id}/files/move", post(files_api::rename))
        .route("/api/servers/{id}/files/delete", post(files_api::delete))
        .route("/api/servers/{id}/files/erase", post(files_api::erase))
        .route("/api/servers/{id}/files/trash", get(files_api::trash_list))
        .route("/api/servers/{id}/files/trash/restore", post(files_api::trash_restore))
        .route("/api/servers/{id}/files/trash/purge", post(files_api::trash_purge))
        .fallback(assets::serve)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn_with_state(state.clone(), http::guard))
        .with_state(state)
}
