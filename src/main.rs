//! Binaire `rustcraft-manager`.

use rc_manager::{assets, config, datadir, db, new_state, serve, thread_count};
use std::net::SocketAddr;
use std::time::Instant;

fn main() {
    let t0 = Instant::now();
    let args = match config::parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{}", config::HELP);
            std::process::exit(2);
        }
    };
    if args.help {
        print!("{}", config::HELP);
        return;
    }
    if args.version {
        println!("rustcraft-manager {} ({})", env!("CARGO_PKG_VERSION"), rc_manager::COMMIT);
        return;
    }
    let level = match std::env::var("RCM_LOG").as_deref() {
        Ok("error") => tracing::Level::ERROR,
        Ok("warn") => tracing::Level::WARN,
        Ok("debug") => tracing::Level::DEBUG,
        Ok("info") | Err(std::env::VarError::NotPresent) => tracing::Level::INFO,
        Ok(other) => {
            eprintln!("configuration : RCM_LOG : error, warn, info ou debug (lu : {other})");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("configuration : RCM_LOG : valeur qui n'est pas de l'UTF-8");
            std::process::exit(2);
        }
    };
    // Couleurs seulement dans un terminal (pas dans un fichier ni les journaux d'un conteneur).
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    tracing_subscriber::fmt().with_max_level(level).with_target(false).with_ansi(ansi).init();

    let cfg = match config::load(&args, &rc_manager::env::ProcessEnv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration : {e}");
            std::process::exit(2);
        }
    };
    scrub_secret_env();
    if args.healthcheck {
        std::process::exit(healthcheck(&cfg));
    }
    let threads = thread_count(&cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        // Fils bloquants bornés (SQLite, Argon2) : 512 par défaut chez tokio. Argon2 garde sa
        // place jusqu'à la fin du calcul (password.rs), SQLite n'a qu'une connexion.
        .max_blocking_threads(rc_manager::MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
        .expect("moteur asynchrone");
    if let Err(e) = rt.block_on(run(cfg, t0)) {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

async fn run(cfg: config::Config, t0: Instant) -> Result<(), String> {
    datadir::prepare(&cfg.data_dir)?;
    let (key, source) = datadir::master_key(&cfg, db::has_encrypted_data(&cfg.db_path()))?;
    if source == datadir::KeySource::Generated {
        tracing::warn!(
            "clé de chiffrement créée : {} ; sauvegardez-la À PART de la base (sans elle, les \
             secrets TOTP sont perdus)",
            cfg.key_path().display()
        );
    }
    let database = db::Db::open(&cfg.db_path(), rc_manager::crypto::Keys::derive(&key))?;
    let addr = SocketAddr::new(cfg.listen, cfg.port);
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("écoute sur {addr} : {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    if !cfg.listen.is_loopback() {
        if cfg.trusted_proxies.is_empty() {
            tracing::warn!(
                "ATTENTION : écoute sur {} sans aucun mandataire de confiance (trusted_proxies vide). \
                 Derrière Traefik, toutes les requêtes semblent venir de Traefik : la limite de \
                 tentatives et l'audit ne voient plus les clients, le cookie n'est pas `Secure` \
                 (sauf RCM_COOKIE_SECURE=always) et HSTS n'est pas envoyé. Déclarez le mandataire \
                 (RCM_TRUSTED_PROXIES=traefik) ; n'exposez jamais ce port directement sur Internet",
                cfg.listen
            );
        } else {
            tracing::info!(
                "écoute sur {} : accessible depuis le réseau, derrière les mandataires déclarés",
                cfg.listen
            );
        }
    }
    let broad = rc_manager::proxies::TrustedProxies::new(&cfg.trusted_proxies).broad_nets();
    if !broad.is_empty() {
        tracing::warn!(
            "trusted_proxies : {} couvre beaucoup d'adresses ; tout conteneur de ce réseau pourrait \
             dicter X-Forwarded-For. Préférez le nom du mandataire (traefik) ou son IP exacte",
            broad.join(", ")
        );
    }
    let (raw, gz) = assets::sizes();
    tracing::info!(
        "données : {} ; interface {} ({} Kio, {} Kio compressée) ; {} fils",
        cfg.data_dir.display(),
        if assets::WEB_BUILT { "embarquée" } else { "absente (page d'explication)" },
        raw / 1024,
        gz / 1024,
        rc_manager::thread_count(&cfg)
    );
    let (state, token) = new_state(cfg, database);
    let shown = if local.ip().is_unspecified() {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), local.port())
    } else {
        local
    };
    if let Some(token) = token {
        // Sortie standard volontairement (journaux du conteneur sous Docker) : le jeton n'ouvre
        // que la création du premier compte et meurt avec ce processus ou à son premier usage.
        println!();
        println!("  ┌──────────────────────────────────────────────────────────────┐");
        println!("  │ Premier lancement : créez le compte administrateur.          │");
        println!("  │ Jeton à usage unique : {token}      │");
        println!("  └──────────────────────────────────────────────────────────────┘");
        println!("  Ouvrez http://{shown}/setup#token={token}");
        println!();
    }
    if let Some(r) = state.config.router {
        if let Some(s) = state.servers.list().into_iter().find(|s| s.port == r.port) {
            return Err(format!(
                "RCM_ROUTER_PORT : le port {} est celui du serveur « {} » : changer son port d'abord",
                r.port, s.name
            ));
        }
        let addr = SocketAddr::new(r.listen, r.port);
        let l = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("aiguilleur sur {addr} : {e}"))?;
        let limits = rc_manager::network::router::Limits {
            max_connections: r.max_connections,
            max_per_ip: r.max_per_ip,
            handshake_timeout: rc_manager::network::router::HANDSHAKE_TIMEOUT,
            idle_timeout: rc_manager::network::router::IDLE_TIMEOUT,
        };
        tokio::spawn(rc_manager::network::router::run(
            l,
            state.network.routes(state.servers.clone()),
            limits,
            state.closing.subscribe(),
        ));
        tracing::info!("aiguilleur à l'écoute sur {addr} (port public partagé, routage par nom)");
    }
    // IP publiques, puis resynchronisation DNS (sans écraser ce qui est posé à la main).
    rc_manager::network::spawn(&state);
    tracing::info!("à l'écoute sur http://{local} (prêt en {} ms)", t0.elapsed().as_millis());
    // Serveurs qui tournaient à l'arrêt précédent : relancés.
    state.servers.resume();
    serve(listener, state, async {
        shutdown_signal().await;
        tracing::info!("arrêt demandé");
    })
    .await
    .map_err(|e| e.to_string())
}

/// Retire les secrets de l'environnement du processus une fois lus (mineur 5 de la seconde
/// revue) : ni `/proc/<pid>/environ`, ni un processus enfant (serveurs Java, de toute façon
/// lancés avec un environnement vidé, `env_clear`, et une liste blanche) ne
/// les voient. Appelé avant le démarrage du moteur asynchrone : le processus n'a qu'un fil, seul
/// cas où modifier l'environnement est sûr.
#[allow(unsafe_code)]
fn scrub_secret_env() {
    for name in rc_manager::config::SECRET_ENV {
        // SAFETY : un seul fil à ce stade (moteur tokio pas encore construit, journal sans fil).
        unsafe { std::env::remove_var(name) };
    }
}

/// Sonde de santé (HEALTHCHECK de l'image Docker, sans curl dans l'image) : GET /api/health en
/// HTTP/1.1 sur l'adresse d'écoute configurée (boucle locale si elle écoute partout).
fn healthcheck(cfg: &config::Config) -> i32 {
    use std::io::{Read, Write};
    use std::time::Duration;
    let ip = if cfg.listen.is_unspecified() {
        if cfg.listen.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() }
    } else {
        cfg.listen
    };
    let addr = SocketAddr::new(ip, cfg.port);
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)) else {
        return 1;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let req = format!("GET /api/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return 1;
    }
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap_or(0);
    if buf[..n].starts_with(b"HTTP/1.1 200") { 0 } else { 1 }
}

/// Ctrl+C, ou SIGTERM (`docker stop`) hors Windows.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
