//! Garde-fous de l'appli installée (PWA) sur le TEXTE des sources de l'interface : ce que ni
//! Chrome ni les tests ne savent émuler (zones sûres d'iOS, flou « Liquid Glass » d'iOS 26+ sous
//! la barre d'état). Une régression ici ne se voit que sur un
//! iPhone ou un iPad.

const STYLE: &str = include_str!("../web/style.css");
const INDEX: &str = include_str!("../web/index.html");
const MANIFEST: &str = include_str!("../web/public/manifest.webmanifest");

#[test]
fn barre_d_etat_opaque_et_metas_ios() {
    for meta in [
        r#"name="apple-mobile-web-app-status-bar-style" content="default""#,
        r#"name="apple-mobile-web-app-capable" content="yes""#,
        "viewport-fit=cover",
        r#"<div class="bande-encoche" aria-hidden="true"></div>"#,
    ] {
        assert!(INDEX.contains(meta), "index.html : absent : {meta}");
    }
    assert!(!INDEX.contains("black-translucent"), "barre translucide = flou iOS 26+");
}

#[test]
fn bande_du_haut_contient_la_zone_sure() {
    let defs: Vec<&str> = STYLE
        .match_indices("--bande:")
        .map(|(i, _)| {
            let rest = &STYLE[i + "--bande:".len()..];
            &rest[..rest.find(';').unwrap()]
        })
        .collect();
    assert!(defs.len() >= 2, "--bande : défaut + mode installé");
    for d in &defs {
        assert!(d.contains("env(safe-area-inset-top"), "--bande sans zone sûre : {d}");
    }
    assert!(
        STYLE.contains("max(env(safe-area-inset-top, 0px), 12px)"),
        "en mode installé la bande doit dépasser 10 px (seuil de WebKit)"
    );
    // La bande est un vrai élément fixé, sans pointer-events: none (transparent au test de WebKit).
    let band = &STYLE[STYLE.find(".bande-encoche {").expect(".bande-encoche absente")..];
    let band = &band[..band.find('}').unwrap()];
    assert!(band.contains("position: fixed") && band.contains("height: var(--bande)"));
    assert!(!band.contains("pointer-events"));
    // Ce qui colle en haut est décalé de la bande.
    let bar = &STYLE[STYLE.find(".topbar {").unwrap()..];
    let bar = &bar[..bar.find('}').unwrap()];
    assert!(bar.contains("var(--bande)"), "la barre du haut ignore la bande : {bar}");
}

#[test]
fn manifeste_installable() {
    for needle in [
        r#""display": "standalone""#,
        r#""sizes": "192x192""#,
        r#""sizes": "512x512""#,
        r#""purpose": "maskable""#,
        r#""start_url": "/""#,
        r#""id": "/""#,
        r#""scope": "/""#,
        r#""purpose": "any""#,
    ] {
        assert!(MANIFEST.contains(needle), "manifeste : absent : {needle}");
    }
    // Une icône masquable par taille (192 et 512).
    let maskable = MANIFEST.lines().filter(|l| l.contains(r#""purpose": "maskable""#)).count();
    assert!(maskable >= 2, "icônes maskable 192 et 512");
}

const SW: &str = include_str!("../web/public/sw.js");

/// Service worker versionné par l'empreinte de l'interface (remplacée par build.rs), `/version`
/// et `/api` jamais en cache, anciens caches purgés.
#[test]
fn service_worker_versionne() {
    assert!(SW.contains(r#"const CACHE = "rcm-__RCM_UI_VERSION__";"#));
    assert!(SW.contains(r#"url.pathname.startsWith("/api/")"#));
    assert!(SW.contains(r#"url.pathname === "/version""#));
    assert!(SW.contains("caches.delete"), "anciens caches purgés");
}

/// La navigation ne met en cache que la coquille : réponse réussie, même origine, non redirigée,
/// en HTML. Sans cela, la page de connexion d'un mandataire (Authelia), une redirection ou une
/// erreur écrasait la coquille et le mode hors ligne servait cette page.
#[test]
fn service_worker_ne_cache_que_la_coquille() {
    let fonction = SW.split("function estCoquille(res)").nth(1).expect("estCoquille définie");
    let corps = fonction.split("\n}\n").next().unwrap();
    for needle in ["res.ok", "!res.redirected", r#"res.type === "basic""#, r#"startsWith("text/html")"#] {
        assert!(corps.contains(needle), "estCoquille : condition absente : {needle}");
    }
    // Le put de la coquille est gardé par estCoquille ; plus aucun put inconditionnel sur "/".
    let nav = SW.split(r#"req.mode === "navigate""#).nth(1).expect("branche navigation");
    let nav = nav.split("return;").next().unwrap();
    assert!(nav.contains("if (estCoquille(res))"), "put gardé");
    assert!(nav.find("estCoquille").unwrap() < nav.find(r#"c.put("/""#).unwrap(), "put après le garde");
    assert_eq!(nav.matches(".put(").count(), 1);
    assert!(nav.contains(r#".catch(() => caches.match("/"))"#), "repli hors ligne conservé");
}

const WEB_MAIN: &str = include_str!("../web/src/main.rs");
const WEB_SERVERS: &str = include_str!("../web/src/servers.rs");

/// Canal en direct refusé ou coupé : l'interface le dit (état traduit, nouvel essai à délai
/// croissant, bouton Recharger après plusieurs échecs) au lieu de rester sur des emplacements vides,
/// et la page d'un serveur ne conclut « n'existe plus » que si la liste a été reçue.
#[test]
fn canal_en_direct_etat_explicite() {
    // Coupures et échecs d'ouverture comptés, remis à zéro à l'ouverture réussie.
    assert!(WEB_MAIN.contains("ctx.live_failures.update(|n| *n += 1)"));
    assert!(WEB_MAIN.contains("ctx.live_failures.set(0)"));
    assert!(WEB_MAIN.contains("fn retry_delay()"), "délai croissant partagé");
    assert!(WEB_MAIN.contains("K::LiveRetrying") && WEB_MAIN.contains("K::Reload"));
    assert!(WEB_MAIN.contains("ctx.live_stuck()"), "Recharger après plusieurs échecs");
    // Barre latérale et accueil : l'avis remplace les squelettes dès le premier échec.
    assert!(WEB_MAIN.matches("<LiveNotice/>").count() >= 2);
    // Page d'un serveur : « n'existe plus » derrière servers_loaded.
    let gone = WEB_SERVERS.find("K::ServerGone").expect("ServerGone");
    let loaded = WEB_SERVERS[..gone].rfind("ctx.servers_loaded.get()").expect("garde servers_loaded");
    assert!(gone - loaded < 600, "ServerGone sans garde servers_loaded");
    assert!(WEB_SERVERS.contains("crate::LiveNotice"));
}
