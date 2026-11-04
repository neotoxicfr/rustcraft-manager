//! Interface de Rustcraft Manager. Leptos en rendu client.
//!
//! Coquille « Obsidienne » (sombre ou claire selon le thème du compte) : navigation latérale avec
//! la liste des serveurs et leur état, en-tête de page, cartes de mesures. Écrans : assistant du
//! premier compte, connexion (+ code TOTP), page d'un serveur (mesures, favoris, constructeur de
//! commandes, console, joueurs), nouveau serveur, thème, compte. Navigation par l'historique du
//! navigateur (adresses servies par le binaire), français par défaut et anglais. État en direct
//! par le WebSocket (liste des serveurs, console, joueurs et mesures du serveur affiché).

mod address;
mod api;
mod configs;
mod console;
mod editor;
mod files;
mod i18n;
mod icons;
mod passkey;
mod players;
mod schema;
mod servers;
mod theme;

/// Échec d'une opération de passkey dans le navigateur → message.
fn passkey_err(f: passkey::Failure) -> K {
    match f {
        passkey::Failure::Unsupported => K::PasskeyUnsupported,
        passkey::Failure::Cancelled => K::PasskeyCancelled,
    }
}

use api::ApiErr;
use i18n::{K, Lang, error_key, t};
use icons::{I, icon};
use leptos::ev::{MouseEvent, SubmitEvent};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;
use std::cell::RefCell;
use std::time::Duration;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Loading,
    /// Gestionnaire injoignable au démarrage (hors ligne, arrêté) : bouton « Réessayer ».
    Unreachable,
    Setup,
    Login,
    /// Accueil : premier serveur, ou invitation à en créer un.
    Servers,
    NewServer,
    Server(i64),
    /// Onglet « Réglages » d'un serveur (fichiers de configuration).
    ServerConfig(i64),
    /// Onglet « Joueurs » (liste blanche, opérateurs, bannissements).
    ServerPlayers(i64),
    /// Onglet « Fichiers » (gestionnaire de fichiers).
    ServerFiles(i64),
    /// Onglet « Adresse » (nom public, DNS, aiguilleur).
    ServerAddress(i64),
    Theme,
    Account,
}

impl Page {
    fn path(self) -> String {
        match self {
            Page::Loading | Page::Unreachable | Page::Servers => "/".into(),
            Page::Setup => "/setup".into(),
            Page::Login => "/login".into(),
            Page::NewServer => "/servers/new".into(),
            Page::Server(id) => format!("/servers/{id}"),
            Page::ServerConfig(id) => format!("/servers/{id}/settings"),
            Page::ServerPlayers(id) => format!("/servers/{id}/players"),
            Page::ServerFiles(id) => format!("/servers/{id}/files"),
            Page::ServerAddress(id) => format!("/servers/{id}/address"),
            Page::Theme => "/theme".into(),
            Page::Account => "/account".into(),
        }
    }
    fn from_path(p: &str) -> Page {
        let p = p.trim_end_matches('/');
        match p {
            "/account" => Page::Account,
            "/theme" => Page::Theme,
            "/login" => Page::Login,
            "/setup" => Page::Setup,
            "/servers/new" => Page::NewServer,
            _ => {
                let rest = p.strip_prefix("/servers/").unwrap_or("");
                let (id, tab) = rest.split_once('/').unwrap_or((rest, ""));
                match (id.parse::<i64>().ok().filter(|n| *n > 0), tab) {
                    (Some(id), "settings") => Page::ServerConfig(id),
                    (Some(id), "players") => Page::ServerPlayers(id),
                    (Some(id), "files") => Page::ServerFiles(id),
                    (Some(id), "address") => Page::ServerAddress(id),
                    (Some(id), _) => Page::Server(id),
                    (None, _) => Page::Servers,
                }
            }
        }
    }
    /// Écran affiché (les onglets d'un serveur partagent le même écran : pas de remontage).
    pub fn screen(self) -> Page {
        match self {
            Page::ServerConfig(id) | Page::ServerPlayers(id) | Page::ServerFiles(id) | Page::ServerAddress(id) => {
                Page::Server(id)
            }
            p => p,
        }
    }
    fn needs_session(self) -> bool {
        matches!(
            self,
            Page::Servers
                | Page::NewServer
                | Page::Server(_)
                | Page::ServerConfig(_)
                | Page::ServerPlayers(_)
                | Page::ServerFiles(_)
                | Page::ServerAddress(_)
                | Page::Theme
                | Page::Account
        )
    }
}

/// Points gardés pour les courbes de mesures (2 min à un point toutes les 2 s).
const SERIES: usize = 60;
/// Lignes de console gardées dans l'interface.
const LINES: usize = 1500;

#[derive(Clone, Copy)]
pub struct Ctx {
    pub lang: RwSignal<Lang>,
    pub me: RwSignal<Option<Me>>,
    pub page: RwSignal<Page>,
    pub live: RwSignal<bool>,
    /// Échecs d'ouverture ou coupures du canal depuis la dernière ouverture réussie.
    pub live_failures: RwSignal<u32>,
    pub servers: RwSignal<Vec<ServerInfo>>,
    pub servers_loaded: RwSignal<bool>,
    /// Serveur suivi (console, joueurs, mesures poussés par le WebSocket).
    pub watched: RwSignal<Option<i64>>,
    pub lines: RwSignal<Vec<ConsoleLine>>,
    pub players: RwSignal<Vec<PlayerInfo>>,
    pub stats: RwSignal<Vec<ServerStats>>,
    pub player_series: RwSignal<Vec<f32>>,
    /// Instant Unix (s), rafraîchi toutes les 30 s (durées affichées).
    pub now: RwSignal<i64>,
    /// Navigation ouverte (téléphone).
    pub nav_open: RwSignal<bool>,
}

impl Ctx {
    pub fn tr(&self, k: K) -> &'static str {
        t(self.lang.get(), k)
    }
    /// Le canal en direct a échoué depuis sa dernière ouverture réussie.
    pub fn live_down(&self) -> bool {
        self.live_failures.get() > 0
    }
    /// Échecs assez nombreux pour proposer de recharger la page.
    pub fn live_stuck(&self) -> bool {
        self.live_failures.get() >= LIVE_RELOAD_AFTER
    }
    pub fn csrf(&self) -> Option<String> {
        self.me.with_untracked(|m| m.as_ref().map(|m| m.csrf_token.clone()))
    }
    pub fn err(&self, e: &ApiErr) -> K {
        match e {
            ApiErr::Api(c) => error_key(*c),
            ApiErr::Network => K::ErrNetwork,
        }
    }
    /// Erreur d'une page connectée : session perdue → écran de connexion.
    pub fn on_err(&self, e: &ApiErr, msg: RwSignal<Option<K>>) {
        if e.is_unauthorized() {
            self.signed_out();
        }
        msg.set(Some(self.err(e)));
    }
    fn signed_out(&self) {
        close_ws();
        self.live.set(false);
        self.live_failures.set(0);
        self.me.set(None);
        self.servers.set(Vec::new());
        self.servers_loaded.set(false);
        go(*self, Page::Login);
    }
    fn signed_in(&self, me: Me) {
        theme::apply_account(me.theme.as_ref());
        self.me.set(Some(me));
        go(*self, Page::Servers);
        connect_ws(*self);
    }
    /// Suivre un serveur : historique de la console, puis flux en direct.
    pub fn watch(&self, id: i64) {
        let ctx = *self;
        ctx.watched.set(Some(id));
        ctx.lines.set(Vec::new());
        ctx.players.set(Vec::new());
        ctx.stats.set(Vec::new());
        ctx.player_series.set(Vec::new());
        ws_send(&WsClientMessage::Watch { server: Some(id) });
        spawn_local(async move {
            if let Ok(h) = api::get::<ConsoleHistory>(&format!("/api/servers/{id}/console")).await
                && ctx.watched.get_untracked() == Some(id)
            {
                ctx.lines.update(|l| {
                    // Lignes arrivées par le WebSocket pendant la lecture : gardées après.
                    let last = h.lines.last().map_or(0, |x| x.seq);
                    let mut v = h.lines;
                    v.extend(l.drain(..).filter(|x| x.seq > last));
                    *l = v;
                });
                ctx.players.set(h.players);
            }
        });
    }
    pub fn unwatch(&self, id: i64) {
        if self.watched.get_untracked() == Some(id) {
            self.watched.set(None);
            ws_send(&WsClientMessage::Watch { server: None });
        }
    }
}

pub fn storage_get(key: &str) -> Option<String> {
    web_sys::window()?.local_storage().ok()??.get_item(key).ok()?
}

pub fn storage_set(key: &str, val: &str) {
    if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = s.set_item(key, val);
    }
}

fn html_el() -> Option<web_sys::Element> {
    web_sys::window()?.document()?.document_element()
}

fn location_path() -> String {
    web_sys::window().and_then(|w| w.location().pathname().ok()).unwrap_or_else(|| "/".into())
}

fn set_url(path: &str, replace: bool) {
    let Some(h) = web_sys::window().and_then(|w| w.history().ok()) else {
        return;
    };
    let _ = if replace {
        h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(path))
    } else {
        h.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(path))
    };
}

pub fn go(ctx: Ctx, page: Page) {
    if location_path() != page.path() {
        set_url(&page.path(), false);
    }
    ctx.nav_open.set(false);
    ctx.page.set(page);
}

thread_local! {
    /// Éditeurs montés et leur état « modifié, pas enregistré » (clé : numéro de l'éditeur).
    static DIRTY: RefCell<std::collections::HashMap<u64, bool>> = RefCell::default();
    static NEXT_EDITOR: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Suit les modifications non enregistrées d'un éditeur tant qu'il est monté.
pub(crate) fn track_dirty(ed: configs::Ed) {
    let key = NEXT_EDITOR.with(|n| {
        n.set(n.get() + 1);
        n.get()
    });
    Effect::new(move |_| {
        let d = ed.dirty();
        DIRTY.with(|m| m.borrow_mut().insert(key, d));
    });
    on_cleanup(move || {
        DIRTY.with(|m| m.borrow_mut().remove(&key));
    });
}

/// Une modification non enregistrée est-elle ouverte ?
pub(crate) fn unsaved() -> bool {
    DIRTY.with(|m| m.borrow().values().any(|d| *d))
}

/// Quitter la vue courante : permis sans rien demander s'il n'y a rien à perdre, sinon après
/// confirmation (les modifications sont alors abandonnées).
pub(crate) fn may_leave(ctx: Ctx) -> bool {
    if !unsaved() {
        return true;
    }
    let ok = web_sys::window().and_then(|w| w.confirm_with_message(ctx.tr(K::DiscardChanges)).ok()).unwrap_or(true);
    if ok {
        DIRTY.with(|m| m.borrow_mut().values_mut().for_each(|d| *d = false));
    }
    ok
}

/// Navigation demandée par l'utilisateur (onglets, liste des serveurs) : [`may_leave`] d'abord.
pub fn nav(ctx: Ctx, page: Page) {
    if ctx.page.get_untracked() == page || may_leave(ctx) {
        go(ctx, page);
    }
}

// ---------------------------------------------------------------------------------------------
// Formats (langue de l'interface)

fn sep(lang: Lang) -> char {
    if lang == Lang::Fr { ',' } else { '.' }
}

/// Nombre décimal (`20,0` en français).
pub fn fmt_dec(v: f32, decimals: usize, lang: Lang) -> String {
    format!("{v:.decimals$}").replace('.', &sep(lang).to_string())
}

/// Entier avec séparateur des milliers (`2 100`, `2,100`).
pub fn fmt_int(v: u64, lang: Lang) -> String {
    let s = v.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(if lang == Lang::Fr { '\u{202f}' } else { ',' });
        }
        out.push(c);
    }
    out
}

/// Durée en millisecondes, en secondes (`4,2 s`).
pub fn fmt_secs(ms: u64, lang: Lang) -> String {
    format!("{} s", fmt_dec(ms as f32 / 1000.0, 1, lang))
}

/// Octets en Go ou Mo (`2,4 Go`, `2.4 GB`).
pub fn fmt_bytes(b: u64, lang: Lang) -> String {
    let (g, m) = if lang == Lang::Fr { ("Go", "Mo") } else { ("GB", "MB") };
    let gib = b as f32 / 1024.0 / 1024.0 / 1024.0;
    if gib >= 1.0 { format!("{} {g}", fmt_dec(gib, 1, lang)) } else { format!("{} {m}", b / 1024 / 1024) }
}

/// Mémoire réglée (Mio) : `2 Go`, `512 Mo`.
pub fn fmt_mb(mb: u32, lang: Lang) -> String {
    let (g, m) = if lang == Lang::Fr { ("Go", "Mo") } else { ("GB", "MB") };
    if mb >= 1024 && mb.is_multiple_of(1024) { format!("{} {g}", mb / 1024) } else { format!("{mb} {m}") }
}

/// Durée en secondes (`3 h 12`, `12 min`).
pub fn fmt_duration(secs: i64, lang: Lang) -> String {
    let s = secs.max(0);
    let (d, h, m) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60);
    match (d, h, lang) {
        (0, 0, _) => format!("{m} min"),
        (0, h, Lang::Fr) => format!("{h} h {m:02}"),
        (0, h, Lang::En) => format!("{h}h {m:02}m"),
        (d, h, Lang::Fr) => format!("{d} j {h} h"),
        (d, h, Lang::En) => format!("{d}d {h}h"),
    }
}

// ---------------------------------------------------------------------------------------------
// Canal en direct (WebSocket)

type Cb = Closure<dyn FnMut(web_sys::Event)>;
type WsSlot = (web_sys::WebSocket, Cb, Cb, Closure<dyn FnMut(web_sys::MessageEvent)>);

thread_local! {
    static WS: RefCell<Option<WsSlot>> = const { RefCell::new(None) };
    /// Reconnexions successives (recul exponentiel).
    static RETRIES: RefCell<u32> = const { RefCell::new(0) };
}

fn close_ws() {
    WS.with(|w| {
        if let Some((ws, _, _, _)) = w.borrow_mut().take() {
            ws.set_onopen(None);
            ws.set_onclose(None);
            ws.set_onmessage(None);
            let _ = ws.close();
        }
    });
}

fn ws_send(msg: &WsClientMessage) {
    let Ok(text) = serde_json::to_string(msg) else { return };
    WS.with(|w| {
        if let Some((ws, _, _, _)) = w.borrow().as_ref()
            && ws.ready_state() == web_sys::WebSocket::OPEN
        {
            let _ = ws.send_with_str(&text);
        }
    });
}

fn on_ws_message(ctx: Ctx, text: &str) {
    let Ok(msg) = serde_json::from_str::<WsServerMessage>(text) else { return };
    match msg {
        WsServerMessage::Hello { .. } => {}
        WsServerMessage::Servers { servers } => {
            ctx.servers.set(servers);
            ctx.servers_loaded.set(true);
        }
        WsServerMessage::Console { server, lines } if ctx.watched.get_untracked() == Some(server) => {
            ctx.lines.update(|l| {
                let last = l.last().map_or(0, |x| x.seq);
                l.extend(lines.into_iter().filter(|x| x.seq > last));
                if l.len() > LINES {
                    l.drain(..l.len() - LINES);
                }
            });
        }
        WsServerMessage::Players { server, players } if ctx.watched.get_untracked() == Some(server) => {
            ctx.players.set(players);
        }
        WsServerMessage::Stats { server, stats } if ctx.watched.get_untracked() == Some(server) => {
            let n = ctx.servers.with_untracked(|l| l.iter().find(|s| s.id == server).map_or(0, |s| s.players));
            ctx.player_series.update(|p| {
                p.push(n as f32);
                if p.len() > SERIES {
                    p.remove(0);
                }
            });
            ctx.stats.update(|s| {
                s.push(stats);
                if s.len() > SERIES {
                    s.remove(0);
                }
            });
        }
        _ => {}
    }
}

/// Délai avant le prochain essai du canal : 2 s, 4 s… 30 s au plus.
fn retry_delay() -> Duration {
    RETRIES.with(|r| {
        let mut r = r.borrow_mut();
        *r = (*r + 1).min(5);
        Duration::from_secs((1u64 << *r).min(30))
    })
}

/// Échecs consécutifs du canal à partir desquels l'interface propose de recharger la page.
const LIVE_RELOAD_AFTER: u32 = 3;

/// État explicite quand la liste n'a pas pu être reçue : le canal ne s'ouvre pas (nouvel essai à
/// délai croissant), puis un bouton Recharger après plusieurs échecs.
#[component]
pub fn LiveNotice() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let reload = move |_: MouseEvent| {
        if let Some(w) = web_sys::window() {
            let _ = w.location().reload();
        }
    };
    view! {
        <div class="state-block live-notice" role="status">
            <p class="faint">{move || ctx.tr(K::LiveRetrying)}</p>
            <Show when=move || ctx.live_stuck()>
                <button type="button" class="btn small" on:click=reload>{move || ctx.tr(K::Reload)}</button>
            </Show>
        </div>
    }
}

fn connect_ws(ctx: Ctx) {
    close_ws();
    let Some(loc) = web_sys::window().map(|w| w.location()) else {
        return;
    };
    let proto = if loc.protocol().ok().as_deref() == Some("https:") { "wss" } else { "ws" };
    let host = loc.host().unwrap_or_default();
    let Ok(ws) = web_sys::WebSocket::new(&format!("{proto}://{host}/api/ws")) else {
        // Adresse refusée par le navigateur : même traitement qu'une coupure (nouvel essai).
        ctx.live_failures.update(|n| *n += 1);
        set_timeout(move || connect_ws(ctx), retry_delay());
        return;
    };
    let on_open = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        ctx.live.set(true);
        ctx.live_failures.set(0);
        RETRIES.with(|r| *r.borrow_mut() = 0);
        // Reconnexion : le serveur affiché est de nouveau suivi.
        if let Some(id) = ctx.watched.get_untracked() {
            ws_send(&WsClientMessage::Watch { server: Some(id) });
        }
    });
    let on_close = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        ctx.live.set(false);
        if ctx.me.with_untracked(Option::is_none) {
            return;
        }
        // Refus (4xx/5xx du mandataire, en-têtes mal reconnus) ou coupure : l'interface le dit
        // (`LiveNotice`) au lieu de rester sur des emplacements vides.
        ctx.live_failures.update(|n| *n += 1);
        // Coupure : session expirée (retour à la connexion) ou gestionnaire redémarré (on
        // réessaie à délai croissant, 30 s au plus).
        let wait = retry_delay();
        spawn_local(async move {
            match api::get::<Me>("/api/auth/me").await {
                Ok(me) => {
                    ctx.me.set(Some(me));
                    set_timeout(move || connect_ws(ctx), wait);
                }
                Err(e) if e.is_unauthorized() => ctx.signed_out(),
                Err(_) => set_timeout(move || connect_ws(ctx), wait),
            }
        });
    });
    let on_message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Some(t) = e.data().as_string() {
            on_ws_message(ctx, &t);
        }
    });
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    WS.with(|w| *w.borrow_mut() = Some((ws, on_open, on_close, on_message)));
}

// ---------------------------------------------------------------------------------------------

fn main() {
    theme::apply_cached();
    leptos::mount::mount_to_body(App);
    register_service_worker();
    watch_version();
}

thread_local! {
    /// Empreinte de l'interface chargée (`/version` au démarrage).
    static UI_VERSION: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Interface mise à jour pendant que l'onglet (ou l'appli installée) dormait : à chaque retour au
/// premier plan, `/version` est relu ; une autre empreinte = rechargement (le nouveau service
/// worker purge l'ancien cache). Panne réseau : rien (on réessaiera au prochain retour).
fn watch_version() {
    async fn check() {
        let Ok(v) = api::get::<rc_manager_shared::VersionInfo>("/version").await else {
            return;
        };
        let changed = UI_VERSION.with(|u| {
            let mut u = u.borrow_mut();
            match u.as_deref() {
                None => {
                    *u = Some(v.ui.clone());
                    false
                }
                Some(old) => old != v.ui,
            }
        });
        if changed && let Some(w) = web_sys::window() {
            let _ = w.location().reload();
        }
    }
    spawn_local(check());
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else { return };
    let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        let visible = web_sys::window()
            .and_then(|w| w.document())
            .is_some_and(|d| d.visibility_state() == web_sys::VisibilityState::Visible);
        if visible {
            spawn_local(check());
        }
    });
    let _ = doc.add_event_listener_with_callback("visibilitychange", cb.as_ref().unchecked_ref());
    // Écouteur gardé pour toute la vie de la page.
    cb.forget();
}

/// Service worker (PWA installable, coquille hors ligne). `navigator.serviceWorker` n'existe
/// qu'en contexte sûr (HTTPS ou boucle locale) : l'appeler ailleurs lèverait une exception JS qui
/// arrêterait le module wasm. Un refus d'enregistrement est absorbé (aucune promesse orpheline).
fn register_service_worker() {
    let Some(w) = web_sys::window() else { return };
    let nav = w.navigator();
    if !js_sys::Reflect::has(&nav, &"serviceWorker".into()).unwrap_or(false) || !w.is_secure_context() {
        return;
    }
    let promise = nav.service_worker().register("/sw.js");
    spawn_local(async move {
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    });
}

fn browser_lang() -> Lang {
    let nav = web_sys::window().map(|w| w.navigator().language().unwrap_or_default()).unwrap_or_default();
    Lang::from_browser(&nav)
}

fn now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

#[component]
fn App() -> impl IntoView {
    // Langue choisie, sinon celle du navigateur (français s'il commence par « fr », anglais sinon).
    let lang = storage_get("rcm-lang").and_then(|s| Lang::from_code(&s)).unwrap_or_else(browser_lang);
    let ctx = Ctx {
        lang: RwSignal::new(lang),
        me: RwSignal::new(None),
        page: RwSignal::new(Page::Loading),
        live: RwSignal::new(false),
        live_failures: RwSignal::new(0),
        servers: RwSignal::new(Vec::new()),
        servers_loaded: RwSignal::new(false),
        watched: RwSignal::new(None),
        lines: RwSignal::new(Vec::new()),
        players: RwSignal::new(Vec::new()),
        stats: RwSignal::new(Vec::new()),
        player_series: RwSignal::new(Vec::new()),
        now: RwSignal::new(now_secs()),
        nav_open: RwSignal::new(false),
    };
    provide_context(ctx);
    // Écran affiché : changer d'onglet d'un serveur ne remonte pas sa page.
    let screen = Memo::new(move |_| ctx.page.get().screen());
    Effect::new(move |_| {
        let l = ctx.lang.get();
        if let Some(el) = html_el() {
            let _ = el.set_attribute("lang", l.code());
        }
    });
    set_interval(move || ctx.now.set(now_secs()), Duration::from_secs(30));

    // Boutons précédent/suivant du navigateur.
    if let Some(w) = web_sys::window() {
        let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            let p = Page::from_path(&location_path());
            let signed = ctx.me.with_untracked(Option::is_some);
            match (signed, p.needs_session()) {
                // Modifications non enregistrées refusées d'abandonner : l'adresse revient.
                (true, true) if ctx.page.get_untracked() != p && !may_leave(ctx) => {
                    set_url(&ctx.page.get_untracked().path(), false)
                }
                (true, true) => ctx.page.set(p),
                (true, false) => go(ctx, Page::Servers),
                (false, _) if ctx.page.get_untracked() != Page::Setup => go(ctx, Page::Login),
                _ => {}
            }
        });
        let _ = w.add_event_listener_with_callback("popstate", cb.as_ref().unchecked_ref());
        cb.forget(); // un seul écouteur, pour toute la vie de la page
        // Fermeture ou rechargement de la page avec des modifications non enregistrées.
        let leave = Closure::<dyn FnMut(web_sys::Event)>::new(move |ev: web_sys::Event| {
            if unsaved() {
                ev.prevent_default();
                // Anciens navigateurs : `returnValue` non vide exigé.
                let _ = js_sys::Reflect::set(&ev, &"returnValue".into(), &"1".into());
            }
        });
        let _ = w.add_event_listener_with_callback("beforeunload", leave.as_ref().unchecked_ref());
        leave.forget();
    }

    // Accueil : premier serveur s'il y en a un (la liste latérale montre les autres).
    Effect::new(move |_| {
        if ctx.page.get() == Page::Servers
            && ctx.servers_loaded.get()
            && let Some(first) = ctx.servers.with(|l| l.first().map(|s| s.id))
        {
            set_url(&Page::Server(first).path(), true);
            ctx.page.set(Page::Server(first));
        }
    });

    // Démarrage : premier compte à créer ? session déjà ouverte ?
    spawn_local(async move {
        match api::get::<SetupStatus>("/api/setup").await {
            Ok(s) if s.needed => {
                let path = location_path();
                if path != "/setup" {
                    set_url("/setup", true);
                }
                ctx.page.set(Page::Setup);
            }
            Err(ApiErr::Network) => ctx.page.set(Page::Unreachable),
            _ => match api::get::<Me>("/api/auth/me").await {
                Ok(me) => {
                    theme::apply_account(me.theme.as_ref());
                    ctx.me.set(Some(me));
                    let p = Page::from_path(&location_path());
                    let p = if p.needs_session() { p } else { Page::Servers };
                    set_url(&p.path(), true);
                    ctx.page.set(p);
                    connect_ws(ctx);
                }
                Err(_) => {
                    set_url("/login", true);
                    ctx.page.set(Page::Login);
                }
            },
        }
    });

    let signed = move || ctx.me.with(Option::is_some) && ctx.page.get().needs_session();
    view! {
        <Show when=signed fallback=move || view! {
            <AuthBar/>
            <main class="auth-main">
                {move || match ctx.page.get() {
                    // Démarrage : rien (quelques millisecondes), plutôt qu'un texte qui clignote.
                    Page::Loading => ().into_any(),
                    Page::Unreachable => view! {
                        <div class="auth"><div class="center card empty">
                            <h1>{move || ctx.tr(K::OfflineTitle)}</h1>
                            <button on:click=move |_| {
                                if let Some(w) = web_sys::window() {
                                    let _ = w.location().reload();
                                }
                            }>{move || ctx.tr(K::Retry)}</button>
                        </div></div>
                    }.into_any(),
                    Page::Setup => view! { <div class="auth"><SetupPage/></div> }.into_any(),
                    _ => view! { <div class="auth"><LoginPage/></div> }.into_any(),
                }}
            </main>
        }>
            <div class="app">
                <MobileBar/>
                <Sidebar/>
                <Show when=move || ctx.nav_open.get()>
                    <div class="scrim" on:click=move |_| ctx.nav_open.set(false)></div>
                </Show>
                <main class="main">
                    {move || match screen.get() {
                        Page::Server(id) => view! { <servers::ServerPage id=id/> }.into_any(),
                        Page::NewServer => view! { <servers::NewServerPage/> }.into_any(),
                        Page::Theme => view! { <theme::ThemePage/> }.into_any(),
                        Page::Account => view! { <AccountPage/> }.into_any(),
                        _ => view! {
                            <Show when=move || ctx.servers_loaded.get() fallback=move || view! {
                                <Show when=move || ctx.live_down() fallback=|| view! { <div class="hero-skeleton skeleton"></div> }>
                                    <LiveNotice/>
                                </Show>
                            }>
                                <servers::NoServers/>
                            </Show>
                        }.into_any(),
                    }}
                </main>
            </div>
        </Show>
    }
}

/// Barre du haut des pages sans session (nom, langue).
#[component]
fn AuthBar() -> impl IntoView {
    view! {
        <header class="topbar auth-bar">
            <span class="brand">{icon(I::Logo)}"Rustcraft Manager"</span>
            <LangButton/>
        </header>
    }
}

#[component]
fn LangButton() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let switch_lang = move |_: MouseEvent| {
        let l = ctx.lang.get_untracked().next();
        storage_set("rcm-lang", l.code());
        ctx.lang.set(l);
    };
    view! {
        <button type="button" class="btn ghost small lang" on:click=switch_lang
            title=move || ctx.tr(K::Language) lang=move || ctx.lang.get().next().code()>
            {icon(I::Globe)}{move || ctx.tr(K::SwitchLang)}
        </button>
    }
}

/// Barre du haut sur téléphone : menu, nom, état du canal en direct.
#[component]
fn MobileBar() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    // Le nom de la page est dans son en-tête : la barre ne montre que la marque (une information, une fois).
    view! {
        <header class="topbar mobile-bar">
            <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::Menu)
                aria-expanded=move || ctx.nav_open.get().to_string()
                on:click=move |_| ctx.nav_open.update(|o| *o = !*o)>{icon(I::Menu)}</button>
            <span class="brand mobile-title">{icon(I::Logo)}"Rustcraft Manager"</span>
            <span class="dot live" class:on=move || ctx.live.get() title=move || ctx.tr(if ctx.live.get() { K::LiveOn } else { K::LiveOff })></span>
        </header>
    }
}

/// Navigation latérale : serveurs (état en pastille), nouveau serveur, thème, compte.
#[component]
fn Sidebar() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let logout = move |_: MouseEvent| {
        let csrf = ctx.csrf();
        spawn_local(async move {
            let _ = api::post_empty("/api/auth/logout", &serde_json::Map::new(), csrf.as_deref()).await;
            ctx.signed_out();
        });
    };
    let link = move |page: Page, ico: I, label: Box<dyn Fn() -> String + Send + Sync>| {
        let href = page.path();
        view! {
            <a href=href class="side-link" class:active=move || ctx.page.get() == page
                on:click=move |ev: MouseEvent| { ev.prevent_default(); nav(ctx, page); }>
                {icon(ico)}<span>{label}</span>
            </a>
        }
    };
    let username = move || ctx.me.with(|m| m.as_ref().map(|m| m.username.clone()).unwrap_or_default());
    view! {
        <nav class="side" class:open=move || ctx.nav_open.get() aria-label=move || ctx.tr(K::Navigation)>
            <div class="side-brand">
                <span class="logo">{icon(I::Logo)}</span>
                <span class="brand-name">"Rustcraft Manager"</span>
                <span class="dot live" class:on=move || ctx.live.get() title=move || ctx.tr(if ctx.live.get() { K::LiveOn } else { K::LiveOff })></span>
            </div>
            <div class="srv-list">
                <Show when=move || !ctx.servers_loaded.get()>
                    <Show when=move || ctx.live_down()
                        fallback=|| (0..2).map(|_| view! { <span class="srv-link skeleton"></span> }).collect_view()>
                        <LiveNotice/>
                    </Show>
                </Show>
                <For each=move || ctx.servers.get() key=|s| (s.id, s.name.clone(), servers::state_class(s)) let:s>
                    {
                        let id = s.id;
                        let cls = format!("dot {}", servers::state_class(&s));
                        let sw = s.software;
                        view! {
                            <a href=Page::Server(id).path() class="srv-link" class:active=move || ctx.page.get().screen() == Page::Server(id)
                                on:click=move |ev: MouseEvent| { ev.prevent_default(); nav(ctx, Page::Server(id)); }>
                                <span class=format!("srv-ico sw-{}", sw.code())>{icon(servers::software_icon(sw))}</span>
                                <span class="srv-name">{s.name.clone()}</span>
                                <span class=cls title=move || ctx.tr(servers::state_key(&s))></span>
                            </a>
                        }
                    }
                </For>
                <button type="button" class="new-srv" class:active=move || ctx.page.get() == Page::NewServer
                    on:click=move |_| nav(ctx, Page::NewServer)>{icon(I::Plus)}{move || ctx.tr(K::NewServer)}</button>
            </div>
            <div class="side-foot">
                {link(Page::Theme, I::Palette, Box::new(move || ctx.tr(K::ThemeTitle).to_string()))}
                {link(Page::Account, I::User, Box::new(username))}
                <div class="foot-tools">
                    <LangButton/>
                    <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::Logout) title=move || ctx.tr(K::Logout)
                        on:click=logout>{icon(I::Logout)}</button>
                </div>
            </div>
        </nav>
    }
}

/// Message d'erreur (ou de succès) traduit sous un formulaire.
#[component]
pub fn Msg(msg: RwSignal<Option<K>>, #[prop(optional)] ok: bool) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    view! {
        <Show when=move || msg.with(Option::is_some)>
            <p class=if ok { "success" } else { "error" } role="alert">
                {move || msg.get().map(|k| ctx.tr(k))}
            </p>
        </Show>
    }
}

fn input_value(ev: &leptos::ev::Event) -> String {
    event_target_value(ev)
}

#[component]
fn SetupPage() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    // Jeton dans le fragment de l'adresse affichée par la console (`/setup#token=…`) : jamais
    // envoyé au serveur dans une URL.
    let from_hash = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .and_then(|h| h.strip_prefix("#token=").map(str::to_string))
        .unwrap_or_default();
    let token = RwSignal::new(from_hash);
    let user = RwSignal::new(String::new());
    let pw = RwSignal::new(String::new());
    let pw2 = RwSignal::new(String::new());
    let msg = RwSignal::new(None::<K>);
    let busy = RwSignal::new(false);
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        if !username_valid(&user.get_untracked()) {
            msg.set(Some(K::ErrInvalidUsername));
            return;
        }
        if !password_valid(&pw.get_untracked()) {
            msg.set(Some(K::ErrWeakPassword));
            return;
        }
        if pw.get_untracked() != pw2.get_untracked() {
            msg.set(Some(K::PasswordMismatch));
            return;
        }
        let req = SetupRequest {
            token: token.get_untracked().trim().to_string(),
            username: user.get_untracked(),
            password: pw.get_untracked(),
        };
        busy.set(true);
        spawn_local(async move {
            match api::post::<_, LoginResponse>("/api/setup", &req, None).await {
                Ok(LoginResponse::LoggedIn { me }) => ctx.signed_in(me),
                Ok(LoginResponse::TotpRequired) => go(ctx, Page::Login),
                Err(ApiErr::Api(ErrorCode::SetupNotNeeded)) => go(ctx, Page::Login),
                Err(e) => msg.set(Some(ctx.err(&e))),
            }
            busy.set(false);
        });
    };
    view! {
        <div class="center card">
            <h1>{move || ctx.tr(K::SetupTitle)}</h1>
            <form on:submit=submit>
                <label>{move || ctx.tr(K::SetupToken)}
                    <input class="mono" autocomplete="off" required
                        prop:value=move || token.get() on:input=move |ev| token.set(input_value(&ev))/>
                    <span class="hint">{move || ctx.tr(K::SetupTokenHint)}</span>
                </label>
                <label>{move || ctx.tr(K::Username)}
                    <input autocomplete="username" required
                        prop:value=move || user.get() on:input=move |ev| user.set(input_value(&ev))/>
                    <span class="hint">{move || ctx.tr(K::UsernameRules)}</span>
                </label>
                <label>{move || ctx.tr(K::Password)}
                    <input type="password" autocomplete="new-password" required
                        prop:value=move || pw.get() on:input=move |ev| pw.set(input_value(&ev))/>
                    <span class="hint">{move || ctx.tr(K::PasswordRules)}</span>
                </label>
                <label>{move || ctx.tr(K::PasswordConfirm)}
                    <input type="password" autocomplete="new-password" required
                        prop:value=move || pw2.get() on:input=move |ev| pw2.set(input_value(&ev))/>
                </label>
                <Msg msg=msg/>
                <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::CreateAdmin)}</button>
            </form>
        </div>
    }
}

#[component]
fn LoginPage() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let user = RwSignal::new(String::new());
    let pw = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let totp_step = RwSignal::new(false);
    let msg = RwSignal::new(None::<K>);
    let busy = RwSignal::new(false);
    // Passkeys : activées sur le serveur (adresse publique) ET gérées par ce navigateur.
    let passkeys = RwSignal::new(false);
    spawn_local(async move {
        if let Ok(s) = api::get::<SetupStatus>("/api/setup").await {
            passkeys.set(s.passkeys && passkey::supported());
        }
    });
    let with_passkey = move |_: MouseEvent| {
        busy.set(true);
        msg.set(None);
        spawn_local(async move {
            let r = async {
                let ch = api::post::<_, PasskeyChallenge>("/api/auth/passkey/start", &serde_json::Map::new(), None)
                    .await
                    .map_err(|e| ctx.err(&e))?;
                let credential = passkey::run(false, &ch.options).await.map_err(passkey_err)?;
                let req = PasskeyFinishRequest { challenge_id: ch.challenge_id, credential };
                api::post::<_, LoginResponse>("/api/auth/passkey/finish", &req, None).await.map_err(|e| ctx.err(&e))
            }
            .await;
            match r {
                Ok(LoginResponse::LoggedIn { me }) => ctx.signed_in(me),
                Ok(LoginResponse::TotpRequired) => totp_step.set(true),
                Err(k) => msg.set(Some(k)),
            }
            busy.set(false);
        });
    };
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        msg.set(None);
        let req = LoginRequest { username: user.get_untracked(), password: pw.get_untracked() };
        spawn_local(async move {
            match api::post::<_, LoginResponse>("/api/auth/login", &req, None).await {
                Ok(LoginResponse::LoggedIn { me }) => ctx.signed_in(me),
                Ok(LoginResponse::TotpRequired) => {
                    pw.set(String::new());
                    totp_step.set(true);
                }
                Err(e) => msg.set(Some(ctx.err(&e))),
            }
            busy.set(false);
        });
    };
    let submit_code = move |ev: SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        msg.set(None);
        let req = TotpLoginRequest { code: code.get_untracked() };
        spawn_local(async move {
            match api::post::<_, LoginResponse>("/api/auth/totp", &req, None).await {
                Ok(LoginResponse::LoggedIn { me }) => ctx.signed_in(me),
                Ok(LoginResponse::TotpRequired) => {}
                Err(ApiErr::Api(ErrorCode::Unauthorized)) => {
                    // Session provisoire expirée : on repart du mot de passe.
                    totp_step.set(false);
                    msg.set(Some(K::ErrUnauthorized));
                }
                Err(e) => msg.set(Some(ctx.err(&e))),
            }
            code.set(String::new());
            busy.set(false);
        });
    };
    view! {
        <div class="center card">
            <h1>{move || ctx.tr(K::LoginTitle)}</h1>
            <Show
                when=move || totp_step.get()
                fallback=move || view! {
                    <form on:submit=submit>
                        <label>{move || ctx.tr(K::Username)}
                            <input autocomplete="username" required
                                prop:value=move || user.get() on:input=move |ev| user.set(input_value(&ev))/>
                        </label>
                        <label>{move || ctx.tr(K::Password)}
                            <input type="password" autocomplete="current-password" required
                                prop:value=move || pw.get() on:input=move |ev| pw.set(input_value(&ev))/>
                        </label>
                        <Msg msg=msg/>
                        <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::LoginButton)}</button>
                        <Show when=move || passkeys.get()>
                            <button type="button" class="ghost" on:click=with_passkey disabled=move || busy.get()>
                                {move || ctx.tr(K::PasskeyLogin)}
                            </button>
                        </Show>
                    </form>
                }
            >
                <form on:submit=submit_code>
                    <label>{move || ctx.tr(K::TotpPrompt)}
                        <input autocomplete="one-time-code" inputmode="text" required
                            prop:value=move || code.get() on:input=move |ev| code.set(input_value(&ev))/>
                    </label>
                    <Msg msg=msg/>
                    <div class="row">
                        <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::Verify)}</button>
                        <button type="button" class="ghost" on:click=move |_| totp_step.set(false)>
                            {move || ctx.tr(K::Back)}
                        </button>
                    </div>
                </form>
            </Show>
        </div>
    }
}

/// Date locale d'un instant Unix (secondes).
fn local_date(unix: i64, lang: Lang) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(unix as f64 * 1000.0));
    d.to_locale_date_string(lang.code(), &wasm_bindgen::JsValue::UNDEFINED).into()
}

/// Passkeys du compte : liste, ajout et suppression (mot de passe, + code si le TOTP est actif).
#[component]
fn PasskeysCard() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let list = RwSignal::new(Vec::<PasskeyInfo>::new());
    let name = RwSignal::new(String::new());
    let pw = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let msg = RwSignal::new(None::<K>);
    let busy = RwSignal::new(false);
    let totp_on = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
    let reauth = move || Reauth {
        password: pw.get_untracked(),
        code: ctx.me.with_untracked(|m| m.as_ref().is_some_and(|m| m.totp_enabled)).then(|| code.get_untracked()),
    };
    let reload = move || {
        spawn_local(async move {
            match api::get::<Vec<PasskeyInfo>>("/api/account/passkeys").await {
                Ok(v) => list.set(v),
                Err(e) => ctx.on_err(&e, msg),
            }
        })
    };
    reload();
    let done = move || {
        pw.set(String::new());
        code.set(String::new());
        busy.set(false);
    };
    let add = move |ev: SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        msg.set(None);
        let csrf = ctx.csrf();
        let req = PasskeyRegisterRequest { reauth: reauth(), name: name.get_untracked() };
        enum Fail {
            Api(ApiErr),
            Browser(K),
        }
        spawn_local(async move {
            let r: Result<PasskeyInfo, Fail> = async {
                let ch = api::post::<_, PasskeyChallenge>("/api/account/passkeys/start", &req, csrf.as_deref())
                    .await
                    .map_err(Fail::Api)?;
                let credential = passkey::run(true, &ch.options).await.map_err(|f| Fail::Browser(passkey_err(f)))?;
                let fin = PasskeyFinishRequest { challenge_id: ch.challenge_id, credential };
                api::post::<_, PasskeyInfo>("/api/account/passkeys/finish", &fin, csrf.as_deref())
                    .await
                    .map_err(Fail::Api)
            }
            .await;
            match r {
                Ok(_) => {
                    name.set(String::new());
                    reload();
                }
                Err(Fail::Browser(k)) => msg.set(Some(k)),
                Err(Fail::Api(e)) => ctx.on_err(&e, msg),
            }
            done();
        });
    };
    let remove = move |id: i64| {
        busy.set(true);
        msg.set(None);
        let csrf = ctx.csrf();
        let req = PasskeyDeleteRequest { reauth: reauth(), id };
        spawn_local(async move {
            match api::post_empty("/api/account/passkeys/delete", &req, csrf.as_deref()).await {
                Ok(()) => reload(),
                Err(e) => ctx.on_err(&e, msg),
            }
            done();
        });
    };
    view! {
        <div class="card">
            <h2>{move || ctx.tr(K::PasskeysTitle)}</h2>
            <Show
                when=move || list.with(|l| !l.is_empty())
                fallback=move || view! { <p class="muted">{move || ctx.tr(K::PasskeyNone)}</p> }
            >
                <ul class="passkeys">
                    {move || list.get().into_iter().map(|p| {
                        let id = p.id;
                        let created = p.created_at;
                        let used = p.last_used_at;
                        view! {
                            <li>
                                <strong>{p.name}</strong>
                                <span class="muted">
                                    {move || ctx.tr(K::PasskeyAddedOn)} " " {move || local_date(created, ctx.lang.get())}
                                    {move || used.map(|u| format!(" · {} {}", ctx.tr(K::PasskeyLastUsed), local_date(u, ctx.lang.get())))}
                                </span>
                                <button type="button" class="ghost small danger" disabled=move || busy.get()
                                    on:click=move |_| remove(id)>{move || ctx.tr(K::PasskeyDelete)}</button>
                            </li>
                        }
                    }).collect_view()}
                </ul>
            </Show>
            <form on:submit=add>
                <p class="muted">{move || ctx.tr(K::PasskeyConfirmHint)}</p>
                <label>{move || ctx.tr(K::PasskeyName)}
                    <input maxlength="64" required
                        prop:value=move || name.get() on:input=move |ev| name.set(input_value(&ev))/>
                </label>
                <label>{move || ctx.tr(K::Password)}
                    <input type="password" autocomplete="current-password" required
                        prop:value=move || pw.get() on:input=move |ev| pw.set(input_value(&ev))/>
                </label>
                <Show when=totp_on>
                    <label>{move || ctx.tr(K::TotpCode)}
                        <input autocomplete="one-time-code" required
                            prop:value=move || code.get() on:input=move |ev| code.set(input_value(&ev))/>
                    </label>
                </Show>
                <Msg msg=msg/>
                <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::PasskeyAdd)}</button>
            </form>
        </div>
    }
}

#[component]
fn AccountPage() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    // Passkeys activées sur ce gestionnaire (adresse publique configurée).
    let passkeys_on = RwSignal::new(false);
    spawn_local(async move {
        if let Ok(s) = api::get::<SetupStatus>("/api/setup").await {
            passkeys_on.set(s.passkeys);
        }
    });
    let refresh = move || {
        spawn_local(async move {
            match api::get::<Me>("/api/auth/me").await {
                Ok(me) => ctx.me.set(Some(me)),
                Err(e) if e.is_unauthorized() => ctx.signed_out(),
                Err(_) => {}
            }
        })
    };
    let username = move || ctx.me.with(|m| m.as_ref().map(|m| m.username.clone()).unwrap_or_default());
    let is_admin = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.is_admin));
    let totp_on = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
    let left = move || ctx.me.with(|m| m.as_ref().map_or(0, |m| m.recovery_codes_left));
    let totp_on_untracked = move || ctx.me.with_untracked(|m| m.as_ref().is_some_and(|m| m.totp_enabled));

    // Activation TOTP.
    let setup = RwSignal::new(None::<TotpSetupResponse>);
    let codes = RwSignal::new(None::<Vec<String>>);
    let code = RwSignal::new(String::new());
    let totp_msg = RwSignal::new(None::<K>);
    // Requête en cours : boutons du compte désactivés (pas de double envoi).
    let busy = RwSignal::new(false);
    let start = move |_: MouseEvent| {
        totp_msg.set(None);
        let csrf = ctx.csrf();
        busy.set(true);
        spawn_local(async move {
            match api::post::<_, TotpSetupResponse>("/api/account/totp/setup", &serde_json::Map::new(), csrf.as_deref())
                .await
            {
                Ok(s) => setup.set(Some(s)),
                Err(e) => ctx.on_err(&e, totp_msg),
            }
            busy.set(false);
        });
    };
    let en_pw = RwSignal::new(String::new());
    let confirm = move |ev: SubmitEvent| {
        ev.prevent_default();
        let csrf = ctx.csrf();
        let req = TotpEnableRequest {
            reauth: Reauth { password: en_pw.get_untracked(), code: None },
            code: code.get_untracked(),
        };
        busy.set(true);
        spawn_local(async move {
            match api::post::<_, TotpEnableResponse>("/api/account/totp/enable", &req, csrf.as_deref()).await {
                Ok(r) => {
                    setup.set(None);
                    codes.set(Some(r.recovery_codes));
                    totp_msg.set(None);
                    refresh();
                }
                Err(e) => ctx.on_err(&e, totp_msg),
            }
            code.set(String::new());
            en_pw.set(String::new());
            busy.set(false);
        });
    };
    // Régénération des codes de secours (proposée surtout pour les codes de l'ancien format).
    let legacy = move || ctx.me.with(|m| m.as_ref().map_or(0, |m| m.recovery_codes_legacy));
    let rg_pw = RwSignal::new(String::new());
    let rg_code = RwSignal::new(String::new());
    let regenerate = move |ev: SubmitEvent| {
        ev.prevent_default();
        let csrf = ctx.csrf();
        let req = RecoveryRegenerateRequest {
            reauth: Reauth { password: rg_pw.get_untracked(), code: Some(rg_code.get_untracked()) },
        };
        busy.set(true);
        spawn_local(async move {
            match api::post::<_, TotpEnableResponse>("/api/account/recovery/regenerate", &req, csrf.as_deref()).await {
                Ok(r) => {
                    codes.set(Some(r.recovery_codes));
                    totp_msg.set(None);
                    refresh();
                }
                Err(e) => ctx.on_err(&e, totp_msg),
            }
            rg_pw.set(String::new());
            rg_code.set(String::new());
            busy.set(false);
        });
    };
    // Désactivation.
    let dis_pw = RwSignal::new(String::new());
    let dis_code = RwSignal::new(String::new());
    let disable = move |ev: SubmitEvent| {
        ev.prevent_default();
        let csrf = ctx.csrf();
        let req = TotpDisableRequest {
            reauth: Reauth { password: dis_pw.get_untracked(), code: Some(dis_code.get_untracked()) },
        };
        busy.set(true);
        spawn_local(async move {
            match api::post_empty("/api/account/totp/disable", &req, csrf.as_deref()).await {
                Ok(()) => {
                    totp_msg.set(None);
                    refresh();
                }
                Err(e) => ctx.on_err(&e, totp_msg),
            }
            dis_pw.set(String::new());
            dis_code.set(String::new());
            busy.set(false);
        });
    };
    // Mot de passe.
    let cur = RwSignal::new(String::new());
    let cur_code = RwSignal::new(String::new());
    let new = RwSignal::new(String::new());
    let new2 = RwSignal::new(String::new());
    let pw_msg = RwSignal::new(None::<K>);
    let pw_ok = RwSignal::new(None::<K>);
    let change_pw = move |ev: SubmitEvent| {
        ev.prevent_default();
        pw_ok.set(None);
        if !password_valid(&new.get_untracked()) {
            pw_msg.set(Some(K::ErrWeakPassword));
            return;
        }
        if new.get_untracked() != new2.get_untracked() {
            pw_msg.set(Some(K::PasswordMismatch));
            return;
        }
        let csrf = ctx.csrf();
        let req = PasswordChangeRequest {
            reauth: Reauth {
                password: cur.get_untracked(),
                code: totp_on_untracked().then(|| cur_code.get_untracked()),
            },
            new: new.get_untracked(),
        };
        busy.set(true);
        spawn_local(async move {
            match api::post_empty("/api/account/password", &req, csrf.as_deref()).await {
                Ok(()) => {
                    pw_msg.set(None);
                    pw_ok.set(Some(K::Saved));
                    cur.set(String::new());
                    new.set(String::new());
                    new2.set(String::new());
                }
                Err(e) => ctx.on_err(&e, pw_msg),
            }
            // Code à usage unique : jamais réutilisable, champ vidé dans tous les cas.
            cur_code.set(String::new());
            busy.set(false);
        });
    };

    view! {
        <header class="page-head"><h1>{move || ctx.tr(K::AccountTitle)}</h1></header>
        <div class="card">
            <p>{move || ctx.tr(K::SignedInAs)} " " <strong>{username}</strong>
                <Show when=is_admin>" (" {move || ctx.tr(K::Administrator)} ")"</Show>
            </p>
        </div>
        <div class="card">
            <h2>{move || ctx.tr(K::TotpTitle)}</h2>
            <Show when=move || codes.with(Option::is_some)>
                <h2>{move || ctx.tr(K::RecoveryTitle)}</h2>
                <p class="muted">{move || ctx.tr(K::RecoveryWarn)}</p>
                <ul class="codes mono">
                    {move || codes.get().unwrap_or_default().into_iter().map(|c| view! { <li>{c}</li> }).collect_view()}
                </ul>
                <button on:click=move |_| codes.set(None)>{move || ctx.tr(K::RecoveryDone)}</button>
            </Show>
            <Show when=move || codes.with(Option::is_none)>
                <Show
                    when=totp_on
                    fallback=move || view! {
                        <p class="muted">{move || ctx.tr(K::TotpDisabled)}</p>
                        <Show
                            when=move || setup.with(Option::is_some)
                            fallback=move || view! { <button on:click=start disabled=move || busy.get()>{move || ctx.tr(K::TotpEnable)}</button> }
                        >
                            <p>{move || ctx.tr(K::TotpScan)}</p>
                            <div class="qr" inner_html=move || setup.with(|s| s.as_ref().map(|s| s.qr_svg.clone()).unwrap_or_default())></div>
                            <p class="muted">{move || ctx.tr(K::TotpManual)} " "
                                <code>{move || setup.with(|s| s.as_ref().map(|s| s.secret.clone()).unwrap_or_default())}</code>
                            </p>
                            <form on:submit=confirm>
                                <label>{move || ctx.tr(K::Password)}
                                    <input type="password" autocomplete="current-password" required
                                        prop:value=move || en_pw.get() on:input=move |ev| en_pw.set(input_value(&ev))/>
                                </label>
                                <label>{move || ctx.tr(K::TotpCode)}
                                    <input autocomplete="one-time-code" inputmode="numeric" maxlength="7" required
                                        prop:value=move || code.get() on:input=move |ev| code.set(input_value(&ev))/>
                                </label>
                                <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::TotpConfirm)}</button>
                            </form>
                        </Show>
                    }
                >
                    <p class="success">{move || ctx.tr(K::TotpEnabled)}</p>
                    <p class="muted">{move || ctx.tr(K::RecoveryLeft)} " " {left}</p>
                    <Show when=move || legacy() != 0>
                        <p class="error" role="status">{move || ctx.tr(K::RecoveryLegacy)}</p>
                    </Show>
                    <form on:submit=regenerate>
                        <label>{move || ctx.tr(K::Password)}
                            <input type="password" autocomplete="current-password" required
                                prop:value=move || rg_pw.get() on:input=move |ev| rg_pw.set(input_value(&ev))/>
                        </label>
                        <label>{move || ctx.tr(K::TotpCode)}
                            <input autocomplete="one-time-code" required
                                prop:value=move || rg_code.get() on:input=move |ev| rg_code.set(input_value(&ev))/>
                        </label>
                        <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::RecoveryRegenerate)}</button>
                    </form>
                    <form on:submit=disable>
                        <label>{move || ctx.tr(K::Password)}
                            <input type="password" autocomplete="current-password" required
                                prop:value=move || dis_pw.get() on:input=move |ev| dis_pw.set(input_value(&ev))/>
                        </label>
                        <label>{move || ctx.tr(K::TotpCode)}
                            <input autocomplete="one-time-code" required
                                prop:value=move || dis_code.get() on:input=move |ev| dis_code.set(input_value(&ev))/>
                        </label>
                        <button type="submit" class="danger" disabled=move || busy.get()>{move || ctx.tr(K::TotpDisable)}</button>
                    </form>
                </Show>
            </Show>
            <Msg msg=totp_msg/>
        </div>
        <Show when=move || passkeys_on.get()>
            <PasskeysCard/>
        </Show>
        <div class="card">
            <h2>{move || ctx.tr(K::PasswordTitle)}</h2>
            <form on:submit=change_pw>
                <label>{move || ctx.tr(K::CurrentPassword)}
                    <input type="password" autocomplete="current-password" required
                        prop:value=move || cur.get() on:input=move |ev| cur.set(input_value(&ev))/>
                </label>
                <Show when=totp_on>
                    <label>{move || ctx.tr(K::TotpCode)}
                        <input autocomplete="one-time-code" required
                            prop:value=move || cur_code.get() on:input=move |ev| cur_code.set(input_value(&ev))/>
                    </label>
                </Show>
                <label>{move || ctx.tr(K::NewPassword)}
                    <input type="password" autocomplete="new-password" required
                        prop:value=move || new.get() on:input=move |ev| new.set(input_value(&ev))/>
                    <span class="hint">{move || ctx.tr(K::PasswordRules)}</span>
                </label>
                <label>{move || ctx.tr(K::PasswordConfirm)}
                    <input type="password" autocomplete="new-password" required
                        prop:value=move || new2.get() on:input=move |ev| new2.set(input_value(&ev))/>
                </label>
                <Msg msg=pw_msg/>
                <Msg msg=pw_ok ok=true/>
                <button type="submit" disabled=move || busy.get()>{move || ctx.tr(K::Save)}</button>
            </form>
        </div>
    }
}
