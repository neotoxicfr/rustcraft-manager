//! Console d'un serveur (maquette Console, de haut en bas) : commandes favorites, constructeur de
//! commandes en tuiles et en arbre (fil d'Ariane, saisie libre avec suggestions à chaque frappe),
//! puis la console : vue lisible (événements typés, icônes colorées, filtres) ou brute (texte
//! exact), saisie libre.

use crate::i18n::K;
use crate::icons::{I, icon};
use crate::{Ctx, api};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;

// ---------------------------------------------------------------------------------------------
// Arbre des commandes

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Node {
    Root,
    GivePlayer,
    Item,
    Qty,
    TpWho,
    TpTo,
    Mode,
    ModeWho,
    Time,
    Weather,
    Msg,
    KickWho,
}

/// Saisie libre d'une étape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Free {
    Player,
    Item,
    Qty,
    Coords,
    Message,
}

#[derive(Clone, Debug, PartialEq)]
struct Step {
    label: String,
    value: String,
    next: Option<Node>,
}

#[derive(Clone)]
struct Tile {
    label: TileLabel,
    color: &'static str,
    value: String,
    next: Option<Node>,
}

#[derive(Clone)]
enum TileLabel {
    K(K),
    Text(String),
}

fn question(n: Node) -> K {
    match n {
        Node::Root => K::QWhat,
        Node::GivePlayer => K::QToWhom,
        Node::Item => K::QWhichItem,
        Node::Qty => K::QHowMany,
        Node::TpWho | Node::KickWho => K::QWho,
        Node::TpTo => K::QToWho,
        Node::Mode => K::QWhichMode,
        Node::ModeWho => K::QForWhom,
        Node::Time => K::QWhen,
        Node::Weather => K::QWhichWeather,
        Node::Msg => K::QWhichMessage,
    }
}

fn free(n: Node) -> Option<(Free, K, Option<Node>)> {
    match n {
        Node::GivePlayer => Some((Free::Player, K::FreeOtherPlayer, Some(Node::Item))),
        Node::KickWho => Some((Free::Player, K::FreeOtherPlayer, None)),
        Node::TpWho => Some((Free::Player, K::FreeOtherPlayer, Some(Node::TpTo))),
        Node::ModeWho => Some((Free::Player, K::FreeOtherPlayer, None)),
        Node::Item => Some((Free::Item, K::FreeSearchItem, Some(Node::Qty))),
        Node::Qty => Some((Free::Qty, K::FreeOtherQty, None)),
        Node::TpTo => Some((Free::Coords, K::FreeCoords, None)),
        Node::Msg => Some((Free::Message, K::FreeMessage, None)),
        _ => None,
    }
}

fn tiles(n: Node, players: &[String]) -> Vec<Tile> {
    let t = |k: K, color: &'static str, value: &str, next: Option<Node>| Tile {
        label: TileLabel::K(k),
        color,
        value: value.to_string(),
        next,
    };
    let people = |next: Option<Node>, everyone: bool| {
        let mut v: Vec<Tile> = players
            .iter()
            .map(|p| Tile { label: TileLabel::Text(p.clone()), color: "#9fb4ff", value: p.clone(), next })
            .collect();
        if everyone {
            v.push(t(K::Everyone, "#7ee2b8", "@a", next));
        }
        v
    };
    match n {
        Node::Root => vec![
            t(K::CmdGive, "#7ee2b8", "give", Some(Node::GivePlayer)),
            t(K::CmdTeleport, "#9fb4ff", "tp", Some(Node::TpWho)),
            t(K::CmdGamemode, "#e6c477", "gamemode", Some(Node::Mode)),
            t(K::CmdTime, "#f0a868", "time set", Some(Node::Time)),
            t(K::CmdWeather, "#8fd3ff", "weather", Some(Node::Weather)),
            t(K::CmdSay, "#c7b8ff", "say", Some(Node::Msg)),
            t(K::CmdKick, "#ef7f73", "kick", Some(Node::KickWho)),
            t(K::CmdSave, "#9aa6b5", "save-all", None),
        ],
        Node::GivePlayer => people(Some(Node::Item), true),
        Node::Item => vec![
            t(K::ItemDiamond, "#6fe3e1", "minecraft:diamond", Some(Node::Qty)),
            t(K::ItemBread, "#c9954c", "minecraft:bread", Some(Node::Qty)),
            t(K::ItemTorch, "#f2c14e", "minecraft:torch", Some(Node::Qty)),
            t(K::ItemOakLog, "#a07a4a", "minecraft:oak_log", Some(Node::Qty)),
            t(K::ItemIronPickaxe, "#cfd4da", "minecraft:iron_pickaxe", None),
            t(K::ItemBed, "#d1495b", "minecraft:red_bed", Some(Node::Qty)),
        ],
        Node::Qty => ["1", "16", "32", "64"]
            .iter()
            .map(|q| Tile { label: TileLabel::Text(q.to_string()), color: "#7d848f", value: q.to_string(), next: None })
            .collect(),
        Node::TpWho => people(Some(Node::TpTo), false),
        Node::TpTo => people(None, false),
        Node::Mode => vec![
            t(K::ModeSurvival, "#e6c477", "survival", Some(Node::ModeWho)),
            t(K::ModeCreative, "#e6c477", "creative", Some(Node::ModeWho)),
            t(K::ModeAdventure, "#e6c477", "adventure", Some(Node::ModeWho)),
            t(K::ModeSpectator, "#e6c477", "spectator", Some(Node::ModeWho)),
        ],
        Node::ModeWho => people(None, true),
        Node::Time => vec![
            t(K::TimeDay, "#f0a868", "day", None),
            t(K::TimeNoon, "#f0a868", "noon", None),
            t(K::TimeNight, "#f0a868", "night", None),
            t(K::TimeMidnight, "#f0a868", "midnight", None),
        ],
        Node::Weather => vec![
            t(K::WeatherClear, "#8fd3ff", "clear", None),
            t(K::WeatherRain, "#8fd3ff", "rain", None),
            t(K::WeatherThunder, "#8fd3ff", "thunder", None),
        ],
        Node::Msg => Vec::new(),
        Node::KickWho => people(None, false),
    }
}

fn player_ok(s: &str) -> bool {
    ((1..=16).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        || matches!(s, "@a" | "@p" | "@r" | "@s" | "@e")
}

/// Coordonnées `x y z` : nombres, `~`, `~n` ou `^n`.
fn coords_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            let n = p.trim_start_matches(['~', '^']);
            n.is_empty() && p.len() == 1 || n.parse::<f64>().is_ok_and(f64::is_finite)
        })
}

fn item_id(s: &str) -> Option<String> {
    let id = s.trim().to_lowercase().replace(' ', "_");
    let id = id.strip_prefix("minecraft:").unwrap_or(&id).to_string();
    (!id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
        .then(|| format!("minecraft:{id}"))
}

/// Valeur d'une saisie libre, si elle est valide.
fn free_value(kind: Free, text: &str) -> Option<String> {
    let t = text.trim();
    match kind {
        Free::Player => player_ok(t).then(|| t.to_string()),
        Free::Item => item_id(t),
        Free::Qty => t.parse::<u32>().ok().filter(|n| (1..=6400).contains(n)).map(|n| n.to_string()),
        Free::Coords => coords_ok(t).then(|| t.split_whitespace().collect::<Vec<_>>().join(" ")),
        Free::Message => {
            (!t.is_empty() && t.chars().count() <= 256 && !t.chars().any(char::is_control)).then(|| t.to_string())
        }
    }
}

/// Suggestion affichée sous la saisie libre.
#[derive(Clone, PartialEq)]
struct Suggestion {
    label: String,
    sub: String,
    value: String,
}

fn encode(s: &str) -> String {
    js_sys::encode_uri_component(s).as_string().unwrap_or_default()
}

/// Commandes favorites (par compte et par serveur) : un clic les exécute.
#[component]
pub fn Favorites(server: i64, favorites: RwSignal<Vec<Favorite>>, msg: RwSignal<Option<K>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let run = move |cmd: String| {
        let csrf = ctx.csrf();
        spawn_local(async move {
            if let Err(e) = api::post_empty(
                &format!("/api/servers/{server}/command"),
                &CommandRequest { command: cmd },
                csrf.as_deref(),
            )
            .await
            {
                ctx.on_err(&e, msg);
            }
        });
    };
    let remove = move |id: i64| {
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post_empty(
                &format!("/api/servers/{server}/favorites/delete"),
                &FavoriteDeleteRequest { id },
                csrf.as_deref(),
            )
            .await
            {
                Ok(()) => favorites.update(|f| f.retain(|x| x.id != id)),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    view! {
        <div class="favorites" role="group" aria-label=move || ctx.tr(K::Favorites)>
            <span class="fav-star">{icon(I::StarFill)}</span>
            <Show when=move || favorites.with(Vec::is_empty)>
                <span class="faint">{move || ctx.tr(K::FavoritesEmpty)}</span>
            </Show>
            <For each=move || favorites.get() key=|f| f.id let:f>
                {
                    let cmd = f.command.clone();
                    let id = f.id;
                    view! {
                        <span class="fav">
                            <button type="button" class="fav-run" title=f.command.clone() on:click=move |_| run(cmd.clone())>{f.label.clone()}</button>
                            <button type="button" class="fav-del" aria-label=move || ctx.tr(K::FavoriteRemove) on:click=move |_| remove(id)>{icon(I::Close)}</button>
                        </span>
                    }
                }
            </For>
        </div>
    }
}

/// Constructeur de commandes en tuiles.
#[component]
pub fn Builder(
    server: i64,
    favorites: RwSignal<Vec<Favorite>>,
    #[prop(into)] running: Signal<bool>,
    msg: RwSignal<Option<K>>,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let path = RwSignal::new(Vec::<Step>::new());
    let text = RwSignal::new(String::new());
    let suggestions = RwSignal::new(Vec::<Suggestion>::new());
    let seq = RwSignal::new(0u32);
    let busy = RwSignal::new(false);
    let node = move || {
        path.with(|p| match p.last() {
            None => Some(Node::Root),
            Some(s) => s.next,
        })
    };
    let command = move || path.with(|p| p.iter().map(|s| s.value.as_str()).collect::<Vec<_>>().join(" "));
    let done = move || path.with(|p| !p.is_empty()) && node().is_none();
    let push = move |s: Step| {
        path.update(|p| p.push(s));
        text.set(String::new());
        suggestions.set(Vec::new());
    };
    let reset = move || {
        path.set(Vec::new());
        text.set(String::new());
        suggestions.set(Vec::new());
    };
    // Suggestions à chaque frappe (objets en français et en anglais, joueurs déjà venus) ; une
    // réponse plus ancienne que la dernière frappe est ignorée.
    let typed = move |v: String| {
        text.set(v.clone());
        let Some((kind, _, _)) = node().and_then(free) else { return };
        let route = match kind {
            Free::Item => "items",
            Free::Player => "players",
            _ => return,
        };
        if v.trim().is_empty() {
            suggestions.set(Vec::new());
            return;
        }
        let n = seq.get_untracked().wrapping_add(1);
        seq.set(n);
        let url = format!("/api/servers/{server}/suggest/{route}?q={}", encode(v.trim()));
        spawn_local(async move {
            let list: Vec<Suggestion> = if kind == Free::Item {
                match api::get::<Vec<ItemSuggestion>>(&url).await {
                    Ok(v) => {
                        let fr = ctx.lang.get_untracked() == crate::i18n::Lang::Fr;
                        v.into_iter()
                            .map(|s| Suggestion {
                                label: if fr { s.fr.clone() } else { s.en.clone() },
                                sub: format!("{} · {}", if fr { &s.en } else { &s.fr }, s.id),
                                value: format!("minecraft:{}", s.id),
                            })
                            .collect()
                    }
                    Err(_) => Vec::new(),
                }
            } else {
                match api::get::<Vec<PlayerSuggestion>>(&url).await {
                    Ok(v) => v
                        .into_iter()
                        .map(|p| Suggestion {
                            label: p.name.clone(),
                            sub: ctx.tr(if p.online { K::PlayerOnline } else { K::PlayerKnown }).to_string(),
                            value: p.name,
                        })
                        .collect(),
                    Err(_) => Vec::new(),
                }
            };
            if seq.get_untracked() == n {
                suggestions.set(list);
            }
        });
    };
    let submit_free = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some((kind, _, next)) = node().and_then(free) else { return };
        let t = text.get_untracked();
        match free_value(kind, &t) {
            Some(value) => {
                msg.set(None);
                push(Step { label: t.trim().to_string(), value, next });
            }
            None => msg.set(Some(K::ErrInvalidInput)),
        }
    };
    let run = move |_| {
        if !done() {
            return;
        }
        busy.set(true);
        let csrf = ctx.csrf();
        let cmd = command();
        spawn_local(async move {
            match api::post_empty(
                &format!("/api/servers/{server}/command"),
                &CommandRequest { command: cmd },
                csrf.as_deref(),
            )
            .await
            {
                Ok(()) => {
                    msg.set(None);
                    reset();
                }
                Err(e) => ctx.on_err(&e, msg),
            }
            busy.set(false);
        });
    };
    let star = move |_| {
        if !done() {
            return;
        }
        let label: String = path.with(|p| p.iter().map(|s| s.label.clone()).collect::<Vec<_>>().join(" · "));
        let label: String = label.chars().take(FAVORITE_LABEL_MAX).collect();
        let req = FavoriteRequest { label, command: command() };
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post::<_, Favorite>(&format!("/api/servers/{server}/favorites"), &req, csrf.as_deref()).await {
                Ok(f) => favorites.update(|v| v.push(f)),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    let tile_label = move |l: &TileLabel| match l {
        TileLabel::K(k) => ctx.tr(*k).to_string(),
        TileLabel::Text(s) => s.clone(),
    };
    let players = move || ctx.players.with(|p| p.iter().map(|x| x.name.clone()).collect::<Vec<_>>());
    view! {
        <section class="panel builder" aria-label=move || ctx.tr(K::Builder)>
            <nav class="crumbs" aria-label=move || ctx.tr(K::BuilderSteps)>
                {move || path.get().into_iter().enumerate().map(|(i, s)| view! {
                    <button type="button" class="crumb" on:click=move |_| {
                        path.update(|p| p.truncate(i));
                        text.set(String::new());
                        suggestions.set(Vec::new());
                    }>{s.label}</button>
                    <span class="crumb-sep" aria-hidden="true">"›"</span>
                }).collect_view()}
                <span class="question">{move || node().map_or(ctx.tr(K::Ready), |n| ctx.tr(question(n)))}</span>
            </nav>
            <Show when=move || node().is_some()>
                <div class="tiles">
                    {move || node().and_then(free).map(|(kind, label, _)| {
                        let (ico, mode) = match kind {
                            Free::Item | Free::Player => (I::Search, "search"),
                            Free::Qty => (I::Type, "numeric"),
                            _ => (I::Type, "text"),
                        };
                        let hint = match kind {
                            Free::Player => K::HintPlayer,
                            Free::Item => K::HintItem,
                            Free::Qty => K::HintQty,
                            Free::Coords => K::HintCoords,
                            Free::Message => K::HintMessage,
                        };
                        view! {
                            <form class="tile free" on:submit=submit_free>
                                <label class="free-label" for="builder-free">{icon(ico)}<span>{move || ctx.tr(label)}</span></label>
                                <div class="free-row">
                                    <input id="builder-free" autocomplete="off" inputmode=mode
                                        placeholder=move || ctx.tr(hint)
                                        prop:value=move || text.get()
                                        on:input=move |ev| typed(event_target_value(&ev))/>
                                    <button type="submit" class="ok">{move || ctx.tr(K::Ok)}</button>
                                </div>
                            </form>
                        }
                    })}
                    <For each=move || suggestions.get() key=|s| s.value.clone() let:s>
                        {
                            let next = node().and_then(free).and_then(|f| f.2);
                            let step = Step { label: s.label.clone(), value: s.value.clone(), next };
                            view! {
                                <button type="button" class="tile suggestion" on:click=move |_| push(step.clone())>
                                    <crate::theme::ColorDot color=crate::theme::color_for(&s.value) class="tile-dot"/>
                                    <span class="tile-label">{s.label.clone()}</span>
                                    <span class="tile-sub">{s.sub.clone()}</span>
                                </button>
                            }
                        }
                    </For>
                    {move || node().map(|n| tiles(n, &players()).into_iter().map(|t| {
                        let label = tile_label(&t.label);
                        let step = Step { label: label.clone(), value: t.value.clone(), next: t.next };
                        view! {
                            <button type="button" class="tile" on:click=move |_| push(step.clone())>
                                <crate::theme::ColorDot color=t.color.to_string() class="tile-dot"/>
                                <span class="tile-label">{label}</span>
                            </button>
                        }
                    }).collect_view())}
                </div>
            </Show>
            <div class="builder-bar">
                <code class="command" class:empty=move || path.with(Vec::is_empty)>
                    {move || if path.with(Vec::is_empty) { ctx.tr(K::ChooseAction).to_string() } else { command() }}
                </code>
                <button type="button" class="btn icon-btn star" aria-label=move || ctx.tr(K::FavoriteAdd)
                    disabled=move || !done() on:click=star>{icon(I::Star)}</button>
                <button type="button" class="btn" disabled=move || path.with(Vec::is_empty) on:click=move |_| reset()>
                    {move || ctx.tr(K::Clear)}
                </button>
                <button type="button" class="btn primary" disabled=move || !done() || !running.get() || busy.get()
                    title=move || if running.get() { "" } else { ctx.tr(K::ErrNotRunning) }
                    on:click=run>{move || ctx.tr(K::Run)}</button>
            </div>
        </section>
    }
}

// ---------------------------------------------------------------------------------------------
// Console

#[derive(Clone, Copy, PartialEq, Eq)]
enum Filter {
    All,
    Chat,
    Players,
    System,
    Alerts,
}

fn filter_of(e: &ConsoleEvent) -> Filter {
    match e {
        ConsoleEvent::Chat { .. } => Filter::Chat,
        ConsoleEvent::Join { .. } | ConsoleEvent::Leave { .. } | ConsoleEvent::Advancement { .. } => Filter::Players,
        ConsoleEvent::Warn { .. } | ConsoleEvent::Error { .. } | ConsoleEvent::Lag { .. } => Filter::Alerts,
        ConsoleEvent::Manager { what: ManagerNote::Crashed | ManagerNote::Killed | ManagerNote::PortNeverOpened } => {
            Filter::Alerts
        }
        _ => Filter::System,
    }
}

/// Heure locale `HH:MM` d'un instant en millisecondes.
pub fn hhmm(ms: i64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms as f64));
    format!("{:02}:{:02}", d.get_hours(), d.get_minutes())
}

fn note_key(n: ManagerNote) -> K {
    match n {
        ManagerNote::Starting => K::NoteStarting,
        ManagerNote::Stopped => K::NoteStopped,
        ManagerNote::Crashed => K::NoteCrashed,
        ManagerNote::Killed => K::NoteKilled,
        ManagerNote::AutoRestart => K::NoteAutoRestart,
        ManagerNote::PortNeverOpened => K::NotePortNeverOpened,
    }
}

/// Ligne de la vue lisible.
fn readable_row(ctx: Ctx, l: &ConsoleLine) -> Option<AnyView> {
    let e = l.event.as_ref()?;
    let time = hhmm(l.ts);
    let (ico, tone, alert, body): (I, &str, bool, AnyView) = match e.clone() {
        ConsoleEvent::Join { player } => {
            (I::Join, "t-accent", false, view! { <span><b>{player}</b>" " {move || ctx.tr(K::EvJoined)}</span> }.into_any())
        }
        ConsoleEvent::Leave { player } => {
            (I::Leave, "t-faint", false, view! { <span><b>{player}</b>" " {move || ctx.tr(K::EvLeft)}</span> }.into_any())
        }
        ConsoleEvent::Chat { player, text } => (
            I::Chat,
            "t-accent-2",
            false,
            view! { <span class="bubble"><b>{player}</b>" " {text}</span> }.into_any(),
        ),
        ConsoleEvent::Advancement { player, title } => {
            (I::Trophy, "t-gold", false, view! { <span><b>{player}</b>" · " {title}</span> }.into_any())
        }
        ConsoleEvent::Saved => (I::Save, "t-faint", false, view! { <span class="muted">{move || ctx.tr(K::EvSaved)}</span> }.into_any()),
        ConsoleEvent::Lag { ms, ticks } => (
            I::Alert,
            "t-warn",
            true,
            view! {
                <span>{move || format!("{} · {} ms ({ticks} {})", ctx.tr(K::EvLag), crate::fmt_int(ms, ctx.lang.get()), ctx.tr(K::EvTicksSkipped))}</span>
            }
            .into_any(),
        ),
        ConsoleEvent::Ready { ms } => (
            I::Check,
            "t-accent",
            false,
            view! { <span>{move || ctx.tr(K::EvReady)}" · " {move || crate::fmt_secs(ms, ctx.lang.get())}</span> }.into_any(),
        ),
        ConsoleEvent::Stopping => (I::Stop, "t-faint", false, view! { <span class="muted">{move || ctx.tr(K::EvStopping)}</span> }.into_any()),
        ConsoleEvent::Warn { text } => (I::Alert, "t-warn", true, view! { <span>{text}</span> }.into_any()),
        ConsoleEvent::Error { text } => (I::Error, "t-danger", true, view! { <span>{text}</span> }.into_any()),
        ConsoleEvent::Command { user, command } => (
            I::Command,
            "t-accent-2",
            false,
            view! { <span><span class="muted">{user}" › "</span><code>{command}</code></span> }.into_any(),
        ),
        ConsoleEvent::Manager { what } => {
            let alert = matches!(what, ManagerNote::Crashed | ManagerNote::Killed | ManagerNote::PortNeverOpened);
            (
                if alert { I::Alert } else { I::Info },
                if alert { "t-warn" } else { "t-faint" },
                alert,
                view! { <span class="muted">{move || ctx.tr(note_key(what))}</span> }.into_any(),
            )
        }
    };
    Some(
        view! {
            <div class="ev" class:alert=alert>
                <span class="ev-time">{time}</span>
                <span class=format!("ev-ico {tone}")>{icon(ico)}</span>
                {body}
            </div>
        }
        .into_any(),
    )
}

/// Console : vue lisible ou brute, filtres, saisie libre (historique par ↑ et ↓).
#[component]
pub fn ConsoleView(server: i64, #[prop(into)] running: Signal<bool>, msg: RwSignal<Option<K>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let raw = RwSignal::new(crate::storage_get("rcm-console-raw").as_deref() == Some("1"));
    let filter = RwSignal::new(Filter::All);
    let input = RwSignal::new(String::new());
    let history = RwSignal::new(Vec::<String>::new());
    let hist_pos = RwSignal::new(None::<usize>);
    let body = NodeRef::<leptos::html::Div>::new();
    let stick = RwSignal::new(true);
    // Reste collée en bas tant que l'utilisateur n'est pas remonté lire.
    Effect::new(move |_| {
        ctx.lines.track();
        raw.track();
        filter.track();
        if stick.get_untracked()
            && let Some(el) = body.get()
        {
            el.set_scroll_top(el.scroll_height());
        }
    });
    let on_scroll = move |_| {
        if let Some(el) = body.get() {
            stick.set(el.scroll_height() - el.scroll_top() - el.client_height() < 40);
        }
    };
    let alerts = move || {
        ctx.lines
            .with(|l| l.iter().filter(|x| x.event.as_ref().is_some_and(|e| filter_of(e) == Filter::Alerts)).count())
    };
    let send = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let cmd = input.get_untracked();
        if cmd.trim().is_empty() {
            return;
        }
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post_empty(
                &format!("/api/servers/{server}/command"),
                &CommandRequest { command: cmd.clone() },
                csrf.as_deref(),
            )
            .await
            {
                Ok(()) => {
                    msg.set(None);
                    history.update(|h| {
                        h.retain(|x| x != &cmd);
                        h.push(cmd);
                        if h.len() > 50 {
                            h.remove(0);
                        }
                    });
                    hist_pos.set(None);
                    input.set(String::new());
                    stick.set(true);
                }
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    let keys = move |ev: leptos::ev::KeyboardEvent| {
        let h = history.get_untracked();
        if h.is_empty() {
            return;
        }
        let pos = match (ev.key().as_str(), hist_pos.get_untracked()) {
            ("ArrowUp", None) => Some(h.len() - 1),
            ("ArrowUp", Some(p)) => Some(p.saturating_sub(1)),
            ("ArrowDown", Some(p)) if p + 1 < h.len() => Some(p + 1),
            ("ArrowDown", Some(_)) => None,
            _ => return,
        };
        ev.prevent_default();
        hist_pos.set(pos);
        input.set(pos.map(|p| h[p].clone()).unwrap_or_default());
    };
    let set_raw = move |v: bool| {
        raw.set(v);
        crate::storage_set("rcm-console-raw", if v { "1" } else { "0" });
        stick.set(true);
    };
    let chip = move |f: Filter, k: K| {
        view! {
            <button type="button" class="chip-filter" class:on=move || filter.get() == f class:warn=f == Filter::Alerts
                aria-pressed=move || (filter.get() == f).to_string() on:click=move |_| filter.set(f)>
                {move || ctx.tr(k)}
                {move || (f == Filter::Alerts && alerts() > 0).then(|| format!(" · {}", alerts()))}
            </button>
        }
    };
    view! {
        <section class="panel console" aria-label=move || ctx.tr(K::Console)>
            <div class="console-head">
                <div class="segmented small" role="group" aria-label=move || ctx.tr(K::ConsoleView)>
                    <button type="button" class:on=move || !raw.get() aria-pressed=move || (!raw.get()).to_string()
                        on:click=move |_| set_raw(false)>{move || ctx.tr(K::ConsoleReadable)}</button>
                    <button type="button" class:on=move || raw.get() aria-pressed=move || raw.get().to_string()
                        on:click=move |_| set_raw(true)>{move || ctx.tr(K::ConsoleRaw)}</button>
                </div>
                <Show when=move || !raw.get()>
                    <div class="filters" role="group" aria-label=move || ctx.tr(K::Filters)>
                        {chip(Filter::All, K::FilterAll)}
                        {chip(Filter::Chat, K::FilterChat)}
                        {chip(Filter::Players, K::FilterPlayers)}
                        {chip(Filter::System, K::FilterSystem)}
                        {chip(Filter::Alerts, K::FilterAlerts)}
                    </div>
                </Show>
            </div>
            <div class="console-body" class:raw=move || raw.get() node_ref=body on:scroll=on_scroll
                role="log" aria-live="polite" tabindex="0">
                {move || {
                    if raw.get() {
                        ctx.lines.with(|l| l.iter().map(|x| {
                            let cls = match x.source {
                                LineSource::Err => "raw-line err",
                                LineSource::Input => "raw-line input",
                                LineSource::Manager => "raw-line manager",
                                LineSource::Out => "raw-line",
                            };
                            view! { <div class=cls>{x.text.clone()}</div> }
                        }).collect_view()).into_any()
                    } else {
                        let f = filter.get();
                        let rows: Vec<AnyView> = ctx.lines.with(|l| l.iter()
                            .filter(|x| x.event.as_ref().is_some_and(|e| f == Filter::All || filter_of(e) == f))
                            .filter_map(|x| readable_row(ctx, x))
                            .collect());
                        if rows.is_empty() {
                            view! { <p class="console-empty faint">{move || ctx.tr(K::ConsoleEmpty)}</p> }.into_any()
                        } else {
                            rows.into_iter().collect_view().into_any()
                        }
                    }
                }}
            </div>
            <form class="console-input" on:submit=send>
                <span class="prompt" aria-hidden="true">"›"</span>
                <input aria-label=move || ctx.tr(K::FreeCommand) autocomplete="off" spellcheck="false"
                    placeholder=move || ctx.tr(if running.get() { K::FreeCommand } else { K::ErrNotRunning })
                    disabled=move || !running.get()
                    prop:value=move || input.get()
                    on:input=move |ev| { input.set(event_target_value(&ev)); hist_pos.set(None); }
                    on:keydown=keys/>
            </form>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saisies_libres() {
        assert_eq!(free_value(Free::Player, " neo "), Some("neo".into()));
        assert_eq!(free_value(Free::Player, "a b"), None);
        assert_eq!(free_value(Free::Item, "Blue wool"), Some("minecraft:blue_wool".into()));
        assert_eq!(free_value(Free::Item, "minecraft:../x"), None);
        assert_eq!(free_value(Free::Qty, "6401"), None);
        assert_eq!(free_value(Free::Coords, "~ ~1 -20.5"), Some("~ ~1 -20.5".into()));
        assert_eq!(free_value(Free::Coords, "1 2"), None);
        assert_eq!(free_value(Free::Message, "a\nop"), None);
    }
}
