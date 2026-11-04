//! Écrans des serveurs : assistant de création en tuiles (logiciel → version → réglages), page
//! d'un serveur (maquette Main : en-tête, mesures, console, joueurs), réglages et suppression.

use crate::console::{Builder, ConsoleView, Favorites};
use crate::i18n::{K, error_key};
use crate::icons::{I, icon};
use crate::{Ctx, Msg, Page, api, go};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;

pub fn software_icon(s: Software) -> I {
    match s {
        Software::Vanilla => I::Cube,
        Software::Paper => I::Paper,
        Software::Purpur => I::Pillar,
        Software::Folia => I::Leaf,
        Software::Fabric => I::Thread,
        Software::Quilt => I::Patch,
    }
}

fn software_tag(s: Software) -> K {
    match s {
        Software::Vanilla => K::SwOfficial,
        Software::Paper => K::SwPlugins,
        Software::Purpur => K::SwPluginsPlus,
        Software::Folia => K::SwMulticore,
        Software::Fabric | Software::Quilt => K::SwMods,
    }
}

/// Nom affiché d'un logiciel (« Vanilla » se dit « officiel » en français).
pub fn software_name(ctx: Ctx, s: Software) -> &'static str {
    if s == Software::Vanilla { ctx.tr(K::SwVanilla) } else { s.name() }
}

fn step_key(s: OpStep) -> K {
    match s {
        OpStep::Resolve => K::StepResolve,
        OpStep::DownloadServer => K::StepDownloadServer,
        OpStep::DownloadLibraries => K::StepDownloadLibraries,
        OpStep::DownloadJava => K::StepDownloadJava,
        OpStep::Extract => K::StepExtract,
        OpStep::Launch => K::StepLaunch,
        OpStep::WaitPort => K::StepWaitPort,
        OpStep::WaitExit => K::StepWaitExit,
    }
}

/// Classe CSS de l'état (pastille).
pub fn state_class(s: &ServerInfo) -> &'static str {
    if s.op.is_some() && matches!(s.state, ServerState::NotInstalled | ServerState::Stopped | ServerState::Crashed) {
        return "busy";
    }
    match s.state {
        ServerState::Running if s.alert.is_some() => "warn",
        ServerState::Running => "on",
        ServerState::Starting | ServerState::Stopping => "busy",
        ServerState::Crashed => "bad",
        ServerState::NotInstalled if s.error.is_some() => "bad",
        _ => "off",
    }
}

pub fn state_key(s: &ServerInfo) -> K {
    match s.state {
        ServerState::NotInstalled if s.op.is_some() => K::StateInstalling,
        ServerState::NotInstalled => K::StateNotInstalled,
        ServerState::Stopped => K::StateStopped,
        ServerState::Starting => K::StateStarting,
        ServerState::Running => K::StateRunning,
        ServerState::Stopping => K::StateStopping,
        ServerState::Crashed => K::StateCrashed,
    }
}

// ---------------------------------------------------------------------------------------------
// Assistant de création

#[component]
pub fn NewServerPage() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let software = RwSignal::new(None::<Software>);
    let version = RwSignal::new(None::<String>);
    let versions = RwSignal::new(None::<Result<Vec<GameVersion>, K>>);
    let search = RwSignal::new(String::new());
    let all = RwSignal::new(false);
    let load_versions = move |sw: Software| {
        versions.set(None);
        spawn_local(async move {
            let r = api::get::<Vec<GameVersion>>(&format!("/api/catalog/{}", sw.code())).await.map_err(|e| ctx.err(&e));
            if software.get_untracked() == Some(sw) {
                versions.set(Some(r));
            }
        });
    };
    let pick_software = move |sw: Software| {
        software.set(Some(sw));
        version.set(None);
        search.set(String::new());
        all.set(false);
        load_versions(sw);
    };
    let crumbs = move || {
        let mut v: Vec<(String, u8)> = Vec::new();
        if let Some(sw) = software.get() {
            v.push((software_name(ctx, sw).to_string(), 0));
        }
        if let Some(ver) = version.get() {
            v.push((ver, 1));
        }
        v
    };
    let question = move || {
        if software.get().is_none() {
            K::QSoftware
        } else if version.get().is_none() {
            K::QVersion
        } else {
            K::QSettings
        }
    };
    view! {
        <header class="page-head"><h1>{move || ctx.tr(K::NewServer)}</h1></header>
        <section class="panel builder">
            <nav class="crumbs" aria-label=move || ctx.tr(K::BuilderSteps)>
                {move || crumbs().into_iter().map(|(label, level)| view! {
                    <button type="button" class="crumb" on:click=move |_| {
                        version.set(None);
                        if level == 0 {
                            software.set(None);
                        }
                    }>{label}</button>
                    <span class="crumb-sep" aria-hidden="true">"›"</span>
                }).collect_view()}
                <span class="question">{move || ctx.tr(question())}</span>
            </nav>
            <Show when=move || software.get().is_none()>
                <div class="tiles big">
                    {Software::ALL.into_iter().map(|sw| view! {
                        <button type="button" class="tile sw" on:click=move |_| pick_software(sw)>
                            <span class=format!("tile-ico sw-{}", sw.code())>{icon(software_icon(sw))}</span>
                            <span class="tile-label">{move || software_name(ctx, sw)}</span>
                            <span class="tile-sub">{move || ctx.tr(software_tag(sw))}</span>
                        </button>
                    }).collect_view()}
                </div>
            </Show>
            <Show when=move || software.get().is_some() && version.get().is_none()>
                {move || match versions.get() {
                    None => view! {
                        <div class="tiles">{(0..8).map(|_| view! { <span class="tile skeleton"></span> }).collect_view()}</div>
                    }.into_any(),
                    Some(Err(k)) => view! {
                        <div class="state-block">
                            <p class="error" role="alert">{move || ctx.tr(k)}</p>
                            <button type="button" class="btn" on:click=move |_| { if let Some(sw) = software.get_untracked() { load_versions(sw) } }>
                                {move || ctx.tr(K::Retry)}
                            </button>
                        </div>
                    }.into_any(),
                    Some(Ok(list)) => {
                        let list = StoredValue::new(list);
                        let shown = move || {
                            let q = search.get().trim().to_lowercase();
                            list.with_value(|l| {
                                let v: Vec<GameVersion> = l.iter().filter(|v| q.is_empty() || v.id.to_lowercase().contains(&q)).cloned().collect();
                                if all.get() || !q.is_empty() { v } else { v.into_iter().filter(|x| x.stable).take(11).collect() }
                            })
                        };
                        let latest = list.with_value(|l| l.iter().find(|v| v.stable).map(|v| v.id.clone()));
                        view! {
                            <div class="tiles">
                                <label class="tile free search-tile">
                                    <span class="free-label">{icon(I::Search)}<span>{move || ctx.tr(K::SearchVersion)}</span></span>
                                    <input inputmode="decimal" autocomplete="off" placeholder="1.21.11"
                                        prop:value=move || search.get() on:input=move |ev| search.set(event_target_value(&ev))/>
                                </label>
                                <For each=shown key=|v| v.id.clone() let:v>
                                    {
                                        let id = v.id.clone();
                                        let is_latest = latest.as_deref() == Some(v.id.as_str());
                                        view! {
                                            <button type="button" class="tile version" class:latest=is_latest on:click=move |_| version.set(Some(id.clone()))>
                                                <span class="tile-label mono">{v.id.clone()}</span>
                                                <span class="tile-sub">{move || if is_latest { ctx.tr(K::Latest) } else if v.stable { "" } else { ctx.tr(K::Preview) }}</span>
                                            </button>
                                        }
                                    }
                                </For>
                                <Show when=move || !all.get() && search.with(String::is_empty) && list.with_value(|l| l.iter().filter(|x| x.stable).count() > 11)>
                                    <button type="button" class="tile more" on:click=move |_| all.set(true)>
                                        <span class="tile-label">{move || ctx.tr(K::AllVersions)}</span>
                                        <span class="tile-sub">{move || list.with_value(|l| l.len().to_string())}</span>
                                    </button>
                                </Show>
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
            {move || match (software.get(), version.get()) {
                (Some(sw), Some(v)) => view! { <CreateForm software=sw version=v/> }.into_any(),
                _ => ().into_any(),
            }}
        </section>
    }
}

/// Port libre suivant parmi ceux des serveurs déjà créés.
fn next_port(list: &[ServerInfo]) -> u16 {
    let mut p = DEFAULT_GAME_PORT;
    while list.iter().any(|s| s.port == p) {
        p += 1;
    }
    p
}

#[component]
fn CreateForm(software: Software, version: String) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let name = RwSignal::new(format!("{} {}", software_name(ctx, software), version));
    let memory = RwSignal::new(2048u32);
    let port = RwSignal::new(ctx.servers.with_untracked(|l| next_port(l)).to_string());
    let eula = RwSignal::new(false);
    let java = RwSignal::new(String::new());
    let javas = RwSignal::new(Vec::<JavaInfo>::new());
    let msg = RwSignal::new(None::<K>);
    let busy = RwSignal::new(false);
    let is_admin = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.is_admin));
    if is_admin() {
        spawn_local(async move {
            if let Ok(v) = api::get::<Vec<JavaInfo>>("/api/java").await {
                javas.set(v.into_iter().filter(|j| !j.managed).collect());
            }
        });
    }
    let version2 = version.clone();
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if !server_name_valid(&name.get_untracked()) {
            msg.set(Some(K::ErrInvalidName));
            return;
        }
        let Ok(p) = port.get_untracked().trim().parse::<u16>() else {
            msg.set(Some(K::ErrInvalidPort));
            return;
        };
        let j = java.get_untracked();
        let req = CreateServerRequest {
            name: name.get_untracked().trim().to_string(),
            software,
            version: version2.clone(),
            memory_mb: memory.get_untracked(),
            port: p,
            java: if j.is_empty() { JavaChoice::Managed } else { JavaChoice::Path { path: j } },
            accept_eula: eula.get_untracked(),
        };
        busy.set(true);
        msg.set(None);
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post::<_, ServerInfo>("/api/servers", &req, csrf.as_deref()).await {
                Ok(s) => {
                    ctx.servers.update(|l| {
                        if !l.iter().any(|x| x.id == s.id) {
                            l.push(s.clone());
                        }
                    });
                    go(ctx, Page::Server(s.id));
                }
                Err(e) => ctx.on_err(&e, msg),
            }
            busy.set(false);
        });
    };
    view! {
        <form class="create-form" on:submit=submit>
            <label class="field">
                <span class="field-label">{move || ctx.tr(K::ServerName)}</span>
                <input required maxlength="48" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/>
            </label>
            <div class="field" role="radiogroup" aria-label=move || ctx.tr(K::Memory)>
                <span class="field-label">{move || ctx.tr(K::Memory)}</span>
                <div class="chips">
                    {[1024u32, 2048, 4096, 8192].into_iter().map(|m| view! {
                        <button type="button" role="radio" class="chip-pick" class:on=move || memory.get() == m
                            aria-checked=move || (memory.get() == m).to_string()
                            on:click=move |_| memory.set(m)>{move || crate::fmt_mb(m, ctx.lang.get())}</button>
                    }).collect_view()}
                    <input class="mem-input" type="number" min="512" max="65536" step="256" aria-label=move || ctx.tr(K::MemoryMb)
                        prop:value=move || memory.get().to_string()
                        on:input=move |ev| if let Ok(v) = event_target_value(&ev).parse() { memory.set(v) }/>
                    <span class="faint">{move || ctx.tr(K::UnitMb)}</span>
                </div>
            </div>
            <label class="field narrow">
                <span class="field-label">{move || ctx.tr(K::Port)}</span>
                <input inputmode="numeric" required prop:value=move || port.get() on:input=move |ev| port.set(event_target_value(&ev))/>
            </label>
            <Show when=move || is_admin() && javas.with(|j| !j.is_empty())>
                <label class="field">
                    <span class="field-label">{move || ctx.tr(K::Java)}</span>
                    <select on:change=move |ev| java.set(event_target_value(&ev))>
                        <option value="">{move || ctx.tr(K::JavaManaged)}</option>
                        {move || javas.get().into_iter().map(|j| view! {
                            <option value=j.path.clone()>{format!("Java {} · {}", j.major, j.path)}</option>
                        }).collect_view()}
                    </select>
                </label>
            </Show>
            <label class="check">
                <input type="checkbox" prop:checked=move || eula.get() on:change=move |ev| eula.set(event_target_checked(&ev))/>
                <span>{move || ctx.tr(K::EulaAccept)}" "
                    <a href="https://aka.ms/MinecraftEULA" target="_blank" rel="noopener noreferrer">{move || ctx.tr(K::EulaLink)}</a>
                </span>
            </label>
            <Msg msg=msg/>
            <div class="row">
                <button type="submit" class="btn primary" disabled=move || busy.get()>{icon(I::Plus)}{move || ctx.tr(K::Create)}</button>
            </div>
        </form>
    }
}

// ---------------------------------------------------------------------------------------------
// Page d'un serveur

/// Courbe fine (sparkline) des dernières valeurs.
#[component]
fn Spark(#[prop(into)] values: Signal<Vec<f32>>, #[prop(optional)] second: bool) -> impl IntoView {
    let points = move || {
        let v = values.get();
        if v.len() < 2 {
            return "0,14 120,14".to_string();
        }
        let (lo, hi) = v.iter().fold((f32::MAX, f32::MIN), |(a, b), &x| (a.min(x), b.max(x)));
        let span = (hi - lo).max(hi.abs() * 0.1).max(0.001);
        let n = v.len() as f32 - 1.0;
        v.iter()
            .enumerate()
            .map(|(i, x)| format!("{:.1},{:.1}", i as f32 * 120.0 / n, 24.0 - (x - lo) / span * 20.0))
            .collect::<Vec<_>>()
            .join(" ")
    };
    view! {
        <svg class="spark" class:second=second class:idle=move || values.with(|v| v.len() < 2) viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true">
            <polyline fill="none" points=points/>
        </svg>
    }
}

#[component]
fn Metrics(#[prop(into)] info: Signal<Option<ServerInfo>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let running = move || info.with(|i| i.as_ref().is_some_and(|i| i.state == ServerState::Running));
    let last = move || ctx.stats.with(|s| s.last().cloned());
    let series = move |f: fn(&ServerStats) -> Option<f32>| {
        Signal::derive(move || ctx.stats.with(|s| s.iter().filter_map(f).collect::<Vec<f32>>()))
    };
    let dash = "—";
    let waiting = move || running() && last().is_none();
    let metric = move |label: K, value: Box<dyn Fn() -> String + Send + Sync>, spark: AnyView| {
        view! {
            <div class="metric" class:loading=waiting>
                <span class="metric-label">{move || ctx.tr(label)}</span>
                <span class="metric-value">{value}</span>
                {spark}
            </div>
        }
    };
    let lang = move || ctx.lang.get();
    view! {
        <section class="metrics" aria-label=move || ctx.tr(K::Performance)>
            {metric(K::MetricTps, Box::new(move || match (running(), last().and_then(|s| s.tps)) {
                (true, Some(t)) => crate::fmt_dec(t, 1, lang()),
                _ => dash.into(),
            }), view! { <Spark values=series(|s| s.tps)/> }.into_any())}
            {metric(K::MetricMspt, Box::new(move || match (running(), last().and_then(|s| s.mspt)) {
                (true, Some(t)) => format!("{} ms", crate::fmt_dec(t, 1, lang())),
                _ => dash.into(),
            }), view! { <Spark values=series(|s| s.mspt)/> }.into_any())}
            {metric(K::MetricPlayers, Box::new(move || info.with(|i| match i {
                Some(i) if i.state == ServerState::Running => format!("{} / {}", i.players, i.max_players),
                _ => dash.into(),
            })), view! { <Spark values=Signal::derive(move || ctx.player_series.get()) second=true/> }.into_any())}
            <div class="metric" class:loading=waiting>
                <span class="metric-label">{move || ctx.tr(K::MetricCpu)}
                    // Cœurs occupés sur les cœurs disponibles : détail discret à côté du libellé.
                    {move || match (running(), last().and_then(|s| s.cores_used.zip(s.cores))) {
                        (true, Some((u, n))) => view! {
                            <span class="metric-detail">{format!("{} / {n} {}", crate::fmt_dec(u, 1, lang()), ctx.tr(K::Cores))}</span>
                        }.into_any(),
                        _ => ().into_any(),
                    }}
                </span>
                <span class="metric-value">{move || match (running(), last().and_then(|s| s.cpu)) {
                    (true, Some(c)) => format!("{} %", crate::fmt_dec(c, if c < 10.0 { 1 } else { 0 }, lang())),
                    _ => dash.into(),
                }}</span>
                <Spark values=series(|s| s.cpu)/>
            </div>
            {metric(K::MetricMemory, Box::new(move || match (running(), last().and_then(|s| s.memory)) {
                (true, Some(m)) => crate::fmt_bytes(m, lang()),
                _ => dash.into(),
            }), view! {
                <MemBar used=Signal::derive(move || if running() { last().and_then(|s| s.memory) } else { None })
                    max=Signal::derive(move || info.with(|i| i.as_ref().map_or(1, |i| i.memory_mb as u64 * 1024 * 1024)))/>
            }.into_any())}
        </section>
    }
}

/// Barre de mémoire (proportion posée par le CSSOM).
#[component]
fn MemBar(#[prop(into)] used: Signal<Option<u64>>, #[prop(into)] max: Signal<u64>) -> impl IntoView {
    let fill = NodeRef::<leptos::html::Span>::new();
    Effect::new(move |_| {
        let pct = used.get().map_or(0.0, |u| (u as f64 / max.get().max(1) as f64 * 100.0).clamp(0.0, 100.0));
        if let Some(el) = fill.get() {
            let _ = web_sys::HtmlElement::style(&el).set_property("width", &format!("{pct:.1}%"));
        }
    });
    view! { <span class="membar" aria-hidden="true"><span class="membar-fill" node_ref=fill></span></span> }
}

#[component]
fn PlayersAside() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    view! {
        <aside class="panel players" aria-label=move || ctx.tr(K::PlayersOnline)>
            <h2 class="panel-title">{move || ctx.tr(K::PlayersOnline)}</h2>
            <Show when=move || ctx.players.with(Vec::is_empty)>
                <p class="faint">{move || ctx.tr(K::NobodyOnline)}</p>
            </Show>
            <For each=move || ctx.players.get() key=|p| p.name.clone() let:p>
                <div class="player">
                    <crate::theme::ColorDot color=crate::theme::color_for(&p.name) class="avatar"/>
                    <span class="player-name">{p.name.clone()}</span>
                    <span class="faint num">{move || p.since.map(|s| crate::fmt_duration(ctx.now.get() - s, ctx.lang.get())).unwrap_or_default()}</span>
                </div>
            </For>
        </aside>
    }
}

#[component]
pub fn ServerPage(id: i64) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let info = Memo::new(move |_| ctx.servers.with(|l| l.iter().find(|s| s.id == id).cloned()));
    let msg = RwSignal::new(None::<K>);
    let favorites = RwSignal::new(Vec::<Favorite>::new());
    let settings = RwSignal::new(false);
    ctx.watch(id);
    on_cleanup(move || ctx.unwatch(id));
    spawn_local(async move {
        if let Ok(f) = api::get::<Vec<Favorite>>(&format!("/api/servers/{id}/favorites")).await {
            favorites.set(f);
        }
    });
    let running = Signal::derive(move || info.with(|i| i.as_ref().is_some_and(|i| i.state == ServerState::Running)));
    let busy = move || info.with(|i| i.as_ref().is_some_and(|i| i.op.is_some()));
    let action = move |what: &'static str| {
        let csrf = ctx.csrf();
        msg.set(None);
        spawn_local(async move {
            match api::post::<_, ServerInfo>(
                &format!("/api/servers/{id}/{what}"),
                &serde_json::Map::new(),
                csrf.as_deref(),
            )
            .await
            {
                Ok(s) => ctx.servers.update(|l| {
                    if let Some(x) = l.iter_mut().find(|x| x.id == s.id) {
                        *x = s;
                    }
                }),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    let sub = move || {
        info.with(|i| {
            let Some(i) = i else { return String::new() };
            let state = match i.state {
                ServerState::Running => match i.started_at {
                    Some(t) => {
                        format!("{} {}", ctx.tr(K::OnlineFor), crate::fmt_duration(ctx.now.get() - t, ctx.lang.get()))
                    }
                    None => ctx.tr(K::StateRunning).to_string(),
                },
                _ => ctx.tr(state_key(i)).to_string(),
            };
            format!("{} {} · {} · :{}", software_name(ctx, i.software), i.version, state, i.port)
        })
    };
    view! {
        <Show when=move || info.with(Option::is_some) fallback=move || view! {
            // « N'existe plus » seulement si la liste a vraiment été reçue.
            <Show when=move || ctx.servers_loaded.get() fallback=move || view! {
                <Show when=move || ctx.live_down() fallback=|| view! { <div class="hero-skeleton skeleton"></div> }>
                    <crate::LiveNotice/>
                </Show>
            }>
                <div class="state-block"><p class="faint">{move || ctx.tr(K::ServerGone)}</p></div>
            </Show>
        }>
            <header class="page-head">
                <div class="head-text">
                    <h1>{move || info.with(|i| i.as_ref().map(|i| i.name.clone()).unwrap_or_default())}</h1>
                    <div class="sub">
                        <span class=move || format!("dot {}", info.with(|i| i.as_ref().map_or("off", state_class)))></span>
                        {sub}
                    </div>
                </div>
                <div class="head-actions">
                    <button type="button" class="btn icon-btn" aria-label=move || ctx.tr(K::Settings) on:click=move |_| settings.set(true)>
                        {icon(I::Gear)}
                    </button>
                    {move || {
                        let st = info.with(|i| i.as_ref().map(|i| i.state));
                        match st {
                            Some(ServerState::Running | ServerState::Starting | ServerState::Stopping) => view! {
                                <button type="button" class="btn" disabled=busy on:click=move |_| action("restart")>
                                    {icon(I::Restart)}{move || ctx.tr(K::Restart)}
                                </button>
                                <button type="button" class="btn stop" disabled=move || busy() || st == Some(ServerState::Stopping)
                                    on:click=move |_| action("stop")>{icon(I::Stop)}{move || ctx.tr(K::Stop)}</button>
                            }.into_any(),
                            Some(ServerState::Stopped | ServerState::Crashed) => view! {
                                <button type="button" class="btn primary" disabled=busy on:click=move |_| action("start")>
                                    {icon(I::Play)}{move || ctx.tr(K::Start)}
                                </button>
                            }.into_any(),
                            _ => ().into_any(),
                        }
                    }}
                </div>
            </header>
            <Banners info=Signal::derive(move || info.get()) msg=msg/>
            <Msg msg=msg/>
            <Show when=move || info.with(|i| i.as_ref().is_some_and(|i| i.state != ServerState::NotInstalled))>
            <nav class="tabs" aria-label=move || ctx.tr(K::Navigation)>
                {[
                    (Page::Server(id), I::Command, K::TabConsole),
                    (Page::ServerConfig(id), I::Sliders, K::TabSettings),
                    (Page::ServerPlayers(id), I::Users, K::TabPlayers),
                    (Page::ServerFiles(id), I::Folder, K::TabFiles),
                    (Page::ServerAddress(id), I::At, K::TabAddress),
                ].into_iter().map(|(page, ico, label)| {
                    let on = move || ctx.page.get() == page;
                    view! {
                        <a href=page.path() class="tab" class:on=on aria-current=move || on().then_some("page")
                            on:click=move |ev: leptos::ev::MouseEvent| { ev.prevent_default(); crate::nav(ctx, page); }>
                            {icon(ico)}<span>{move || ctx.tr(label)}</span>
                        </a>
                    }
                }).collect_view()}
            </nav>
            {move || match ctx.page.get() {
                Page::ServerConfig(_) => Some(view! { <crate::configs::ConfigTab id=id info=Signal::derive(move || info.get())/> }.into_any()),
                Page::ServerPlayers(_) => Some(view! { <crate::players::PlayersTab id=id info=Signal::derive(move || info.get())/> }.into_any()),
                Page::ServerFiles(_) => Some(view! { <crate::files::FilesTab id=id info=Signal::derive(move || info.get())/> }.into_any()),
                Page::ServerAddress(_) => Some(view! { <crate::address::AddressTab id=id/> }.into_any()),
                _ => None,
            }}
            <Show when=move || ctx.page.get() == Page::Server(id)>
            <Metrics info=Signal::derive(move || info.get())/>
            <Favorites server=id favorites=favorites msg=msg/>
            <Builder server=id favorites=favorites running=running msg=msg/>
            <div class="console-row">
                <ConsoleView server=id running=running msg=msg/>
                <PlayersAside/>
            </div>
            </Show>
            </Show>
            <Show when=move || settings.get()>
                <SettingsPanel id=id info=Signal::derive(move || info.get()) open=settings/>
            </Show>
        </Show>
    }
}

/// Bandeaux : installation ou téléchargement en cours (progression), erreurs, alertes, EULA.
#[component]
fn Banners(#[prop(into)] info: Signal<Option<ServerInfo>>, msg: RwSignal<Option<K>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let accept = move |_| {
        let Some(id) = info.with_untracked(|i| i.as_ref().map(|i| i.id)) else { return };
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post::<_, ServerInfo>(
                &format!("/api/servers/{id}/eula"),
                &EulaRequest { accept: true },
                csrf.as_deref(),
            )
            .await
            {
                Ok(s) => ctx.servers.update(|l| {
                    if let Some(x) = l.iter_mut().find(|x| x.id == s.id) {
                        *x = s;
                    }
                }),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    let checked = RwSignal::new(false);
    let retry = move |_| {
        let Some(id) = info.with_untracked(|i| i.as_ref().map(|i| i.id)) else { return };
        let csrf = ctx.csrf();
        spawn_local(async move {
            if let Err(e) = api::post::<_, ServerInfo>(
                &format!("/api/servers/{id}/install"),
                &serde_json::Map::new(),
                csrf.as_deref(),
            )
            .await
            {
                ctx.on_err(&e, msg);
            }
        });
    };
    view! {
        {move || info.get().map(|i| {
            let mut out: Vec<AnyView> = Vec::new();
            if let Some(op) = i.op.clone() {
                let pct = match (op.done, op.total) {
                    (Some(d), Some(t)) if t > 0 => Some((d as f64 / t as f64 * 100.0).min(100.0)),
                    _ => None,
                };
                let java = i.java_major;
                out.push(view! {
                    <div class="banner progress" role="status">
                        <span class="spinner" aria-hidden="true"></span>
                        <span>{move || {
                            let s = ctx.tr(step_key(op.step));
                            let s = if op.step == OpStep::DownloadJava { format!("{s} {java}") } else { s.to_string() };
                            match pct { Some(p) => format!("{s} · {p:.0} %"), None => s }
                        }}</span>
                        <ProgressBar pct=pct/>
                    </div>
                }.into_any());
            }
            if let (ServerState::NotInstalled, None, Some(e)) = (i.state, &i.op, i.error) {
                out.push(view! {
                    <div class="banner bad" role="alert">
                        {icon(I::Error)}
                        <span>{move || ctx.tr(K::InstallFailed)}" · " {move || ctx.tr(error_key(e))}</span>
                        <button type="button" class="btn small" on:click=retry>{move || ctx.tr(K::Retry)}</button>
                    </div>
                }.into_any());
            } else if let (Some(ErrorCode::LaunchRefused), None, Some(r)) = (i.error, &i.op, i.refusal.clone()) {
                // Fichier et cause nommés : quoi corriger avant de redémarrer.
                let cause = match r.cause {
                    LaunchCause::Unreadable => K::LaunchUnreadable,
                    LaunchCause::UnsafeValue => K::LaunchUnsafe,
                    LaunchCause::Unverifiable(u) => crate::configs::unverifiable_key(u),
                };
                let key = r.key.map(|k| format!(" ({k})")).unwrap_or_default();
                out.push(view! {
                    <div class="banner bad" role="alert">{icon(I::Error)}
                        <span><code>{r.file}</code>{key}" : "{move || ctx.tr(cause)}" · "{move || ctx.tr(K::LaunchRefusedTail)}</span>
                    </div>
                }.into_any());
            } else if let (Some(e), None) = (i.error, &i.op) {
                out.push(view! {
                    <div class="banner bad" role="alert">{icon(I::Error)}<span>{move || ctx.tr(error_key(e))}</span></div>
                }.into_any());
            }
            match i.alert {
                Some(ServerAlert::PortNeverOpened) => out.push(view! {
                    <div class="banner warn" role="alert">{icon(I::Alert)}<span>{move || ctx.tr(K::AlertPortNeverOpened)}</span></div>
                }.into_any()),
                Some(ServerAlert::CrashLoop) => out.push(view! {
                    <div class="banner bad" role="alert">{icon(I::Alert)}<span>{move || ctx.tr(K::AlertCrashLoop)}</span></div>
                }.into_any()),
                _ => {}
            }
            if !i.eula {
                out.push(view! {
                    <div class="banner eula">
                        {icon(I::Info)}
                        <label class="check">
                            <input type="checkbox" prop:checked=move || checked.get() on:change=move |ev| checked.set(event_target_checked(&ev))/>
                            <span>{move || ctx.tr(K::EulaAccept)}" "
                                <a href="https://aka.ms/MinecraftEULA" target="_blank" rel="noopener noreferrer">{move || ctx.tr(K::EulaLink)}</a>
                            </span>
                        </label>
                        <button type="button" class="btn small primary" disabled=move || !checked.get() on:click=accept>
                            {move || ctx.tr(K::Confirm)}
                        </button>
                    </div>
                }.into_any());
            }
            out.into_iter().collect_view()
        })}
    }
}

#[component]
fn ProgressBar(pct: Option<f64>) -> impl IntoView {
    let fill = NodeRef::<leptos::html::Span>::new();
    Effect::new(move |_| {
        if let (Some(el), Some(p)) = (fill.get(), pct) {
            let _ = web_sys::HtmlElement::style(&el).set_property("width", &format!("{p:.1}%"));
        }
    });
    view! {
        <span class="pbar" class:indeterminate=pct.is_none() aria-hidden="true"><span class="pbar-fill" node_ref=fill></span></span>
    }
}

/// Réglages du serveur (panneau) et suppression (nom recopié + ré-authentification).
#[component]
fn SettingsPanel(id: i64, #[prop(into)] info: Signal<Option<ServerInfo>>, open: RwSignal<bool>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let cur = info.get_untracked();
    let name = RwSignal::new(cur.as_ref().map(|i| i.name.clone()).unwrap_or_default());
    let memory = RwSignal::new(cur.as_ref().map_or(2048, |i| i.memory_mb).to_string());
    let port = RwSignal::new(cur.as_ref().map_or(DEFAULT_GAME_PORT, |i| i.port).to_string());
    let auto = RwSignal::new(cur.as_ref().is_some_and(|i| i.auto_restart));
    let java = cur.as_ref().map(|i| i.java.clone()).unwrap_or_default();
    let msg = RwSignal::new(None::<K>);
    let ok = RwSignal::new(None::<K>);
    let busy = RwSignal::new(false);
    let save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let (Ok(m), Ok(p)) = (memory.get_untracked().trim().parse::<u32>(), port.get_untracked().trim().parse::<u16>())
        else {
            msg.set(Some(K::ErrInvalidInput));
            return;
        };
        let req = ServerSettingsRequest {
            name: name.get_untracked(),
            memory_mb: m,
            port: p,
            auto_restart: auto.get_untracked(),
            java: java.clone(),
        };
        busy.set(true);
        ok.set(None);
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post::<_, ServerInfo>(&format!("/api/servers/{id}/settings"), &req, csrf.as_deref()).await {
                Ok(s) => {
                    msg.set(None);
                    ok.set(Some(K::SavedPlain));
                    ctx.servers.update(|l| {
                        if let Some(x) = l.iter_mut().find(|x| x.id == s.id) {
                            *x = s;
                        }
                    });
                }
                Err(e) => ctx.on_err(&e, msg),
            }
            busy.set(false);
        });
    };
    // Suppression.
    let confirm = RwSignal::new(String::new());
    let pw = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let del_msg = RwSignal::new(None::<K>);
    let totp_on = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
    let name_ok = move || info.with(|i| i.as_ref().is_some_and(|i| i.name.trim() == confirm.get().trim()));
    let delete = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let req = DeleteServerRequest {
            reauth: Reauth { password: pw.get_untracked(), code: totp_on().then(|| code.get_untracked()) },
            confirm_name: confirm.get_untracked(),
        };
        busy.set(true);
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post_empty(&format!("/api/servers/{id}/delete"), &req, csrf.as_deref()).await {
                Ok(()) => {
                    open.set(false);
                    go(ctx, Page::Servers);
                }
                Err(e) => ctx.on_err(&e, del_msg),
            }
            pw.set(String::new());
            code.set(String::new());
            busy.set(false);
        });
    };
    view! {
        <div class="overlay" on:click=move |_| open.set(false)></div>
        <aside class="sheet" role="dialog" aria-modal="true" aria-label=move || ctx.tr(K::Settings)>
            <div class="sheet-head">
                <h2>{move || ctx.tr(K::Settings)}</h2>
                <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::Close) on:click=move |_| open.set(false)>{icon(I::Close)}</button>
            </div>
            <form class="stack" on:submit=save>
                <label class="field">
                    <span class="field-label">{move || ctx.tr(K::ServerName)}</span>
                    <input required maxlength="48" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/>
                </label>
                <div class="two">
                    <label class="field">
                        <span class="field-label">{move || ctx.tr(K::MemoryMb)}</span>
                        <input type="number" min="512" max="65536" step="256" prop:value=move || memory.get() on:input=move |ev| memory.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">{move || ctx.tr(K::Port)}</span>
                        <input inputmode="numeric" prop:value=move || port.get() on:input=move |ev| port.set(event_target_value(&ev))/>
                    </label>
                </div>
                <label class="switch">
                    <input type="checkbox" role="switch" prop:checked=move || auto.get() on:change=move |ev| auto.set(event_target_checked(&ev))/>
                    <span class="switch-track" aria-hidden="true"></span>
                    <span>{move || ctx.tr(K::AutoRestart)}</span>
                </label>
                <p class="faint small">{move || ctx.tr(K::NextStartHint)}</p>
                <Msg msg=msg/>
                <Msg msg=ok ok=true/>
                <div class="row"><button type="submit" class="btn primary" disabled=move || busy.get()>{move || ctx.tr(K::Save)}</button></div>
            </form>
            <form class="stack danger-zone" on:submit=delete>
                <h3>{move || ctx.tr(K::DeleteServer)}</h3>
                <label class="field">
                    <span class="field-label">{move || ctx.tr(K::TypeNameToConfirm)}</span>
                    <input autocomplete="off" placeholder=move || info.with(|i| i.as_ref().map(|i| i.name.clone()).unwrap_or_default())
                        prop:value=move || confirm.get() on:input=move |ev| confirm.set(event_target_value(&ev))/>
                </label>
                <label class="field">
                    <span class="field-label">{move || ctx.tr(K::Password)}</span>
                    <input type="password" autocomplete="current-password" required prop:value=move || pw.get() on:input=move |ev| pw.set(event_target_value(&ev))/>
                </label>
                <Show when=totp_on>
                    <label class="field">
                        <span class="field-label">{move || ctx.tr(K::TotpCode)}</span>
                        <input autocomplete="one-time-code" required prop:value=move || code.get() on:input=move |ev| code.set(event_target_value(&ev))/>
                    </label>
                </Show>
                <Msg msg=del_msg/>
                <div class="row">
                    <button type="submit" class="btn danger" disabled=move || busy.get() || !name_ok()>{icon(I::Trash)}{move || ctx.tr(K::Delete)}</button>
                </div>
            </form>
        </aside>
    }
}

/// Accueil sans serveur.
#[component]
pub fn NoServers() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    view! {
        <div class="empty-hero">
            <span class="hero-ico">{icon(I::Logo)}</span>
            <p class="muted">{move || ctx.tr(K::ServersEmpty)}</p>
            <button type="button" class="btn primary" on:click=move |_| crate::nav(ctx, Page::NewServer)>{icon(I::Plus)}{move || ctx.tr(K::NewServer)}</button>
        </div>
    }
}
