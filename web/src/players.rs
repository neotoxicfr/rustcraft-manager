//! Onglet « Joueurs » d'un serveur : liste blanche, opérateurs, joueurs et adresses bannis, en
//! visuel (listes, ajout avec suggestions à la frappe) ou en JSON (fichiers du jeu, même éditeur
//! que les réglages). Serveur en marche : le gestionnaire passe par la console (immédiat) ;
//! arrêté : il écrit le fichier.

use crate::api;
use crate::i18n::K;
use crate::icons::{I, icon};
use crate::{Ctx, Msg};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Visual,
    Json,
}

fn entries(st: &AccessState, l: AccessList) -> &Vec<AccessEntry> {
    match l {
        AccessList::Whitelist => &st.whitelist,
        AccessList::Ops => &st.ops,
        AccessList::BannedPlayers => &st.banned_players,
        AccessList::BannedIps => &st.banned_ips,
    }
}

fn list_key(l: AccessList) -> K {
    match l {
        AccessList::Whitelist => K::ListWhitelist,
        AccessList::Ops => K::ListOps,
        AccessList::BannedPlayers => K::ListBannedPlayers,
        AccessList::BannedIps => K::ListBannedIps,
    }
}

fn list_icon(l: AccessList) -> (I, &'static str) {
    match l {
        AccessList::Whitelist => (I::ListCheck, "t-accent"),
        AccessList::Ops => (I::Crown, "t-gold"),
        AccessList::BannedPlayers => (I::Ban, "t-danger"),
        AccessList::BannedIps => (I::Globe, "t-warn"),
    }
}

/// Tête d'un joueur : initiale sur une couleur stable tirée du pseudo (aucun appel externe).
#[component]
fn Head(name: String) -> impl IntoView {
    let el = NodeRef::<leptos::html::Span>::new();
    let color = crate::theme::color_for(&name);
    Effect::new(move |_| {
        if let Some(e) = el.get() {
            let _ = web_sys::HtmlElement::style(&e).set_property("--dot", &color);
        }
    });
    let initial = name.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_default();
    view! { <span class="head" node_ref=el aria-hidden="true">{initial}</span> }
}

/// Durées de bannissement proposées (secondes ; `None` : définitif).
const DURATIONS: [(Option<i64>, K); 5] = [
    (None, K::Forever),
    (Some(3600), K::Hour1),
    (Some(86_400), K::Day1),
    (Some(7 * 86_400), K::Days7),
    (Some(30 * 86_400), K::Days30),
];

fn level_key(n: u8) -> K {
    match n {
        1 => K::OpLevel1,
        2 => K::OpLevel2,
        3 => K::OpLevel3,
        _ => K::OpLevel4,
    }
}

#[derive(Clone, Copy)]
struct Act {
    id: i64,
    state: RwSignal<Option<AccessState>>,
    msg: RwSignal<Option<K>>,
    note: RwSignal<Option<K>>,
    pending: RwSignal<bool>,
}

/// Entrée attendue après une commande de console : liste, pseudo ou adresse, présente ou non.
type Expect = Option<(AccessList, String, bool)>;

fn has_entry(s: &AccessState, l: AccessList, who: &str) -> bool {
    entries(s, l).iter().any(|e| {
        [&e.name, &e.uuid, &e.ip].into_iter().any(|v| v.as_deref().is_some_and(|v| v.eq_ignore_ascii_case(who)))
    })
}

impl Act {
    fn load(self) {
        self.load_then(None);
    }

    /// Relit l'état ; `expect` : la commande envoyée doit s'y voir, sinon le jeu l'a refusée
    /// (pseudo inconnu en online-mode…) et on le dit.
    fn load_then(self, expect: Expect) {
        let id = self.id;
        spawn_local(async move {
            match api::get::<AccessState>(&format!("/api/servers/{id}/access")).await {
                Ok(s) => {
                    if let Some((l, who, present)) = &expect
                        && has_entry(&s, *l, who) != *present
                    {
                        self.note.set(None);
                        self.msg.set(Some(K::EntryMissing));
                    }
                    self.state.set(Some(s));
                }
                Err(e) => {
                    let ctx = expect_context::<Ctx>();
                    ctx.on_err(&e, self.msg);
                }
            }
        });
    }

    fn post<B: serde::Serialize + 'static>(
        self,
        ctx: Ctx,
        what: &'static str,
        body: B,
        expect: Expect,
        done: impl Fn() + 'static,
    ) {
        let (id, csrf) = (self.id, ctx.csrf());
        self.pending.set(true);
        self.msg.set(None);
        self.note.set(None);
        spawn_local(async move {
            let r = api::post::<_, AccessApplied>(&format!("/api/servers/{id}/access/{what}"), &body, csrf.as_deref())
                .await;
            self.pending.set(false);
            match r {
                Ok(a) => {
                    // Console : la commande est envoyée, son effet se voit au rechargement.
                    self.note.set(Some(if a.by_console { K::CommandSent } else { K::AppliedFile }));
                    done();
                    self.load();
                    // Le jeu réécrit son fichier juste après la commande.
                    if a.by_console {
                        // (Paper 26.3 mesuré : ≈ 1 s pour résoudre le pseudo puis écrire.)
                        set_timeout(move || self.load(), Duration::from_millis(1200));
                        set_timeout(move || self.load_then(expect.clone()), Duration::from_millis(4000));
                    }
                }
                Err(e) => {
                    // Interrupteurs et cases reprennent la valeur réelle (rien n'a changé).
                    self.state.update(|_| {});
                    ctx.on_err(&e, self.msg)
                }
            }
        });
    }
}

#[component]
pub fn PlayersTab(id: i64, #[prop(into)] info: Signal<Option<ServerInfo>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let act = Act {
        id,
        state: RwSignal::new(None),
        msg: RwSignal::new(None),
        note: RwSignal::new(None),
        pending: RwSignal::new(false),
    };
    let mode = RwSignal::new(Mode::Visual);
    let json_list = RwSignal::new(AccessList::Whitelist);
    act.load();
    let running = Signal::derive(move || info.with(|i| i.as_ref().is_some_and(|i| i.state == ServerState::Running)));
    let busy = Signal::derive(move || {
        info.with(|i| {
            i.as_ref()
                .is_some_and(|i| i.op.is_some() || matches!(i.state, ServerState::Starting | ServerState::Stopping))
        })
    });
    // État du serveur changé : les listes ont pu changer (le jeu les réécrit en s'arrêtant).
    let st = Memo::new(move |_| info.with(|i| i.as_ref().map(|i| i.state)));
    Effect::new(move |prev: Option<Option<ServerState>>| {
        let s = st.get();
        if prev.is_some_and(|p| p != s) {
            act.load();
        }
        s
    });
    let set_mode = move |m: Mode| {
        if m == mode.get_untracked() || !crate::may_leave(ctx) {
            return;
        }
        if m == Mode::Visual && mode.get_untracked() == Mode::Json {
            act.load();
        }
        act.note.set(None);
        mode.set(m);
    };
    view! {
        <div class="acc">
            <div class="acc-bar">
                <div class="segmented small" role="group">
                    <button type="button" class:on=move || mode.get() == Mode::Visual aria-pressed=move || (mode.get() == Mode::Visual).to_string()
                        on:click=move |_| set_mode(Mode::Visual)>{icon(I::Users)}{move || ctx.tr(K::ModeVisual)}</button>
                    <button type="button" class:on=move || mode.get() == Mode::Json aria-pressed=move || (mode.get() == Mode::Json).to_string()
                        on:click=move |_| set_mode(Mode::Json)>{icon(I::Braces)}{move || ctx.tr(K::ModeJson)}</button>
                </div>
                <span class="acc-how faint small">
                    {move || if running.get() { icon(I::Command).into_any() } else { icon(I::FileText).into_any() }}
                    {move || ctx.tr(if running.get() { K::HowConsole } else { K::HowFile })}
                </span>
            </div>
            <Msg msg=act.msg/>
            {move || act.note.get().map(|k| view! {
                <div class="banner ok-banner" role="status">{icon(I::Check)}<span>{move || ctx.tr(k)}</span></div>
            })}
            {move || match mode.get() {
                Mode::Visual => view! { <Visual act=act running=running busy=busy json_list=json_list mode=mode/> }.into_any(),
                Mode::Json => view! {
                    <div class="chips acc-files" role="group" aria-label=move || ctx.tr(K::ConfigFiles)>
                        {AccessList::ALL.into_iter().map(|l| view! {
                            <button type="button" class="chip-filter" class:on=move || json_list.get() == l
                                aria-pressed=move || (json_list.get() == l).to_string()
                                on:click=move |_| { if json_list.get_untracked() != l && crate::may_leave(ctx) { json_list.set(l) } }>{l.file()}</button>
                        }).collect_view()}
                    </div>
                    {move || {
                        let f = json_list.get().file();
                        view! { <crate::configs::ConfigTab id=id info=info only=f/> }
                    }}
                }.into_any(),
            }}
        </div>
    }
}

#[component]
fn Visual(
    act: Act,
    running: Signal<bool>,
    busy: Signal<bool>,
    json_list: RwSignal<AccessList>,
    mode: RwSignal<Mode>,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    view! {
        {move || act.state.with(|s| s.as_ref().map(|s| s.unreadable.clone())).unwrap_or_default().into_iter().map(|l| view! {
            <div class="banner bad" role="alert">{icon(I::Error)}
                <span>{move || ctx.tr(K::ListUnreadable)}" "<code>{l.file()}</code></span>
                <button type="button" class="btn small" on:click=move |_| { json_list.set(l); mode.set(Mode::Json); }>
                    {icon(I::Braces)}{move || ctx.tr(K::FixInJson)}
                </button>
            </div>
        }).collect_view()}
        <Show when=move || act.state.with(Option::is_some) fallback=|| view! { <div class="cfg-skeleton skeleton"></div> }>
            <Show when=move || act.state.with(|s| s.as_ref().is_some_and(|s| !s.online_mode))>
                <p class="faint small acc-offline">{icon(I::Info)}{move || ctx.tr(K::OfflineUuids)}</p>
            </Show>
            <div class="acc-grid">
                {AccessList::ALL.into_iter().map(|l| view! { <ListCard list=l act=act running=running busy=busy/> }).collect_view()}
            </div>
        </Show>
    }
}

#[component]
fn ListCard(list: AccessList, act: Act, running: Signal<bool>, busy: Signal<bool>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let id = act.id;
    let target = RwSignal::new(String::new());
    let level = RwSignal::new(None::<u8>);
    let bypass = RwSignal::new(false);
    let reason = RwSignal::new(String::new());
    let duration = RwSignal::new(None::<i64>);
    let suggestions = RwSignal::new(Vec::<PlayerSuggestion>::new());
    let typing = StoredValue::new(0u64);
    let players = list != AccessList::BannedIps;
    let dl = format!("acc-dl-{}", list.code());
    let default_level = move || act.state.with(|s| s.as_ref().map_or(4, |s| s.default_op_level));
    let on_type = move |v: String| {
        target.set(v.clone());
        if !players {
            return;
        }
        typing.update_value(|t| *t += 1);
        let t = typing.get_value();
        set_timeout(
            move || {
                if typing.get_value() != t {
                    return;
                }
                let q = js_sys::encode_uri_component(&v).as_string().unwrap_or_default();
                spawn_local(async move {
                    if let Ok(l) =
                        api::get::<Vec<PlayerSuggestion>>(&format!("/api/servers/{id}/suggest/players?q={q}")).await
                        && typing.get_value() == t
                    {
                        suggestions.set(l);
                    }
                });
            },
            Duration::from_millis(150),
        );
    };
    let submit = move || {
        let t = target.get_untracked().trim().to_string();
        if t.is_empty() {
            return;
        }
        let req = AccessAddRequest {
            list,
            target: t,
            level: (list == AccessList::Ops).then(|| level.get_untracked().unwrap_or_else(default_level)),
            bypasses_player_limit: (list == AccessList::Ops && bypass.get_untracked()).then_some(true),
            reason: Some(reason.get_untracked()).filter(|r| !r.trim().is_empty()),
            expires: duration.get_untracked().map(|d| (js_sys::Date::now() / 1000.0) as i64 + d),
        };
        let expect = Some((list, req.target.clone(), true));
        act.post(ctx, "add", req, expect, move || {
            target.set(String::new());
            reason.set(String::new());
            duration.set(None);
        });
    };
    let remove = move |who: String| {
        let expect = Some((list, who.clone(), false));
        act.post(ctx, "remove", AccessRemoveRequest { list, target: who }, expect, || {});
    };
    let (ico, tone) = list_icon(list);
    let count = move || act.state.with(|s| s.as_ref().map_or(0, |s| entries(s, list).len()));
    let stopped_only = move || running.get();
    view! {
        <section class="panel acc-card">
            <header class="acc-head">
                <span class=format!("acc-ico {tone}")>{icon(ico)}</span>
                <h2>{move || ctx.tr(list_key(list))}</h2>
                <span class="cfg-count">{count}</span>
            </header>
            {(list == AccessList::Whitelist).then(|| view! { <WhitelistSwitches act=act running=running busy=busy/> })}
            <form class="acc-add" on:submit=move |ev: leptos::ev::SubmitEvent| { ev.prevent_default(); submit(); }>
                <input type="text" class="acc-target" required=true spellcheck="false" autocomplete="off" autocapitalize="off"
                    maxlength=if players { "16" } else { "45" }
                    list=players.then(|| dl.clone())
                    placeholder=move || ctx.tr(if players { K::PlayerName } else { K::IpAddress })
                    aria-label=move || ctx.tr(if players { K::PlayerName } else { K::IpAddress })
                    prop:value=move || target.get() on:input=move |ev| on_type(event_target_value(&ev))/>
                {players.then(|| view! {
                    <datalist id=dl.clone()>
                        {move || suggestions.get().into_iter().map(|p| view! { <option value=p.name.clone()></option> }).collect_view()}
                    </datalist>
                })}
                {(list == AccessList::Ops).then(|| view! {
                    <select aria-label=move || ctx.tr(K::OpLevel) title=move || if stopped_only() { ctx.tr(K::StoppedOnly) } else { "" }
                        on:change=move |ev| level.set(event_target_value(&ev).parse().ok())>
                        {move || {
                            let d = default_level();
                            let cur = level.get().unwrap_or(d);
                            OP_LEVELS.map(|n| view! {
                                <option value=n.to_string() selected=n == cur disabled=move || stopped_only() && n != d>
                                    {format!("{n} · {}", ctx.tr(level_key(n)))}
                                </option>
                            }).collect_view()
                        }}
                    </select>
                    <label class="check acc-check" title=move || if stopped_only() { ctx.tr(K::StoppedOnly) } else { "" }>
                        <input type="checkbox" prop:checked=move || bypass.get() disabled=stopped_only
                            on:change=move |ev| bypass.set(event_target_checked(&ev))/>
                        <span>{move || ctx.tr(K::BypassLimit)}</span>
                    </label>
                })}
                {matches!(list, AccessList::BannedPlayers | AccessList::BannedIps).then(|| view! {
                    <input type="text" class="acc-reason" maxlength="200" placeholder=move || ctx.tr(K::Reason)
                        aria-label=move || ctx.tr(K::Reason) prop:value=move || reason.get() on:input=move |ev| reason.set(event_target_value(&ev))/>
                    <select aria-label=move || ctx.tr(K::Duration) title=move || if stopped_only() { ctx.tr(K::StoppedOnly) } else { "" }
                        on:change=move |ev| duration.set(event_target_value(&ev).parse().ok())>
                        {DURATIONS.map(|(d, k)| view! {
                            <option value=d.map(|d| d.to_string()).unwrap_or_default() selected=move || duration.get() == d
                                disabled=move || stopped_only() && d.is_some()>{move || ctx.tr(k)}</option>
                        }).collect_view()}
                    </select>
                })}
                <button type="submit" class="btn primary small" disabled=move || busy.get() || act.pending.get() || target.with(|t| t.trim().is_empty())>
                    {icon(I::Plus)}{move || ctx.tr(K::AddItem)}
                </button>
            </form>
            <ul class="acc-list">
                {move || {
                    let rows = act.state.with(|s| s.as_ref().map(|s| entries(s, list).clone())).unwrap_or_default();
                    if rows.is_empty() {
                        return view! { <li class="acc-empty faint">{move || ctx.tr(K::Nobody)}</li> }.into_any();
                    }
                    rows.into_iter().map(|e| {
                        let who = e.ip.clone().or_else(|| e.name.clone()).or_else(|| e.uuid.clone()).unwrap_or_default();
                        let shown = e.name.clone().or_else(|| e.ip.clone()).unwrap_or_else(|| who.clone());
                        let sub = if players { e.uuid.clone().unwrap_or_default() } else { String::new() };
                        let meta = entry_meta(ctx, &e);
                        let label = format!("{} {shown}", ctx.tr(K::RemoveItem));
                        let w = who.clone();
                        view! {
                            <li class="acc-row">
                                {if players { view! { <Head name=shown.clone()/> }.into_any() } else { view! { <span class="head ip" aria-hidden="true">{icon(I::Globe)}</span> }.into_any() }}
                                <span class="acc-text">
                                    <span class="acc-name">{shown.clone()}</span>
                                    {(!sub.is_empty()).then(|| view! { <span class="acc-sub">{sub.clone()}</span> })}
                                    {(!meta.is_empty()).then(|| view! { <span class="acc-meta">{meta.clone()}</span> })}
                                </span>
                                <button type="button" class="btn icon-btn ghost acc-del" aria-label=label.clone() title=label
                                    disabled=move || busy.get() || act.pending.get() on:click=move |_| remove(w.clone())>{icon(I::Trash)}</button>
                            </li>
                        }
                    }).collect_view().into_any()
                }}
            </ul>
        </section>
    }
}

/// Niveau, limite, raison, fin : une ligne courte sous le pseudo.
fn entry_meta(ctx: Ctx, e: &AccessEntry) -> String {
    let mut parts = Vec::new();
    if let Some(n) = e.level {
        parts.push(format!("{} {n}", ctx.tr(K::OpLevel)));
    }
    if e.bypasses_player_limit == Some(true) {
        parts.push(ctx.tr(K::BypassLimit).to_string());
    }
    if let Some(r) = e.reason.as_deref().filter(|r| !r.is_empty()) {
        parts.push(format!("« {r} »"));
    }
    match e.expires.as_deref() {
        Some("forever") => parts.push(ctx.tr(K::Forever).to_string()),
        // Date du jeu (`2026-10-27 13:14:00 +0000`) : minutes, sans coupure de ligne.
        Some(d) if !d.is_empty() => {
            let d = d.get(..16).unwrap_or(d).replace('-', "\u{2011}").replace(' ', "\u{a0}");
            parts.push(format!("{} {d}", ctx.tr(K::Until)))
        }
        _ => {}
    }
    parts.join(" · ")
}

#[component]
fn WhitelistSwitches(act: Act, running: Signal<bool>, busy: Signal<bool>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let on = move || act.state.with(|s| s.as_ref().is_some_and(|s| s.white_list));
    let enforce = move || act.state.with(|s| s.as_ref().is_some_and(|s| s.enforce_whitelist));
    let send = move |enabled: bool, enforce: bool| {
        act.post(ctx, "whitelist", WhitelistModeRequest { enabled, enforce }, None, || {});
    };
    view! {
        <div class="acc-switches">
            <label class="switch acc-switch">
                <span>{move || ctx.tr(K::WhitelistOn)}</span>
                <input type="checkbox" role="switch" prop:checked=on disabled=move || busy.get() || act.pending.get()
                    on:change=move |ev| send(event_target_checked(&ev), enforce())/>
                <span class="switch-track" aria-hidden="true"></span>
            </label>
            <label class="switch acc-switch" title=move || if running.get() { ctx.tr(K::StoppedOnly) } else { "" }>
                <span>{move || ctx.tr(K::WhitelistEnforce)}</span>
                <input type="checkbox" role="switch" prop:checked=enforce disabled=move || busy.get() || running.get() || act.pending.get()
                    on:change=move |ev| send(on(), event_target_checked(&ev))/>
                <span class="switch-track" aria-hidden="true"></span>
            </label>
        </div>
    }
}
