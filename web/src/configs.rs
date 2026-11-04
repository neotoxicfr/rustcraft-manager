//! Onglet « Réglages » d'un serveur : fichiers de configuration du logiciel, chacun en mode
//! visuel (formulaire de `server.properties`, arbre éditable pour YAML, JSON, TOML) ou texte
//! (éditeur coloré), les deux sur le même texte. Toute édition visuelle passe par le serveur
//! (édition ciblée vérifiée), toute saisie de texte est vérifiée par le vrai analyseur ;
//! l'enregistrement montre l'écart d'abord.

use crate::api::{self, ApiErr};
use crate::editor::highlight;
use crate::i18n::{K, Lang};
use crate::icons::{I, icon};
use crate::schema::{self, GROUPS, Group, Kind, Managed, PROPS, Prop};
use crate::{Ctx, Msg};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;
use std::collections::HashSet;
use std::time::Duration;

fn enc(s: &str) -> String {
    js_sys::encode_uri_component(s).as_string().unwrap_or_default()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Visual,
    Text,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Note {
    Saved,
    Restart,
}

/// Fichier ouvert : texte en cours, texte du disque, arbre et erreur de l'analyseur.
#[derive(Clone, Copy)]
pub(crate) struct Ed {
    id: i64,
    /// Vérification par les routes des fichiers (gestionnaire de fichiers) : texte seul, pas
    /// d'édition visuelle.
    files: bool,
    pub(crate) path: RwSignal<String>,
    pub(crate) format: RwSignal<ConfigFormat>,
    pub(crate) original: RwSignal<String>,
    pub(crate) hash: RwSignal<String>,
    pub(crate) text: RwSignal<String>,
    entries: RwSignal<Vec<ConfigEntry>>,
    pub(crate) error: RwSignal<Option<ConfigError>>,
    pub(crate) loading: RwSignal<bool>,
    /// Numéro de la dernière vérification (une réponse plus ancienne est ignorée).
    seq: StoredValue<u64>,
    /// Éditions visuelles en route vers le serveur ; les suivantes attendent leur tour (sinon
    /// deux éditions partent du même texte et la seconde efface la première).
    in_flight: StoredValue<bool>,
    queued: StoredValue<Vec<ConfigEdit>>,
    /// Chemin en double : visuel refusé.
    duplicate: RwSignal<Option<String>>,
    /// Réglages réservés aux administrateurs changés par rapport au disque.
    pub(crate) sensitive: RwSignal<Vec<String>>,
    /// Texte valide dont les réglages ne peuvent pas être vérifiés (avertissement).
    pub(crate) unverifiable: RwSignal<Option<Unverifiable>>,
    msg: RwSignal<Option<K>>,
}

impl Ed {
    pub(crate) fn new(id: i64, files: bool, msg: RwSignal<Option<K>>) -> Ed {
        Ed {
            id,
            files,
            path: RwSignal::new(String::new()),
            format: RwSignal::new(ConfigFormat::Properties),
            original: RwSignal::new(String::new()),
            hash: RwSignal::new(String::new()),
            text: RwSignal::new(String::new()),
            entries: RwSignal::new(Vec::new()),
            error: RwSignal::new(None),
            loading: RwSignal::new(false),
            seq: StoredValue::new(0),
            in_flight: StoredValue::new(false),
            queued: StoredValue::new(Vec::new()),
            duplicate: RwSignal::new(None),
            sensitive: RwSignal::new(Vec::new()),
            unverifiable: RwSignal::new(None),
            msg,
        }
    }

    pub(crate) fn dirty(&self) -> bool {
        self.text.with(|t| self.original.with(|o| t != o))
    }

    fn take_queue(self) -> Vec<ConfigEdit> {
        let q = self.queued.with_value(Vec::clone);
        self.queued.set_value(Vec::new());
        q
    }

    /// Vérification par le serveur (et éditions ciblées) ; met à jour texte, arbre et erreur.
    /// Éditions : une seule requête à la fois ; si le texte a changé pendant l'aller-retour
    /// (saisie, autre fichier), la réponse ne l'écrase pas : les éditions repartent du texte courant.
    pub(crate) fn check(self, ctx: Ctx, edits: Vec<ConfigEdit>) {
        let has_edits = !edits.is_empty();
        if has_edits && self.in_flight.get_value() {
            self.queued.update_value(|q| q.extend(edits));
            return;
        }
        self.seq.update_value(|g| *g += 1);
        let seq = self.seq.get_value();
        self.in_flight.set_value(has_edits);
        let (path, sent) = (self.path.get_untracked(), self.text.get_untracked());
        let req = ConfigCheckRequest { path: path.clone(), text: sent.clone(), edits: edits.clone() };
        let csrf = ctx.csrf();
        let (id, files) = (self.id, self.files);
        spawn_local(async move {
            let r = if files {
                let req = FileCheckRequest { path: req.path, text: req.text };
                api::post::<_, ConfigCheck>(&format!("/api/servers/{id}/files/check"), &req, csrf.as_deref()).await
            } else {
                api::post::<_, ConfigCheck>(&format!("/api/servers/{id}/config/check"), &req, csrf.as_deref()).await
            };
            if has_edits {
                self.in_flight.set_value(false);
            }
            if self.path.with_untracked(|p| *p != path) {
                self.queued.set_value(Vec::new());
                return;
            }
            if has_edits && self.text.with_untracked(|t| *t != sent) {
                let mut again = edits;
                again.extend(self.take_queue());
                self.check(ctx, again);
                return;
            }
            if !has_edits && self.seq.get_value() != seq {
                return;
            }
            match r {
                Ok(c) => {
                    if has_edits && c.text.is_none() {
                        self.queued.set_value(Vec::new());
                        // Contrôles redessinés : ils reprennent la valeur réelle (rien n'a changé).
                        self.entries.update(|_| {});
                        self.msg.set(Some(if c.duplicate.is_some() { K::DuplicateKey } else { K::EditRefused }));
                        return;
                    }
                    if let Some(t) = c.text {
                        self.text.set(t);
                    }
                    if c.error.is_none() || !c.entries.is_empty() || c.duplicate.is_some() {
                        self.entries.set(c.entries);
                    }
                    self.duplicate.set(c.duplicate);
                    // `*` (rien de vérifiable) : expliqué par la bannière « non vérifiable ».
                    self.sensitive.set(c.sensitive.into_iter().filter(|k| k != "*").collect());
                    self.unverifiable.set(c.unverifiable);
                    self.error.set(c.error);
                }
                Err(e) => {
                    self.queued.set_value(Vec::new());
                    if has_edits {
                        self.entries.update(|_| {});
                    }
                    ctx.on_err(&e, self.msg);
                    return;
                }
            }
            let next = self.take_queue();
            if !next.is_empty() {
                self.check(ctx, next);
            }
        });
    }

    fn edit(self, ctx: Ctx, e: ConfigEdit) {
        self.msg.set(None);
        self.check(ctx, vec![e]);
    }
}

fn format_icon(f: ConfigFormat) -> (I, &'static str) {
    match f {
        ConfigFormat::Properties => (I::Sliders, "fmt-props"),
        ConfigFormat::Yaml => (I::FileText, "fmt-yaml"),
        ConfigFormat::Json | ConfigFormat::Json5 => (I::Braces, "fmt-json"),
        ConfigFormat::Toml => (I::FileText, "fmt-toml"),
        ConfigFormat::Text => (I::FileText, "fmt-text"),
    }
}

/// Redémarre le serveur (bannière « redémarrage nécessaire » des deux éditeurs).
pub(crate) fn restart_server(ctx: Ctx, id: i64, msg: RwSignal<Option<K>>) {
    let csrf = ctx.csrf();
    spawn_local(async move {
        if let Err(e) =
            api::post::<_, ServerInfo>(&format!("/api/servers/{id}/restart"), &serde_json::Map::new(), csrf.as_deref())
                .await
        {
            ctx.on_err(&e, msg);
        }
    });
}

fn confirm(text: &str) -> bool {
    web_sys::window().and_then(|w| w.confirm_with_message(text).ok()).unwrap_or(true)
}

fn show(v: &ConfigValue) -> String {
    match v {
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        ConfigValue::Float(f) => f.to_string(),
        ConfigValue::Str(s) => s.clone(),
        ConfigValue::Null => String::new(),
    }
}

fn pkey(p: &[ConfigSeg]) -> String {
    p.iter()
        .map(|s| match s {
            ConfigSeg::Key(k) => k.clone(),
            ConfigSeg::Index(i) => i.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Taille d'un fichier de configuration (octets ou kilo-octets).
fn fmt_size(b: u64, lang: Lang) -> String {
    let (o, k) = if lang == Lang::Fr { ("o", "Ko") } else { ("B", "KB") };
    if b < 1024 { format!("{b} {o}") } else { format!("{} {k}", crate::fmt_dec(b as f32 / 1024.0, 1, lang)) }
}

fn local_datetime(unix: i64, lang: Lang) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(unix as f64 * 1000.0));
    d.to_locale_string(lang.code(), &wasm_bindgen::JsValue::UNDEFINED).into()
}

#[component]
pub fn ConfigTab(
    id: i64,
    #[prop(into)] info: Signal<Option<ServerInfo>>,
    /// Un seul fichier, en texte (listes d'accès de l'onglet « Joueurs ») : ni liste de fichiers,
    /// ni mode visuel.
    #[prop(optional)]
    only: Option<&'static str>,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let files = RwSignal::new(None::<Vec<ConfigFileInfo>>);
    let msg = RwSignal::new(None::<K>);
    let ed = Ed::new(id, false, msg);
    let mode = RwSignal::new(Mode::Visual);
    let query = RwSignal::new(String::new());
    let diff_open = RwSignal::new(false);
    let history_open = RwSignal::new(false);
    let note = RwSignal::new(None::<Note>);
    let saving = RwSignal::new(false);
    let conflict = RwSignal::new(false);
    let jump = RwSignal::new(None::<u32>);
    // « Enregistré » ne reste pas affiché quand on modifie de nouveau le fichier.
    Effect::new(move |_| {
        if ed.dirty() && note.with_untracked(|n| *n == Some(Note::Saved)) {
            note.set(None);
        }
    });
    crate::track_dirty(ed);

    let open = move |path: String, force: bool| {
        if !force && ed.dirty() && !confirm(ctx.tr(K::DiscardChanges)) {
            return;
        }
        ed.path.set(path.clone());
        ed.loading.set(true);
        note.set(None);
        conflict.set(false);
        msg.set(None);
        query.set(String::new());
        spawn_local(async move {
            match api::get::<ConfigFile>(&format!("/api/servers/{id}/config?path={}", enc(&path))).await {
                Ok(f) if ed.path.get_untracked() == f.path => {
                    ed.format.set(f.format);
                    ed.original.set(f.text.clone());
                    ed.hash.set(f.hash);
                    ed.text.set(f.text);
                    ed.entries.set(Vec::new());
                    ed.error.set(None);
                    ed.check(ctx, Vec::new());
                }
                Ok(_) => {}
                Err(e) => ctx.on_err(&e, msg),
            }
            ed.loading.set(false);
        });
    };
    let load_list = move || {
        if let Some(p) = only {
            files.set(Some(vec![ConfigFileInfo { path: p.to_string(), format: ConfigFormat::Json, size: 0 }]));
            if ed.path.get_untracked().is_empty() {
                open(p.to_string(), true);
            }
            return;
        }
        spawn_local(async move {
            match api::get::<Vec<ConfigFileInfo>>(&format!("/api/servers/{id}/configs")).await {
                Ok(l) => {
                    let first = l.first().map(|f| f.path.clone());
                    files.set(Some(l));
                    if ed.path.get_untracked().is_empty()
                        && let Some(p) = first
                    {
                        open(p, true);
                    }
                }
                Err(e) => {
                    files.set(Some(Vec::new()));
                    ctx.on_err(&e, msg);
                }
            }
        });
    };
    load_list();
    // Premier démarrage : les fichiers apparaissent une fois le serveur lancé.
    let state = Memo::new(move |_| info.with(|i| i.as_ref().map(|i| i.state)));
    Effect::new(move |prev: Option<Option<ServerState>>| {
        let s = state.get();
        if prev.is_some_and(|p| p != s) && files.with_untracked(|f| f.as_ref().is_none_or(|f| f.len() < 2)) {
            load_list();
        }
        s
    });
    let server_busy = move || {
        info.with(|i| {
            i.as_ref()
                .is_some_and(|i| i.op.is_some() || matches!(i.state, ServerState::Starting | ServerState::Stopping))
        })
    };
    let can_save =
        move || ed.dirty() && ed.error.with(Option::is_none) && !saving.get() && !server_busy() && !ed.loading.get();
    let save = move || {
        saving.set(true);
        note.set(None);
        conflict.set(false);
        let text = ed.text.get_untracked();
        let req =
            ConfigSaveRequest { path: ed.path.get_untracked(), text: text.clone(), base_hash: ed.hash.get_untracked() };
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post::<_, ConfigSaved>(&format!("/api/servers/{id}/config/save"), &req, csrf.as_deref()).await {
                Ok(s) => {
                    ed.original.set(text);
                    ed.hash.set(s.hash);
                    note.set(Some(if s.restart_needed { Note::Restart } else { Note::Saved }));
                    msg.set(None);
                }
                Err(ApiErr::Api(ErrorCode::ConfigChanged)) => conflict.set(true),
                Err(e) => ctx.on_err(&e, msg),
            }
            diff_open.set(false);
            saving.set(false);
        });
    };
    let restart = move |_| {
        note.set(None);
        restart_server(ctx, id, msg);
    };
    let visual_ok = move || only.is_none() && ed.format.get().visual();
    let version = Signal::derive(move || info.with(|i| i.as_ref().map(|i| i.version.clone()).unwrap_or_default()));

    view! {
        <Show when=move || files.with(Option::is_some) fallback=|| view! { <div class="cfg-skeleton skeleton"></div> }>
        <Show when=move || files.with(|f| f.as_ref().is_some_and(|f| !f.is_empty())) fallback=move || view! {
            <div class="state-block panel cfg-empty">{icon(I::FileText)}<p class="muted">{move || ctx.tr(K::ConfigNone)}</p></div>
        }>
        <div class="cfg" class:single=only.is_some()>
            <Show when=move || only.is_none()>
            <nav class="cfg-files" aria-label=move || ctx.tr(K::ConfigFiles)>
                {move || files.get().unwrap_or_default().into_iter().map(|f| {
                    let (ico, cls) = format_icon(f.format);
                    // Fichiers des mods : le dossier du mod reste dans le nom (deux « config.json »).
                    let (dir, name) = match f.path.strip_prefix("config/").filter(|r| r.contains('/')) {
                        Some(rest) => ("config/".to_string(), rest.to_string()),
                        None => match f.path.rsplit_once('/') {
                            Some((d, n)) => (format!("{d}/"), n.to_string()),
                            None => (String::new(), f.path.clone()),
                        },
                    };
                    let p = f.path.clone();
                    let p2 = f.path.clone();
                    view! {
                        <button type="button" class="cfg-file" class:on=move || ed.path.with(|x| *x == p)
                            aria-current=move || ed.path.with(|x| (*x == p2).then_some("true"))
                            on:click=move |_| if ed.path.get_untracked() != f.path { open(f.path.clone(), false) }>
                            <span class=format!("cfg-ico {cls}")>{icon(ico)}</span>
                            <span class="cfg-file-text">
                                <span class="cfg-name">{name}</span>
                                <span class="cfg-dir">{dir}</span>
                            </span>
                        </button>
                    }
                }).collect_view()}
            </nav>
            </Show>
            <section class="cfg-main panel">
                <div class="cfg-bar">
                    <Show when=visual_ok>
                        <div class="segmented small" role="group">
                            <button type="button" class:on=move || mode.get() == Mode::Visual aria-pressed=move || (mode.get() == Mode::Visual).to_string()
                                on:click=move |_| mode.set(Mode::Visual)>{icon(I::Sliders)}{move || ctx.tr(K::ModeVisual)}</button>
                            <button type="button" class:on=move || mode.get() == Mode::Text aria-pressed=move || (mode.get() == Mode::Text).to_string()
                                on:click=move |_| mode.set(Mode::Text)>{icon(I::Code)}{move || ctx.tr(K::ModeText)}</button>
                        </div>
                    </Show>
                    <Show when=move || mode.get() == Mode::Visual && visual_ok()>
                        <label class="cfg-search">
                            {icon(I::Search)}
                            <input type="search" placeholder=move || ctx.tr(K::SearchOptions) aria-label=move || ctx.tr(K::SearchOptions)
                                prop:value=move || query.get() on:input=move |ev| query.set(event_target_value(&ev))/>
                        </label>
                    </Show>
                    <div class="cfg-bar-end">
                        <Show when=move || ed.dirty()>
                            <span class="cfg-dirty">{move || ctx.tr(K::Modified)}</span>
                        </Show>
                        <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::History) title=move || ctx.tr(K::History)
                            on:click=move |_| history_open.set(true)>{icon(I::History)}</button>
                        <button type="button" class="btn primary" disabled=move || !can_save() on:click=move |_| diff_open.set(true)>
                            {icon(I::Save)}{move || ctx.tr(K::Save)}
                        </button>
                    </div>
                </div>
                <Msg msg=msg/>
                {move || note.get().map(|n| match n {
                    Note::Saved => view! { <div class="banner ok-banner" role="status">{icon(I::Check)}<span>{move || ctx.tr(K::SavedPlain)}</span></div> }.into_any(),
                    Note::Restart => view! {
                        <div class="banner warn" role="status">{icon(I::Restart)}<span>{move || ctx.tr(K::RestartNeeded)}</span>
                            <button type="button" class="btn small" on:click=restart>{move || ctx.tr(K::Restart)}</button>
                        </div>
                    }.into_any(),
                })}
                <Show when=move || conflict.get()>
                    <div class="banner bad" role="alert">{icon(I::Alert)}<span>{move || ctx.tr(K::ErrConfigChanged)}</span>
                        <button type="button" class="btn small" on:click=move |_| {
                            if confirm(ctx.tr(K::DiscardChanges)) { open(ed.path.get_untracked(), true) }
                        }>{move || ctx.tr(K::Reload)}</button>
                    </div>
                </Show>
                {move || ed.error.get().map(|e| {
                    let keyed = [(e.managed_key.clone(), K::ManagedKeyChanged), (e.admin_key.clone(), K::AdminKeyChanged), (e.unsafe_key.clone(), K::UnsafeKey)]
                        .into_iter()
                        .find_map(|(k, label)| k.map(|k| (k, label)));
                    if let Some(why) = e.unverifiable {
                        // Fichier non vérifiable : pourquoi, et quoi faire.
                        unverifiable_banner(ctx, why, e.unsafe_key.is_some(), true)
                    } else if let Some((k, label)) = keyed {
                        view! { <div class="banner bad" role="alert">{icon(I::Lock)}<span>{move || ctx.tr(label)}" "<code>{k.clone()}</code></span></div> }.into_any()
                    } else {
                        let line = e.line;
                        let where_ = (line > 0).then(|| match e.col {
                            0 => format!("{} {line} · ", ctx.tr(K::Line)),
                            c => format!("{} {line}, {} {c} · ", ctx.tr(K::Line), ctx.tr(K::Column)),
                        });
                        view! {
                            <button type="button" class="banner bad cfg-err" role="alert" on:click=move |_| {
                                mode.set(Mode::Text);
                                if line > 0 { jump.set(Some(line)); }
                            }>
                                {icon(I::Error)}<span>{where_.unwrap_or_default()}{e.message.clone()}</span>
                            </button>
                        }.into_any()
                    }
                })}
                {move || ed.unverifiable.get().map(|w| unverifiable_banner(ctx, w, false, false))}
                {move || ed.duplicate.get().map(|k| view! {
                    <div class="banner warn" role="status">{icon(I::Alert)}<span>{move || ctx.tr(K::DuplicateKey)}" "<code>{k.clone()}</code></span></div>
                })}
                {move || ed.sensitive.with(|v| !v.is_empty()).then(|| view! {
                    <div class="banner warn" role="status">{icon(I::Shield)}
                        <span>{move || ctx.tr(K::SensitiveChanged)}" "<code>{move || ed.sensitive.get().join(", ")}</code></span>
                    </div>
                })}
                {move || if ed.loading.get() {
                    view! { <div class="cfg-skeleton skeleton"></div> }.into_any()
                } else if mode.get() == Mode::Text || !visual_ok() {
                    view! {
                        <Show when=move || !visual_ok() && only.is_none()><p class="faint small">{move || ctx.tr(K::TextOnly)}</p></Show>
                        <CodeEditor ed=ed jump=jump/>
                    }.into_any()
                } else if ed.format.get() == ConfigFormat::Properties {
                    view! { <PropsForm ed=ed query=query version=version/> }.into_any()
                } else {
                    view! { <TreeForm ed=ed query=query/> }.into_any()
                }}
            </section>
        </div>
        </Show>
        </Show>
        <Show when=move || diff_open.get()>
            <DiffModal ed=ed open=diff_open saving=saving on_save=save/>
        </Show>
        <Show when=move || history_open.get()>
            <HistorySheet ed=ed open=history_open diff_open=diff_open/>
        </Show>
    }
}

// ---------------------------------------------------------------------------------------------
// server.properties

fn group_key(g: Group) -> K {
    match g {
        Group::Game => K::GroupGame,
        Group::World => K::GroupWorld,
        Group::Players => K::GroupPlayers,
        Group::Network => K::GroupNetwork,
        Group::Security => K::GroupSecurity,
        Group::Performance => K::GroupPerformance,
        Group::Advanced => K::GroupAdvanced,
    }
}

fn managed_key(m: Managed) -> K {
    match m {
        Managed::Port => K::ManagedPort,
        Managed::Rcon => K::ManagedRcon,
        Managed::Query => K::ManagedQuery,
        Managed::Management => K::ManagedManagement,
    }
}

fn set_prop(ctx: Ctx, ed: Ed, key: &str, v: String) {
    ed.edit(ctx, ConfigEdit::Set { path: vec![ConfigSeg::Key(key.to_string())], value: ConfigValue::Str(v) });
}

/// Contrôle d'une clé de `server.properties` selon son genre.
fn prop_control(ctx: Ctx, ed: Ed, p: &'static Prop, value: String) -> AnyView {
    let key = p.key;
    if p.managed.is_some() {
        let shown = if p.kind == Kind::Secret && !value.is_empty() { "••••••".to_string() } else { value };
        return view! { <span class="cfg-locked">{icon(I::Lock)}<code>{shown}</code></span> }.into_any();
    }
    match p.kind {
        Kind::Bool => {
            let on = value == "true";
            view! {
                <label class="switch cfg-switch">
                    <input type="checkbox" role="switch" aria-label=key prop:checked=on
                        on:change=move |ev| set_prop(ctx, ed, key, event_target_checked(&ev).to_string())/>
                    <span class="switch-track" aria-hidden="true"></span>
                </label>
            }
            .into_any()
        }
        Kind::Int { min, max } => {
            let v0 = value.clone();
            view! {
                <input type="number" class="cfg-num" inputmode="numeric" aria-label=key min=min.to_string() max=max.to_string() step="1"
                    prop:value=value on:change=move |ev| {
                        let raw = event_target_value(&ev);
                        match raw.trim().parse::<i64>() {
                            Ok(n) if (min..=max).contains(&n) => set_prop(ctx, ed, key, n.to_string()),
                            _ => {
                                ed.msg.set(Some(K::OutOfRange));
                                if let Some(t) = ev.target().and_then(|t| wasm_bindgen::JsCast::dyn_into::<web_sys::HtmlInputElement>(t).ok()) {
                                    t.set_value(&v0);
                                }
                            }
                        }
                    }/>
            }
            .into_any()
        }
        Kind::Choice(list) => {
            let extra = (!list.contains(&value.as_str())).then(|| value.clone());
            view! {
                <select aria-label=key on:change=move |ev| set_prop(ctx, ed, key, event_target_value(&ev))>
                    {extra.map(|x| view! { <option value=x.clone() selected=true>{x.clone()}</option> })}
                    {list.iter().map(|o| view! { <option value=*o selected=*o == value>{*o}</option> }).collect_view()}
                </select>
            }
            .into_any()
        }
        Kind::Suggest(list) => {
            let dl = format!("dl-{key}");
            view! {
                <input type="text" aria-label=key list=dl.clone() autocomplete="off" spellcheck="false" prop:value=value
                    on:change=move |ev| set_prop(ctx, ed, key, event_target_value(&ev))/>
                <datalist id=dl>{list.iter().map(|o| view! { <option value=*o></option> }).collect_view()}</datalist>
            }
            .into_any()
        }
        Kind::Text => view! {
            <input type="text" aria-label=key spellcheck="false" prop:value=value
                on:change=move |ev| set_prop(ctx, ed, key, event_target_value(&ev))/>
        }
        .into_any(),
        Kind::Secret => view! {
            <input type="password" aria-label=key autocomplete="new-password" prop:value=value
                on:change=move |ev| set_prop(ctx, ed, key, event_target_value(&ev))/>
        }
        .into_any(),
    }
}

/// Construction qui empêche de vérifier un fichier, et quoi faire.
pub(crate) fn unverifiable_key(why: Unverifiable) -> K {
    match why {
        Unverifiable::Syntax => K::UnvSyntax,
        Unverifiable::ComplexKey => K::UnvComplexKey,
        Unverifiable::UnknownAlias => K::UnvUnknownAlias,
        Unverifiable::ManyDocuments => K::UnvManyDocuments,
        Unverifiable::CollectionTag => K::UnvCollectionTag,
        Unverifiable::BadMerge => K::UnvBadMerge,
        Unverifiable::TooLarge => K::UnvTooLarge,
        Unverifiable::OnDisk => K::UnvOnDisk,
    }
}

/// Fichier dont les réglages ne peuvent pas être vérifiés : qui peut l'enregistrer (`locked` :
/// personne, le serveur ne démarre pas non plus), la construction en cause et quoi faire.
/// `refused` : refus de la vérification (sinon simple avertissement).
pub(crate) fn unverifiable_banner(ctx: Ctx, why: Unverifiable, locked: bool, refused: bool) -> AnyView {
    let scope = if locked { K::UnvLocked } else { K::UnvAdminOnly };
    let cause = unverifiable_key(why);
    let (class, role) = if refused { ("banner bad", "alert") } else { ("banner warn", "status") };
    view! {
        <div class=class role=role>{icon(I::Lock)}<span>{move || ctx.tr(scope)}" "{move || ctx.tr(cause)}</span></div>
    }
    .into_any()
}

/// Pastille « réservé aux administrateurs » (le serveur refuse le changement aux autres comptes).
fn admin_badge(ctx: Ctx) -> impl IntoView {
    view! {
        <span class="cfg-admin" title=move || ctx.tr(K::AdminOnly) aria-label=move || ctx.tr(K::AdminOnly) role="img">
            {icon(I::Shield)}
        </span>
    }
}

fn prop_row(ctx: Ctx, ed: Ed, p: &'static Prop, cur: Option<String>, lang: Lang) -> AnyView {
    let value = cur.unwrap_or_else(|| p.default.to_string());
    // Secret généré par le jeu : jamais « par défaut ».
    let is_default = value == p.default || (p.kind == Kind::Secret && p.default.is_empty());
    let help = match p.managed {
        Some(m) => ctx.tr(managed_key(m)),
        None => p.help(lang),
    };
    let reset = (!is_default && p.managed.is_none()).then(|| {
        let shown = if p.default.is_empty() { "∅".to_string() } else { p.default.to_string() };
        view! {
            <button type="button" class="cfg-reset" title=move || format!("{} {}", ctx.tr(K::ResetTo), p.default)
                on:click=move |_| set_prop(ctx, ed, p.key, p.default.to_string())>{icon(I::Undo)}<span>{shown}</span></button>
        }
    });
    view! {
        <div class="cfg-row" class:changed=!is_default class:locked=p.managed.is_some()>
            <div class="cfg-text">
                <div class="cfg-label">{p.label(lang)}<code class="cfg-key">{p.key}</code>
                    {(p.managed.is_none() && admin_only("server.properties", &[ConfigSeg::Key(p.key.to_string())]))
                        .then(|| admin_badge(ctx))}
                </div>
                <p class="cfg-help">{help}</p>
            </div>
            <div class="cfg-ctl">
                {prop_control(ctx, ed, p, value)}
                {match reset {
                    Some(r) => r.into_any(),
                    None => view! { <span class="cfg-def">{move || ctx.tr(K::ByDefault)}</span> }.into_any(),
                }}
            </div>
        </div>
    }
    .into_any()
}

fn matches_prop(p: &Prop, q: &str, lang: Lang) -> bool {
    p.key.contains(q) || p.label(lang).to_lowercase().contains(q) || p.help(lang).to_lowercase().contains(q)
}

#[component]
fn PropsForm(ed: Ed, query: RwSignal<String>, version: Signal<String>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let values = Memo::new(move |_| {
        ed.entries.with(|e| {
            e.iter()
                .filter_map(|x| match (x.path.as_slice(), &x.value) {
                    ([ConfigSeg::Key(k)], Some(v)) => Some((k.clone(), show(v))),
                    _ => None,
                })
                .collect::<Vec<(String, String)>>()
        })
    });
    // Fichier écrit par le serveur (toutes ses clés) ou seulement par le gestionnaire.
    let generated = move || values.with(|v| v.iter().any(|(k, _)| k == "level-name"));
    view! {
        <Show when=move || !generated()>
            <p class="cfg-note">{icon(I::Info)}<span>{move || ctx.tr(K::NotGenerated)}</span></p>
        </Show>
        {move || {
            // Suivi direct (pas seulement par `values`) : une édition refusée redessine les
            // contrôles avec leur valeur réelle, même si les valeurs n'ont pas changé.
            ed.entries.track();
            let q = query.get().trim().to_lowercase();
            let lang = ctx.lang.get();
            let vals = values.get();
            let gen_ = generated();
            let ver = version.get();
            let get = |k: &str| vals.iter().rev().find(|(x, _)| x == k).map(|(_, v)| v.clone());
            let mut out: Vec<AnyView> = Vec::new();
            for g in GROUPS {
                let rows: Vec<AnyView> = PROPS
                    .iter()
                    .filter(|p| p.group == g)
                    .filter(|p| get(p.key).is_some() || (!gen_ && schema::in_version(p, &ver)))
                    .filter(|p| q.is_empty() || matches_prop(p, &q, lang))
                    .map(|p| prop_row(ctx, ed, p, get(p.key), lang))
                    .collect();
                if !rows.is_empty() {
                    out.push(view! {
                        <section class="cfg-group"><h3 class="cfg-group-title">{ctx.tr(group_key(g))}</h3>{rows}</section>
                    }.into_any());
                }
            }
            // Clés inconnues (mods, plugins, versions futures) : gardées et éditables en texte libre.
            let others: Vec<AnyView> = vals
                .iter()
                .filter(|(k, _)| schema::prop(k).is_none())
                .filter(|(k, _)| q.is_empty() || k.to_lowercase().contains(&q))
                .map(|(k, v)| {
                    let key = k.clone();
                    view! {
                        <div class="cfg-row">
                            <div class="cfg-text"><div class="cfg-label"><code class="cfg-key solo">{k.clone()}</code></div></div>
                            <div class="cfg-ctl">
                                <input type="text" aria-label=k.clone() spellcheck="false" prop:value=v.clone()
                                    on:change=move |ev| set_prop(ctx, ed, &key, event_target_value(&ev))/>
                            </div>
                        </div>
                    }.into_any()
                })
                .collect();
            if !others.is_empty() {
                out.push(view! {
                    <section class="cfg-group"><h3 class="cfg-group-title">{ctx.tr(K::GroupOthers)}</h3>{others}</section>
                }.into_any());
            }
            if out.is_empty() {
                out.push(view! { <p class="faint cfg-nomatch">{ctx.tr(K::NoMatch)}</p> }.into_any());
            }
            out.into_iter().collect_view()
        }}
    }
}

// ---------------------------------------------------------------------------------------------
// Arbre (YAML, JSON, TOML)

/// Valeur saisie dans une liste : même type que ses éléments quand c'est possible.
fn typed_like(siblings: &[ConfigValue], raw: &str) -> ConfigValue {
    let raw = raw.trim();
    match siblings.first() {
        Some(ConfigValue::Int(_)) if raw.parse::<i64>().is_ok() => ConfigValue::Int(raw.parse().unwrap_or(0)),
        Some(ConfigValue::Float(_)) if raw.parse::<f64>().is_ok() => ConfigValue::Float(raw.parse().unwrap_or(0.0)),
        Some(ConfigValue::Bool(_)) if raw == "true" || raw == "false" => ConfigValue::Bool(raw == "true"),
        _ => ConfigValue::Str(raw.to_string()),
    }
}

fn value_control(ctx: Ctx, ed: Ed, path: Vec<ConfigSeg>, v: ConfigValue, label: String) -> AnyView {
    let set = move |value: ConfigValue| ed.edit(ctx, ConfigEdit::Set { path: path.clone(), value });
    match v {
        ConfigValue::Bool(b) => view! {
            <label class="switch cfg-switch">
                <input type="checkbox" role="switch" aria-label=label prop:checked=b
                    on:change=move |ev| set(ConfigValue::Bool(event_target_checked(&ev)))/>
                <span class="switch-track" aria-hidden="true"></span>
            </label>
        }
        .into_any(),
        ConfigValue::Int(n) => view! {
            <input type="number" class="cfg-num" step="1" aria-label=label prop:value=n.to_string()
                on:change=move |ev| {
                    match event_target_value(&ev).trim().parse::<i64>() {
                        Ok(x) => set(ConfigValue::Int(x)),
                        Err(_) => ed.msg.set(Some(K::OutOfRange)),
                    }
                }/>
        }
        .into_any(),
        ConfigValue::Float(f) => view! {
            <input type="number" class="cfg-num" step="any" aria-label=label prop:value=f.to_string()
                on:change=move |ev| {
                    match event_target_value(&ev).trim().parse::<f64>() {
                        Ok(x) => set(ConfigValue::Float(x)),
                        Err(_) => ed.msg.set(Some(K::OutOfRange)),
                    }
                }/>
        }
        .into_any(),
        ConfigValue::Str(s) => view! {
            <input type="text" spellcheck="false" aria-label=label prop:value=s
                on:change=move |ev| set(ConfigValue::Str(event_target_value(&ev)))/>
        }
        .into_any(),
        ConfigValue::Null => view! {
            <input type="text" spellcheck="false" aria-label=label placeholder="null"
                on:change=move |ev| {
                    let v = event_target_value(&ev);
                    if !v.is_empty() { set(ConfigValue::Str(v)) }
                }/>
        }
        .into_any(),
    }
}

/// Commentaire du fichier en aide : lignes décoratives (`=====`) retirées ; au-delà de deux
/// lignes, la première seule est montrée et le reste se déplie.
fn help_block(text: &str) -> Option<AnyView> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| l.chars().any(char::is_alphanumeric)).collect();
    let (first, rest) = lines.split_first()?;
    let (all, more) = (lines.join("\n"), rest.join("\n"));
    if rest.len() < 2 && text.len() <= 200 {
        return Some(view! { <p class="cfg-help">{all}</p> }.into_any());
    }
    Some(
        view! {
            <details class="cfg-help cfg-more">
                <summary>{first.to_string()}</summary>
                <p>{more}</p>
            </details>
        }
        .into_any(),
    )
}

#[component]
fn TreeForm(ed: Ed, query: RwSignal<String>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let expanded = RwSignal::new(HashSet::<String>::new());
    view! {
        {move || {
            let q = query.get().trim().to_lowercase();
            let lang = ctx.lang.get();
            let file = ed.path.get();
            let open = expanded.get();
            ed.entries.with(|entries| {
                if entries.is_empty() {
                    // Chemin en double : bandeau au-dessus, rien de plus ici.
                    if ed.duplicate.with(Option::is_some) {
                        return ().into_any();
                    }
                    return view! { <p class="faint cfg-nomatch">{ctx.tr(K::VisualUnavailable)}</p> }.into_any();
                }
                let keys: Vec<String> = entries.iter().map(|e| pkey(&e.path)).collect();
                let label_of = |e: &ConfigEntry, key: &str| -> (String, Option<String>) {
                    let known = schema::known(&file, key);
                    let name = match e.path.last() {
                        Some(ConfigSeg::Key(k)) => k.clone(),
                        Some(ConfigSeg::Index(i)) => format!("#{}", i + 1),
                        None => String::new(),
                    };
                    match known {
                        Some(k) => {
                            let (l, h) = if lang == Lang::Fr { k.fr } else { k.en };
                            (l.to_string(), Some(h.to_string()))
                        }
                        None => (name, e.comment.clone()),
                    }
                };
                // Listes de valeurs simples : leurs éléments deviennent des pastilles.
                let chip_lists: HashSet<&str> = entries
                    .iter()
                    .zip(&keys)
                    .filter(|(e, _)| e.kind == EntryKind::List && e.editable_list)
                    .map(|(_, k)| k.as_str())
                    .collect();
                let parent_key = |e: &ConfigEntry| pkey(&e.path[..e.path.len().saturating_sub(1)]);
                // Recherche : entrées qui correspondent, et leurs parents.
                let shown: Option<HashSet<String>> = (!q.is_empty()).then(|| {
                    let mut s = HashSet::new();
                    for (e, k) in entries.iter().zip(&keys) {
                        let (l, h) = label_of(e, k);
                        let hit = k.to_lowercase().contains(&q)
                            || l.to_lowercase().contains(&q)
                            || h.is_some_and(|h| h.to_lowercase().contains(&q))
                            || e.value.as_ref().is_some_and(|v| show(v).to_lowercase().contains(&q));
                        if hit {
                            for n in 1..=e.path.len() {
                                s.insert(pkey(&e.path[..n]));
                            }
                        }
                    }
                    s
                });
                let mut rows: Vec<AnyView> = Vec::new();
                for (e, k) in entries.iter().zip(&keys) {
                    if e.path.len() > 1 && chip_lists.contains(parent_key(e).as_str()) {
                        continue;
                    }
                    let visible = match &shown {
                        Some(s) => s.contains(k),
                        None => (1..e.path.len()).all(|n| open.contains(&pkey(&e.path[..n]))),
                    };
                    if !visible {
                        continue;
                    }
                    let depth = (e.path.len() - 1).min(8);
                    let (label, help) = label_of(e, k);
                    let help_view = help.and_then(|h| help_block(&h));
                    let row = match e.kind {
                        EntryKind::Section | EntryKind::List if !e.editable_list => {
                            let is_open = shown.is_some() || open.contains(k);
                            let key = k.clone();
                            let count = entries.iter().filter(|x| x.path.len() == e.path.len() + 1 && x.path.starts_with(&e.path)).count();
                            view! {
                                <div class=format!("cfg-sec d{depth}")>
                                    <button type="button" class="cfg-sec-btn" class:open=is_open aria-expanded=is_open.to_string()
                                        on:click=move |_| expanded.update(|s| { if !s.remove(&key) { s.insert(key.clone()); } })>
                                        <span class="cfg-chev">{icon(I::Chevron)}</span>
                                        <span class="cfg-label">{label.clone()}</span>
                                        <span class="cfg-count">{count}</span>
                                    </button>
                                    {help_view}
                                </div>
                            }.into_any()
                        }
                        EntryKind::List => {
                            let items: Vec<(Vec<ConfigSeg>, ConfigValue)> = entries
                                .iter()
                                .filter(|x| x.path.len() == e.path.len() + 1 && x.path.starts_with(&e.path))
                                .filter_map(|x| x.value.clone().map(|v| (x.path.clone(), v)))
                                .collect();
                            let siblings: Vec<ConfigValue> = items.iter().map(|(_, v)| v.clone()).collect();
                            let path = e.path.clone();
                            let add = move |ev: leptos::ev::KeyboardEvent| {
                                if ev.key() == "Enter" {
                                    ev.prevent_default();
                                    let v = event_target_value(&ev);
                                    if !v.trim().is_empty() {
                                        ed.edit(ctx, ConfigEdit::Push { path: path.clone(), value: typed_like(&siblings, &v) });
                                    }
                                }
                            };
                            view! {
                                <div class=format!("cfg-row cfg-list d{depth}")>
                                    <div class="cfg-text"><div class="cfg-label">{label.clone()}</div>{help_view}</div>
                                    <div class="cfg-chips">
                                        {items.into_iter().map(|(p, v)| view! {
                                            <span class="cfg-chip">
                                                <span>{show(&v)}</span>
                                                <button type="button" aria-label=move || ctx.tr(K::RemoveItem)
                                                    on:click=move |_| ed.edit(ctx, ConfigEdit::Remove { path: p.clone() })>{icon(I::Close)}</button>
                                            </span>
                                        }).collect_view()}
                                        <input type="text" class="cfg-add" spellcheck="false" placeholder=move || ctx.tr(K::AddItem)
                                            aria-label=move || ctx.tr(K::AddItem) on:keydown=add/>
                                    </div>
                                </div>
                            }.into_any()
                        }
                        EntryKind::Value => {
                            let ctl = match e.value.clone() {
                                Some(v) => value_control(ctx, ed, e.path.clone(), v, label.clone()),
                                None => view! {
                                    <span class="cfg-raw"><code>{e.raw.clone().unwrap_or_default()}</code>
                                        <span class="faint small">{ctx.tr(K::EditAsText)}</span></span>
                                }.into_any(),
                            };
                            let admin = admin_only(&file, &e.path).then(|| admin_badge(ctx));
                            view! {
                                <div class=format!("cfg-row d{depth}")>
                                    <div class="cfg-text"><div class="cfg-label">{label.clone()}{admin}</div>{help_view}</div>
                                    <div class="cfg-ctl">{ctl}</div>
                                </div>
                            }.into_any()
                        }
                        EntryKind::Section => ().into_any(),
                    };
                    rows.push(row);
                }
                if rows.is_empty() {
                    return view! { <p class="faint cfg-nomatch">{ctx.tr(K::NoMatch)}</p> }.into_any();
                }
                view! { <div class="cfg-tree">{rows}</div> }.into_any()
            })
        }}
    }
}

// ---------------------------------------------------------------------------------------------
// Éditeur de texte

#[component]
pub(crate) fn CodeEditor(ed: Ed, jump: RwSignal<Option<u32>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let scroller = NodeRef::<leptos::html::Div>::new();
    let area = NodeRef::<leptos::html::Textarea>::new();
    let html = Memo::new(move |_| {
        let f = ed.format.get();
        ed.text.with(|t| highlight(f, t))
    });
    let lines = Memo::new(move |_| ed.text.with(|t| t.split('\n').count()));
    let gutter = move || {
        let err = ed.error.with(|e| e.as_ref().map(|e| e.line).filter(|l| *l > 0));
        (1..=lines.get())
            .map(|i| if Some(i as u32) == err { format!("<span class=\"ln-err\">{i}</span>") } else { i.to_string() })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let typing = StoredValue::new(0u64);
    let changed = move |v: String| {
        let merged = ed.text.with_untracked(|old| merge_eol(old, &v));
        ed.text.set(merged);
        typing.update_value(|t| *t += 1);
        let t = typing.get_value();
        set_timeout(
            move || {
                if typing.get_value() == t {
                    ed.check(ctx, Vec::new());
                }
            },
            Duration::from_millis(350),
        );
    };
    // Tabulation : deux espaces (YAML refuse les tabulations).
    let on_key = move |ev: leptos::ev::KeyboardEvent| {
        if ev.key() == "Tab" && !ev.shift_key() && !ev.ctrl_key() && !ev.alt_key() {
            ev.prevent_default();
            if let Some(a) = area.get() {
                let _ = a.set_range_text_with_start_and_end_and_mode(
                    "  ",
                    a.selection_start().ok().flatten().unwrap_or(0),
                    a.selection_end().ok().flatten().unwrap_or(0),
                    "end",
                );
                changed(a.value());
            }
        }
    };
    // Aller à la ligne de l'erreur.
    Effect::new(move |_| {
        let Some(line) = jump.get() else { return };
        let (Some(a), Some(s)) = (area.get(), scroller.get()) else { return };
        jump.set(None);
        let text = ed.text.get_untracked().replace("\r\n", "\n");
        let off: usize = text.split('\n').take(line as usize - 1).map(|l| l.encode_utf16().count() + 1).sum();
        let _ = a.focus();
        let _ = a.set_selection_range(off as u32, off as u32);
        s.set_scroll_top(((line as i32) - 4).max(0) * 20);
    });
    // La zone de saisie ne garde que `\n` (fins de ligne du fichier remises par `merge_eol`).
    let lf_text = move || ed.text.with(|t| t.replace("\r\n", "\n"));
    view! {
        <div class="code" node_ref=scroller>
            <pre class="code-gutter" aria-hidden="true" inner_html=gutter></pre>
            <div class="code-area">
                <pre class="code-hl" aria-hidden="true" inner_html=move || html.get()></pre>
                <textarea class="code-input" node_ref=area spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off"
                    aria-label=move || ed.path.get() prop:value=lf_text
                    on:input=move |ev| changed(event_target_value(&ev)) on:keydown=on_key></textarea>
            </div>
        </div>
    }
}

// ---------------------------------------------------------------------------------------------
// Écart avant enregistrement, historique

#[component]
pub(crate) fn DiffModal(
    ed: Ed,
    open: RwSignal<bool>,
    saving: RwSignal<bool>,
    on_save: impl Fn() + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let lines = diff_lines(&ed.original.get_untracked(), &ed.text.get_untracked());
    // Lignes identiques repliées au-delà de 3 lignes de contexte.
    let mut rows: Vec<AnyView> = Vec::new();
    let (mut old_n, mut new_n) = (0usize, 0usize);
    let mut i = 0;
    while i < lines.len() {
        if let DiffLine::Same(_) = &lines[i] {
            let run = lines[i..].iter().take_while(|l| matches!(l, DiffLine::Same(_))).count();
            let (head, tail) = (if i == 0 { 0 } else { 3 }, if i + run == lines.len() { 0 } else { 3 });
            if run > head + tail + 1 {
                for l in &lines[i..i + head] {
                    old_n += 1;
                    new_n += 1;
                    if let DiffLine::Same(t) = l {
                        rows.push(view! { <div class="dl same"><span class="dn">{new_n}</span><span class="dt">{t.clone()}</span></div> }.into_any());
                    }
                }
                let hidden = run - head - tail;
                old_n += hidden;
                new_n += hidden;
                rows.push(view! { <div class="dl fold"><span class="dn">"⋯"</span><span class="dt">{format!("{hidden} {}", ctx.tr(K::SameLines))}</span></div> }.into_any());
                for l in &lines[i + run - tail..i + run] {
                    old_n += 1;
                    new_n += 1;
                    if let DiffLine::Same(t) = l {
                        rows.push(view! { <div class="dl same"><span class="dn">{new_n}</span><span class="dt">{t.clone()}</span></div> }.into_any());
                    }
                }
                i += run;
                continue;
            }
        }
        match &lines[i] {
            DiffLine::Same(t) => {
                old_n += 1;
                new_n += 1;
                rows.push(view! { <div class="dl same"><span class="dn">{new_n}</span><span class="dt">{t.clone()}</span></div> }.into_any());
            }
            DiffLine::Removed(t) => {
                old_n += 1;
                rows.push(
                    view! { <div class="dl del"><span class="dn">"−"</span><span class="dt">{t.clone()}</span></div> }
                        .into_any(),
                );
            }
            DiffLine::Added(t) => {
                new_n += 1;
                rows.push(view! { <div class="dl add"><span class="dn">{new_n}</span><span class="dt">{t.clone()}</span></div> }.into_any());
            }
        }
        i += 1;
    }
    let _ = old_n;
    let empty = rows.is_empty() || lines.iter().all(|l| matches!(l, DiffLine::Same(_)));
    view! {
        <div class="overlay" on:click=move |_| open.set(false)></div>
        <div class="modal" role="dialog" aria-modal="true" aria-label=move || ctx.tr(K::ReviewChanges)>
            <div class="sheet-head">
                <h2>{move || ctx.tr(K::ReviewChanges)}</h2>
                <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::Close) on:click=move |_| open.set(false)>{icon(I::Close)}</button>
            </div>
            <div class="diff">
                {if empty { view! { <p class="faint">{move || ctx.tr(K::NoChange)}</p> }.into_any() } else { rows.into_iter().collect_view().into_any() }}
            </div>
            <div class="row modal-actions">
                <button type="button" class="btn ghost" on:click=move |_| open.set(false)>{move || ctx.tr(K::Back)}</button>
                <button type="button" class="btn primary" disabled=move || saving.get() || empty on:click=move |_| on_save()>
                    {icon(I::Save)}{move || ctx.tr(K::Save)}
                </button>
            </div>
        </div>
    }
}

#[component]
fn HistorySheet(ed: Ed, open: RwSignal<bool>, diff_open: RwSignal<bool>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let list = RwSignal::new(None::<Vec<ConfigVersion>>);
    let msg = RwSignal::new(None::<K>);
    let id = ed.id;
    let path = ed.path.get_untracked();
    spawn_local(async move {
        match api::get::<Vec<ConfigVersion>>(&format!("/api/servers/{id}/config/history?path={}", enc(&path))).await {
            Ok(l) => list.set(Some(l)),
            Err(e) => {
                list.set(Some(Vec::new()));
                ctx.on_err(&e, msg);
            }
        }
    });
    let restore = move |vid: i64| {
        // Le texte en cours de modification serait remplacé : demandé d'abord.
        if ed.dirty() && !confirm(ctx.tr(K::DiscardChanges)) {
            return;
        }
        spawn_local(async move {
            match api::get::<ConfigVersionContent>(&format!("/api/servers/{id}/config/history/{vid}")).await {
                // Version d'un autre fichier (onglet changé pendant la requête) : ignorée.
                Ok(v) if ed.path.with_untracked(|p| *p == v.path) => {
                    ed.text.set(v.text);
                    ed.check(ctx, Vec::new());
                    open.set(false);
                    diff_open.set(true);
                }
                Ok(_) => open.set(false),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    view! {
        <div class="overlay" on:click=move |_| open.set(false)></div>
        <aside class="sheet" role="dialog" aria-modal="true" aria-label=move || ctx.tr(K::History)>
            <div class="sheet-head">
                <h2>{move || ctx.tr(K::History)}</h2>
                <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::Close) on:click=move |_| open.set(false)>{icon(I::Close)}</button>
            </div>
            <Msg msg=msg/>
            {move || match list.get() {
                None => view! { <div class="cfg-skeleton skeleton"></div> }.into_any(),
                Some(l) if l.is_empty() => view! { <p class="faint">{move || ctx.tr(K::HistoryEmpty)}</p> }.into_any(),
                Some(l) => view! {
                    <ul class="hist">
                        {l.into_iter().map(|v| {
                            let lang = ctx.lang.get_untracked();
                            let who = v.user.clone().unwrap_or_default();
                            view! {
                                <li class="hist-item">
                                    <span class="hist-text">
                                        <span>{local_datetime(v.ts, lang)}</span>
                                        <span class="faint small">{format!("{who} · {}", fmt_size(v.size, lang))}</span>
                                    </span>
                                    <button type="button" class="btn small" on:click=move |_| restore(v.id)>{icon(I::Undo)}{move || ctx.tr(K::Restore)}</button>
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                }.into_any(),
            }}
        </aside>
    }
}
