//! Onglet « Fichiers » d'un serveur : navigation dans le dossier du serveur, aperçu et édition des
//! fichiers texte (éditeur coloré et vérification des réglages), envoi (glisser-déposer, plusieurs
//! fichiers, progression), téléchargement (dossier en zip), création, renommage, déplacement,
//! corbeille. Toutes les gardes sont côté serveur ; l'interface ne fait qu'éviter les impasses.

use crate::api::{self, ApiErr};
use crate::configs::{CodeEditor, DiffModal, Ed};
use crate::i18n::{K, Lang};
use crate::icons::{I, icon};
use crate::{Ctx, Msg};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;

fn enc(s: &str) -> String {
    js_sys::encode_uri_component(s).as_string().unwrap_or_default()
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") }
}

fn parent(p: &str) -> String {
    p.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default()
}

/// Taille lisible (o, Ko, Mo, Go).
fn fmt_size(b: u64, lang: Lang) -> String {
    let units: [&str; 4] = if lang == Lang::Fr { ["o", "Ko", "Mo", "Go"] } else { ["B", "KB", "MB", "GB"] };
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < 3 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{b} {}", units[0]) } else { format!("{} {}", crate::fmt_dec(v as f32, 1, lang), units[u]) }
}

fn local_date(unix: i64, lang: Lang) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(unix as f64 * 1000.0));
    let opts = js_sys::Object::new();
    for (k, v) in
        [("day", "2-digit"), ("month", "2-digit"), ("year", "numeric"), ("hour", "2-digit"), ("minute", "2-digit")]
    {
        let _ = js_sys::Reflect::set(&opts, &k.into(), &v.into());
    }
    d.to_locale_string(lang.code(), &opts).into()
}

/// Icône et teinte d'une entrée selon sa nature et son extension.
fn entry_icon(e: &FileEntry) -> (I, &'static str) {
    if e.kind == FileKind::Dir {
        return (I::Folder, "t-accent");
    }
    if e.kind == FileKind::Link {
        return (I::Move, "t-warn");
    }
    let ext = e.name.rsplit_once('.').map(|(_, x)| x.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "jar" | "class" => (I::Cube, "t-gold"),
        "zip" | "gz" | "tgz" | "xz" | "7z" | "rar" => (I::Archive, "t-gold"),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" => (I::Image, "t-accent-2"),
        "properties" | "yml" | "yaml" | "toml" | "cfg" | "conf" | "ini" => (I::Sliders, "t-accent-2"),
        "json" | "json5" | "mcmeta" => (I::Braces, "t-accent-2"),
        "log" | "txt" | "md" => (I::FileText, "t-faint"),
        "sh" | "bat" | "cmd" | "ps1" => (I::Command, "t-danger"),
        _ if !e.editable => (I::Binary, "t-faint"),
        _ => (I::FileText, "t-faint"),
    }
}

/// Envoi en cours ou terminé (barre de progression, erreur, « remplacer »).
#[derive(Clone, PartialEq)]
struct Upload {
    key: u64,
    name: String,
    dir: String,
    size: f64,
    sent: f64,
    done: bool,
    error: Option<K>,
    exists: bool,
}

/// Vue de l'onglet.
#[derive(Clone, PartialEq)]
enum View {
    List,
    Edit(String),
    /// Fichier non éditable : informations et téléchargement.
    Info(FileEntry, String),
    Trash,
}

#[derive(Clone, PartialEq)]
enum Dialog {
    NewDir,
    NewFile,
    Rename(String),
    Delete(String, bool),
}

#[component]
pub fn FilesTab(id: i64, #[prop(into)] info: Signal<Option<ServerInfo>>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let path = RwSignal::new(String::new());
    let list = RwSignal::new(None::<FileList>);
    let view_ = RwSignal::new(View::List);
    let msg = RwSignal::new(None::<K>);
    let dialog = RwSignal::new(None::<Dialog>);
    let uploads = RwSignal::new(Vec::<Upload>::new());
    let next_key = StoredValue::new(0u64);
    let dragging = RwSignal::new(false);
    let trash = RwSignal::new(None::<Vec<TrashItem>>);
    let file_input = NodeRef::<leptos::html::Input>::new();
    let running = move || info.with(|i| i.as_ref().is_some_and(|i| i.state == ServerState::Running));
    let busy = move || {
        info.with(|i| {
            i.as_ref()
                .is_some_and(|i| i.op.is_some() || matches!(i.state, ServerState::Starting | ServerState::Stopping))
        })
    };

    // Dossier illisible ou disparu : ni « dossier vide », ni dépôt possible.
    let failed = RwSignal::new(false);
    let load = move |p: String| {
        msg.set(None);
        spawn_local(async move {
            match api::get::<FileList>(&format!("/api/servers/{id}/files?path={}", enc(&p))).await {
                Ok(l) if path.get_untracked() == l.path => {
                    failed.set(false);
                    list.set(Some(l));
                }
                Ok(_) => {}
                Err(e) => {
                    failed.set(true);
                    list.set(Some(FileList { path: p, entries: Vec::new(), truncated: false, world: false }));
                    ctx.on_err(&e, msg);
                }
            }
        });
    };
    let go_dir = move |p: String| {
        if !crate::may_leave(ctx) {
            return;
        }
        path.set(p.clone());
        list.set(None);
        view_.set(View::List);
        load(p);
    };
    load(String::new());
    let reload = move || load(path.get_untracked());
    let load_trash = move || {
        spawn_local(async move {
            match api::get::<Vec<TrashItem>>(&format!("/api/servers/{id}/files/trash")).await {
                Ok(t) => trash.set(Some(t)),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    let post = move |what: &'static str, body: serde_json::Value, then: Box<dyn Fn()>| {
        let csrf = ctx.csrf();
        msg.set(None);
        spawn_local(async move {
            match api::post_empty(&format!("/api/servers/{id}/files/{what}"), &body, csrf.as_deref()).await {
                Ok(()) => then(),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };

    // Envoi d'un fichier par XMLHttpRequest (progression de l'envoi).
    let start_upload = move |file: web_sys::File, dir: String, overwrite: bool, key: Option<u64>| {
        let key = key.unwrap_or_else(|| {
            next_key.update_value(|k| *k += 1);
            next_key.get_value()
        });
        let name = file.name();
        let item = Upload {
            key,
            name: name.clone(),
            dir: dir.clone(),
            size: file.size(),
            sent: 0.0,
            done: false,
            error: None,
            exists: false,
        };
        uploads.update(|u| match u.iter_mut().find(|x| x.key == key) {
            Some(x) => *x = item.clone(),
            None => u.push(item.clone()),
        });
        let set = move |f: &dyn Fn(&mut Upload)| uploads.update(|u| u.iter_mut().filter(|x| x.key == key).for_each(f));
        let Ok(xhr) = web_sys::XmlHttpRequest::new() else { return };
        let url =
            format!("/api/servers/{id}/files/upload?path={}&name={}&overwrite={overwrite}", enc(&dir), enc(&name));
        if xhr.open("POST", &url).is_err() {
            return;
        }
        let _ = xhr.set_request_header("content-type", "application/octet-stream");
        if let Some(t) = ctx.csrf() {
            let _ = xhr.set_request_header(CSRF_HEADER, &t);
        }
        let progress = Closure::<dyn FnMut(web_sys::ProgressEvent)>::new(move |ev: web_sys::ProgressEvent| {
            let sent = ev.loaded();
            set(&|x: &mut Upload| x.sent = sent);
        });
        if let Ok(up) = xhr.upload() {
            up.set_onprogress(Some(progress.as_ref().unchecked_ref()));
        }
        let x2 = xhr.clone();
        let file2 = file.clone();
        let onload = Closure::once_into_js(move || {
            drop(progress);
            let status = x2.status().unwrap_or(0);
            if (200..300).contains(&status) {
                set(&|x: &mut Upload| {
                    x.done = true;
                    x.sent = x.size;
                });
                if path.get_untracked() == dir {
                    reload();
                }
                return;
            }
            let text = x2.response_text().ok().flatten().unwrap_or_default();
            let code = serde_json::from_str::<ApiError>(&text).map(|e| e.code).unwrap_or(ErrorCode::Internal);
            if code == ErrorCode::Unauthorized {
                ctx.on_err(&ApiErr::Api(code), msg);
            }
            let k = ctx.err(&ApiErr::Api(code));
            set(&|x: &mut Upload| {
                x.error = Some(k);
                x.exists = code == ErrorCode::AlreadyExists;
            });
            // Garde le fichier pour « Remplacer ».
            PENDING.with(|p| p.borrow_mut().insert(key, file2.clone()));
        });
        xhr.set_onload(Some(onload.unchecked_ref()));
        let onerror = Closure::once_into_js(move || {
            set(&|x: &mut Upload| x.error = Some(K::ErrNetwork));
        });
        xhr.set_onerror(Some(onerror.unchecked_ref()));
        let _ = xhr.send_with_opt_blob(Some(&file));
    };
    let upload_files = move |files: web_sys::FileList| {
        let dir = path.get_untracked();
        for i in 0..files.length() {
            if let Some(f) = files.get(i) {
                start_upload(f, dir.clone(), false, None);
            }
        }
    };
    let replace = move |key: u64| {
        let f = PENDING.with(|p| p.borrow_mut().remove(&key));
        let dir =
            uploads.with_untracked(|u| u.iter().find(|x| x.key == key).map(|x| x.dir.clone())).unwrap_or_default();
        if let Some(f) = f {
            start_upload(f, dir, true, Some(key));
        }
    };

    let crumbs = move || {
        let p = path.get();
        let mut acc = String::new();
        let mut out = vec![(String::new(), ctx.tr(K::ServerFolder).to_string())];
        for seg in p.split('/').filter(|s| !s.is_empty()) {
            acc = join(&acc, seg);
            out.push((acc.clone(), seg.to_string()));
        }
        out
    };
    let open_entry = move |e: FileEntry| {
        let full = join(&path.get_untracked(), &e.name);
        match e.kind {
            FileKind::Dir => go_dir(full),
            FileKind::Link => msg.set(Some(K::LinkNotFollowed)),
            FileKind::File if e.editable => view_.set(View::Edit(full)),
            FileKind::File => view_.set(View::Info(e, full)),
        }
    };
    let download_url = move |p: &str| format!("/api/servers/{id}/files/download?path={}", enc(p));

    view! {
        <div class="fm" class:dragging=move || dragging.get()
            on:dragover=move |ev: leptos::ev::DragEvent| { ev.prevent_default(); dragging.set(true); }
            on:dragleave=move |ev: leptos::ev::DragEvent| {
                // Quitte vraiment la zone (pas un enfant).
                if ev.related_target().is_none() { dragging.set(false); }
            }
            on:drop=move |ev: leptos::ev::DragEvent| {
                ev.prevent_default();
                dragging.set(false);
                if failed.get_untracked() { return; }
                if let Some(f) = ev.data_transfer().and_then(|d| d.files()) { upload_files(f); }
            }>
            <div class="fm-bar">
                <nav class="crumbs fm-crumbs" aria-label=move || ctx.tr(K::Navigation)>
                    {move || {
                        let c = crumbs();
                        let last = c.len() - 1;
                        c.into_iter().enumerate().map(|(i, (p, label))| {
                            let p2 = p.clone();
                            view! {
                                {(i > 0).then(|| view! { <span class="crumb-sep" aria-hidden="true">"/"</span> })}
                                <button type="button" class="crumb" class:here=i == last aria-current=(i == last).then_some("page")
                                    on:click=move |_| go_dir(p2.clone())>
                                    {(i == 0).then(|| icon(I::Folder))}{label}
                                </button>
                            }
                        }).collect_view()
                    }}
                </nav>
                <div class="fm-actions">
                    <button type="button" class="btn small" disabled=busy aria-label=move || ctx.tr(K::NewFolder) on:click=move |_| dialog.set(Some(Dialog::NewDir))>
                        {icon(I::Folder)}<span>{move || ctx.tr(K::NewFolder)}</span></button>
                    <button type="button" class="btn small" disabled=busy aria-label=move || ctx.tr(K::NewFile) on:click=move |_| dialog.set(Some(Dialog::NewFile))>
                        {icon(I::Plus)}<span>{move || ctx.tr(K::NewFile)}</span></button>
                    <button type="button" class="btn small primary" disabled=move || busy() || failed.get() aria-label=move || ctx.tr(K::Upload)
                        on:click=move |_| { if let Some(i) = file_input.get() { i.click(); } }>
                        {icon(I::Upload)}<span>{move || ctx.tr(K::Upload)}</span></button>
                    <input type="file" multiple=true class="sr-only" node_ref=file_input tabindex="-1" aria-hidden="true"
                        on:change=move |ev| {
                            let t: web_sys::HtmlInputElement = event_target(&ev);
                            if let Some(f) = t.files() { upload_files(f); }
                            t.set_value("");
                        }/>
                    <a class="btn small icon-btn ghost" href=move || download_url(&path.get()) download=""
                        aria-label=move || ctx.tr(K::DownloadZip) title=move || ctx.tr(K::DownloadZip)>{icon(I::Download)}</a>
                    <button type="button" class="btn small icon-btn ghost" class:on=move || view_.get() == View::Trash
                        aria-label=move || ctx.tr(K::Trash) title=move || ctx.tr(K::Trash)
                        on:click=move |_| {
                            if view_.get_untracked() == View::Trash { view_.set(View::List); }
                            else if crate::may_leave(ctx) { load_trash(); view_.set(View::Trash); }
                        }>
                        {icon(I::Trash)}</button>
                </div>
            </div>
            <Msg msg=msg/>
            <Show when=move || uploads.with(|u| !u.is_empty())>
                <ul class="fm-uploads">
                    <For each=move || uploads.get() key=|u| (u.key, u.done, u.error.is_some(), u.sent as u64) let:u>
                        {
                            let pct = if u.size > 0.0 { (u.sent / u.size * 100.0).clamp(0.0, 100.0) } else { 100.0 };
                            let key = u.key;
                            view! {
                                <li class="fm-up" class:fm-up-bad=u.error.is_some() class:fm-up-done=u.done>
                                    {if u.done { icon(I::Check).into_any() } else if u.error.is_some() { icon(I::Error).into_any() } else { icon(I::Upload).into_any() }}
                                    <span class="fm-up-name">{u.name.clone()}</span>
                                    {match u.error {
                                        Some(k) => view! { <span class="fm-up-err">{move || ctx.tr(k)}</span> }.into_any(),
                                        None => view! { <span class="pbar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow=format!("{pct:.0}")>
                                            <span class="pbar-fill" style:width=format!("{pct:.1}%")></span></span> }.into_any(),
                                    }}
                                    {u.exists.then(|| view! {
                                        <button type="button" class="btn small" on:click=move |_| replace(key)>{move || ctx.tr(K::Replace)}</button>
                                    })}
                                </li>
                            }
                        }
                    </For>
                    <li class="fm-up-clear">
                        <button type="button" class="btn small ghost" on:click=move |_| uploads.update(|u| u.retain(|x| !x.done && x.error.is_none()))>
                            {move || ctx.tr(K::ClearDone)}</button>
                    </li>
                </ul>
            </Show>
            <Show when=move || running() && list.with(|l| l.as_ref().is_some_and(|l| l.world))>
                <div class="banner warn" role="status">{icon(I::Lock)}<span>{move || ctx.tr(K::WorldReadOnly)}</span></div>
            </Show>
            {move || match view_.get() {
                View::List => view! { <FileListView list=list failed=failed go_dir=go_dir busy=Signal::derive(busy) open_entry=open_entry dialog=dialog
                    download_url=download_url/> }.into_any(),
                View::Edit(p) => {
                    // Pas du texte UTF-8, ou trop grand : vue « téléchargement » au lieu d'un éditeur vide.
                    let unreadable = move |p: String| {
                        let name = p.rsplit('/').next().unwrap_or(&p).to_string();
                        match list.with_untracked(|l| l.as_ref().and_then(|l| l.entries.iter().find(|e| e.name == name).cloned())) {
                            Some(e) => view_.set(View::Info(e, p)),
                            None => view_.set(View::List),
                        }
                    };
                    view! { <FileEditor id=id path=p back=move || { view_.set(View::List); reload(); } unreadable=unreadable busy=Signal::derive(busy)/> }.into_any()
                }
                View::Info(e, p) => {
                    let (ico, tone) = entry_icon(&e);
                    let lang = ctx.lang.get_untracked();
                    view! {
                        <section class="panel fm-info">
                            <span class=format!("fm-big {tone}")>{icon(ico)}</span>
                            <h2>{e.name.clone()}</h2>
                            <p class="faint">{format!("{} · {}", fmt_size(e.size, lang), local_date(e.modified, lang))}</p>
                            <p class="muted small">{move || ctx.tr(K::NotEditable)}</p>
                            <div class="row">
                                <a class="btn primary" href=download_url(&p) download="">{icon(I::Download)}{move || ctx.tr(K::Download)}</a>
                                <button type="button" class="btn" on:click=move |_| view_.set(View::List)>{move || ctx.tr(K::Back)}</button>
                            </div>
                        </section>
                    }.into_any()
                }
                View::Trash => view! { <TrashView id=id trash=trash msg=msg reload=reload busy=Signal::derive(busy)/> }.into_any(),
            }}
            <div class="fm-drop" aria-hidden="true">{icon(I::Upload)}<span>{move || ctx.tr(K::DropHere)}</span></div>
        </div>
        {move || dialog.get().map(|d| view! { <FileDialog id=id d=d path=path dialog=dialog post=post reload=reload view_=view_/> })}
    }
}

thread_local! {
    /// Fichiers refusés (« existe déjà ») gardés pour un nouvel envoi avec remplacement.
    static PENDING: std::cell::RefCell<std::collections::HashMap<u64, web_sys::File>> = Default::default();
}

#[component]
fn FileListView(
    list: RwSignal<Option<FileList>>,
    failed: RwSignal<bool>,
    go_dir: impl Fn(String) + Copy + Send + Sync + 'static,
    busy: Signal<bool>,
    open_entry: impl Fn(FileEntry) + Copy + Send + Sync + 'static,
    dialog: RwSignal<Option<Dialog>>,
    download_url: impl Fn(&str) -> String + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    view! {
        {move || match list.get() {
            None => view! { <div class="cfg-skeleton skeleton"></div> }.into_any(),
            // Lecture ratée (message affiché au-dessus) : seulement le chemin du retour.
            Some(l) if failed.get() => {
                let up = parent(&l.path);
                let root = l.path.is_empty();
                view! {
                    <div class="state-block panel fm-empty">{icon(I::Error)}
                        {(!root).then(|| view! {
                            <button type="button" class="btn small" on:click=move |_| go_dir(up.clone())>
                                {icon(I::Up)}{move || ctx.tr(K::ParentFolder)}</button>
                        })}
                    </div>
                }.into_any()
            }
            Some(l) if l.entries.is_empty() => view! {
                <div class="state-block panel fm-empty">{icon(I::Folder)}<p class="muted">{move || ctx.tr(K::EmptyFolder)}</p>
                    <p class="faint small">{move || ctx.tr(K::DropHere)}</p></div>
            }.into_any(),
            Some(l) => {
                let lang = ctx.lang.get_untracked();
                let dir = l.path.clone();
                view! {
                    <ul class="panel fm-list">
                        {(!dir.is_empty()).then(|| {
                            let up = parent(&dir);
                            view! { <li class="fm-row"><button type="button" class="fm-open" aria-label=move || ctx.tr(K::ParentFolder)
                                on:click=move |_| go_dir(up.clone())>
                                <span class="fm-ico t-faint">{icon(I::Up)}</span><span class="fm-name">".."</span></button></li> }
                        })}
                        {l.entries.into_iter().map(|e| {
                            let full = join(&dir, &e.name);
                            let (ico, tone) = entry_icon(&e);
                            let e2 = e.clone();
                            let (rn, del) = (full.clone(), full.clone());
                            let is_dir = e.kind == FileKind::Dir;
                            let size = if e.kind == FileKind::File { fmt_size(e.size, lang) } else { String::new() };
                            let date = if e.modified > 0 { local_date(e.modified, lang) } else { String::new() };
                            let name = e.name.clone();
                            view! {
                                <li class="fm-row" class:blocked=e.blocked>
                                    <button type="button" class="fm-open" disabled=e.blocked on:click=move |_| open_entry(e2.clone())>
                                        <span class=format!("fm-ico {tone}")>{icon(ico)}</span>
                                        <span class="fm-name">{name.clone()}</span>
                                        {e.sensitive.then(|| view! { <span class="fm-badge t-warn" title=move || ctx.tr(K::Sensitive) aria-label=move || ctx.tr(K::Sensitive) role="img">{icon(I::Key)}</span> })}
                                        {e.managed.then(|| view! { <span class="fm-badge t-faint" title=move || ctx.tr(K::ManagedByScreen) aria-label=move || ctx.tr(K::ManagedByScreen) role="img">{icon(I::Lock)}</span> })}
                                        <span class="fm-size num">{size}</span>
                                        <span class="fm-date num">{date}</span>
                                    </button>
                                    {(e.kind != FileKind::Link && !e.blocked).then(|| view! {
                                        <span class="fm-acts">
                                            <a class="btn icon-btn ghost small" href=download_url(&full) download=""
                                                aria-label=move || ctx.tr(if is_dir { K::DownloadZip } else { K::Download })
                                                title=move || ctx.tr(if is_dir { K::DownloadZip } else { K::Download })>{icon(I::Download)}</a>
                                            <button type="button" class="btn icon-btn ghost small" disabled=move || busy.get() || e.managed
                                                aria-label=move || ctx.tr(K::Rename) title=move || ctx.tr(K::Rename)
                                                on:click=move |_| dialog.set(Some(Dialog::Rename(rn.clone())))>{icon(I::Pencil)}</button>
                                            <button type="button" class="btn icon-btn ghost small danger-ghost" disabled=move || busy.get() || e.managed
                                                aria-label=move || ctx.tr(K::ToTrash) title=move || ctx.tr(K::ToTrash)
                                                on:click=move |_| dialog.set(Some(Dialog::Delete(del.clone(), is_dir)))>{icon(I::Trash)}</button>
                                        </span>
                                    })}
                                </li>
                            }
                        }).collect_view()}
                        {l.truncated.then(|| view! { <li class="fm-row faint small">{move || ctx.tr(K::ListTruncated)}</li> })}
                    </ul>
                }.into_any()
            }
        }}
    }
}

/// Fenêtres : nouveau dossier, nouveau fichier, renommer ou déplacer, mettre à la corbeille.
#[component]
fn FileDialog(
    id: i64,
    d: Dialog,
    path: RwSignal<String>,
    dialog: RwSignal<Option<Dialog>>,
    post: impl Fn(&'static str, serde_json::Value, Box<dyn Fn()>) + Copy + Send + Sync + 'static,
    reload: impl Fn() + Copy + Send + Sync + 'static,
    view_: RwSignal<View>,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let dir = path.get_untracked();
    let admin = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.is_admin));
    let totp_on = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
    // Suppression : erreur dans la fenêtre ; trop gros pour la corbeille (administrateur) :
    // effacement définitif proposé, avec ré-authentification.
    let dmsg = RwSignal::new(None::<K>);
    let erase = RwSignal::new(false);
    let pw = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let sending = RwSignal::new(false);
    let (title, init, label) = match &d {
        Dialog::NewDir => (K::NewFolder, String::new(), K::Name),
        Dialog::NewFile => (K::NewFile, String::new(), K::Name),
        Dialog::Rename(p) => (K::Rename, p.clone(), K::NewPath),
        Dialog::Delete(_, true) => (K::DeleteFolder, String::new(), K::TypeNameToConfirm),
        Dialog::Delete(_, false) => (K::ToTrash, String::new(), K::Name),
    };
    let value = RwSignal::new(init);
    let close = move || dialog.set(None);
    let d2 = d.clone();
    let ok = move || {
        let v = value.get_untracked().trim().to_string();
        let done: Box<dyn Fn()> = Box::new(move || {
            dialog.set(None);
            reload();
        });
        match &d2 {
            Dialog::NewDir => post("mkdir", serde_json::json!({ "path": join(&dir, &v) }), done),
            Dialog::NewFile => {
                let p = join(&dir, &v);
                let p2 = p.clone();
                post(
                    "write",
                    // Texte valide pour le format (`{}` en JSON : un texte vide serait refusé).
                    serde_json::json!({ "path": p, "text": ConfigFormat::new_file_text(&v) }),
                    Box::new(move || {
                        dialog.set(None);
                        view_.set(View::Edit(p2.clone()));
                    }),
                )
            }
            Dialog::Rename(from) => post("move", serde_json::json!({ "from": from, "to": v }), done),
            Dialog::Delete(p, _) => {
                let csrf = ctx.csrf();
                let p = p.clone();
                sending.set(true);
                dmsg.set(None);
                spawn_local(async move {
                    let res = if erase.get_untracked() {
                        let req = FileEraseRequest {
                            path: p,
                            confirm: v,
                            reauth: Reauth {
                                password: pw.get_untracked(),
                                code: totp_on().then(|| code.get_untracked()),
                            },
                        };
                        pw.set(String::new());
                        code.set(String::new());
                        api::post_empty(&format!("/api/servers/{id}/files/erase"), &req, csrf.as_deref()).await
                    } else {
                        let req = FileDeleteRequest { path: p, confirm: v };
                        api::post_empty(&format!("/api/servers/{id}/files/delete"), &req, csrf.as_deref()).await
                    };
                    sending.set(false);
                    match res {
                        Ok(()) => done(),
                        Err(ApiErr::Api(ErrorCode::TrashTooLarge)) if admin() => {
                            erase.set(true);
                            dmsg.set(Some(K::ErrTrashTooLarge));
                        }
                        Err(e) => ctx.on_err(&e, dmsg),
                    }
                });
            }
        }
    };
    let target_name = match &d {
        Dialog::Delete(p, _) => p.rsplit('/').next().unwrap_or(p).to_string(),
        _ => String::new(),
    };
    let tn = StoredValue::new(target_name.clone());
    let folder_delete = matches!(d, Dialog::Delete(_, true));
    let is_delete = matches!(d, Dialog::Delete(..));
    let needs_input = !matches!(d, Dialog::Delete(_, false));
    // Dossier : nom recopié à l'identique ; fichier : rien à saisir ; sinon : un nom.
    let can = move || {
        if folder_delete {
            value.with(|v| tn.with_value(|t| v == t))
        } else {
            !needs_input || value.with(|v| !v.trim().is_empty())
        }
    };
    view! {
        <div class="overlay" on:click=move |_| close()></div>
        <form class="modal fm-modal" role="dialog" aria-modal="true" aria-label=move || ctx.tr(title)
            on:submit=move |ev: leptos::ev::SubmitEvent| { ev.prevent_default(); if can() { ok(); } }>
            <h2>{move || ctx.tr(title)}</h2>
            {is_delete.then(|| view! { <p class="muted">{move || ctx.tr(K::TrashExplain)}" "<code>{target_name.clone()}</code></p> })}
            // Administrateur : la corbeille pleine fait partir les plus anciens (un compte ordinaire
            // est refusé, rien ne part).
            <Show when=move || is_delete && admin() && !erase.get()>
                <p class="faint small">{move || ctx.tr(K::TrashQuota)}</p>
            </Show>
            <Msg msg=dmsg/>
            {needs_input.then(|| view! {
                <label class="field">
                    <span class="field-label">{move || ctx.tr(label)}</span>
                    <input type="text" spellcheck="false" autocomplete="off" autocapitalize="off" maxlength="1024" autofocus=true
                        prop:value=move || value.get() on:input=move |ev| value.set(event_target_value(&ev))/>
                </label>
            })}
            <Show when=move || erase.get()>
                <p class="faint small">{move || ctx.tr(K::DeleteForeverConfirm)}</p>
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
            </Show>
            <div class="row modal-actions">
                <button type="button" class="btn" on:click=move |_| close()>{move || ctx.tr(K::Cancel)}</button>
                <button type="submit" class="btn" class:primary=!is_delete class:danger=is_delete disabled=move || !can() || sending.get()>
                    {if is_delete { icon(I::Trash).into_any() } else { icon(I::Check).into_any() }}
                    {move || ctx.tr(if erase.get() { K::DeleteForever } else { title })}
                </button>
            </div>
        </form>
    }
}

/// Éditeur d'un fichier texte : mêmes éditeur coloré, vérification et écart que les réglages.
#[component]
fn FileEditor(
    id: i64,
    path: String,
    back: impl Fn() + Copy + Send + Sync + 'static,
    unreadable: impl Fn(String) + Copy + Send + Sync + 'static,
    busy: Signal<bool>,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let msg = RwSignal::new(None::<K>);
    let ed = Ed::new(id, true, msg);
    crate::track_dirty(ed);
    let sensitive = RwSignal::new(false);
    let jump = RwSignal::new(None::<u32>);
    let diff_open = RwSignal::new(false);
    let saving = RwSignal::new(false);
    let saved = RwSignal::new(false);
    // Réglage enregistré serveur en marche : pris en compte au prochain démarrage.
    let restart = RwSignal::new(false);
    // « Enregistré » s'efface dès qu'on modifie de nouveau le fichier.
    Effect::new(move |_| {
        if ed.dirty() && saved.get_untracked() {
            saved.set(false);
        }
    });
    let conflict = RwSignal::new(false);
    let known = RwSignal::new(false);
    ed.path.set(path.clone());
    ed.loading.set(true);
    let open = move |p: String| {
        spawn_local(async move {
            match api::get::<FileText>(&format!("/api/servers/{id}/files/read?path={}", enc(&p))).await {
                Ok(f) => {
                    known.set(f.format.is_some());
                    ed.format.set(f.format.unwrap_or(ConfigFormat::Text));
                    ed.original.set(f.text.clone());
                    ed.hash.set(f.hash);
                    ed.text.set(f.text);
                    sensitive.set(f.sensitive);
                    conflict.set(false);
                    if f.format.is_some() {
                        ed.check(ctx, Vec::new());
                    }
                }
                Err(ApiErr::Api(ErrorCode::NotText | ErrorCode::FileTooLarge)) => unreadable(p.clone()),
                Err(e) => ctx.on_err(&e, msg),
            }
            ed.loading.set(false);
        });
    };
    open(path.clone());
    let can_save =
        move || ed.dirty() && ed.error.with(Option::is_none) && !saving.get() && !busy.get() && !ed.loading.get();
    let save = move || {
        saving.set(true);
        saved.set(false);
        let text = ed.text.get_untracked();
        let req =
            FileWriteRequest { path: ed.path.get_untracked(), text: text.clone(), base_hash: ed.hash.get_untracked() };
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post::<_, FileWritten>(&format!("/api/servers/{id}/files/write"), &req, csrf.as_deref()).await {
                Ok(w) => {
                    ed.original.set(text);
                    ed.hash.set(w.hash);
                    saved.set(!w.restart_needed);
                    restart.set(w.restart_needed);
                    msg.set(None);
                }
                Err(ApiErr::Api(ErrorCode::AlreadyExists)) => conflict.set(true),
                Err(e) => ctx.on_err(&e, msg),
            }
            diff_open.set(false);
            saving.set(false);
        });
    };
    let p2 = StoredValue::new(path.clone());
    view! {
        <section class="panel cfg-main fm-editor">
            <div class="cfg-bar">
                <button type="button" class="btn icon-btn ghost" aria-label=move || ctx.tr(K::Back) title=move || ctx.tr(K::Back)
                    on:click=move |_| { if !ed.dirty() || confirm(ctx.tr(K::DiscardChanges)) { back() } }>{icon(I::Chevron)}</button>
                <code class="fm-path">{path.clone()}</code>
                <Show when=move || sensitive.get()>
                    <span class="fm-badge t-warn" title=move || ctx.tr(K::Sensitive) aria-label=move || ctx.tr(K::Sensitive) role="img">{icon(I::Key)}</span>
                </Show>
                <div class="cfg-bar-end">
                    <Show when=move || ed.dirty()><span class="cfg-dirty">{move || ctx.tr(K::Modified)}</span></Show>
                    <button type="button" class="btn primary" disabled=move || !can_save() on:click=move |_| diff_open.set(true)>
                        {icon(I::Save)}{move || ctx.tr(K::Save)}
                    </button>
                </div>
            </div>
            <Msg msg=msg/>
            <Show when=move || saved.get()>
                <div class="banner ok-banner" role="status">{icon(I::Check)}<span>{move || ctx.tr(K::SavedPlain)}</span></div>
            </Show>
            <Show when=move || restart.get()>
                <div class="banner warn" role="status">{icon(I::Restart)}<span>{move || ctx.tr(K::RestartNeeded)}</span>
                    <button type="button" class="btn small" disabled=busy on:click=move |_| crate::configs::restart_server(ctx, id, msg)>{move || ctx.tr(K::Restart)}</button>
                </div>
            </Show>
            <Show when=move || conflict.get()>
                <div class="banner bad" role="alert">{icon(I::Alert)}<span>{move || ctx.tr(K::ErrConfigChanged)}</span>
                    <button type="button" class="btn small" on:click=move |_| { if confirm(ctx.tr(K::DiscardChanges)) { open(p2.get_value()) } }>{move || ctx.tr(K::Reload)}</button>
                </div>
            </Show>
            {move || ed.sensitive.with(|v| !v.is_empty()).then(|| view! {
                <div class="banner warn" role="status">{icon(I::Shield)}
                    <span>{move || ctx.tr(K::SensitiveChanged)}" "<code>{move || ed.sensitive.get().join(", ")}</code></span>
                </div>
            })}
            {move || ed.unverifiable.get().map(|w| crate::configs::unverifiable_banner(ctx, w, false, false))}
            {move || ed.error.get().map(|e| {
                let keyed = [(e.managed_key.clone(), K::ManagedKeyChanged), (e.admin_key.clone(), K::AdminKeyChanged), (e.unsafe_key.clone(), K::UnsafeKey)]
                    .into_iter()
                    .find_map(|(k, label)| k.map(|k| (k, label)));
                match keyed {
                    // Fichier non vérifiable : pourquoi, et quoi faire.
                    _ if e.unverifiable.is_some() => {
                        crate::configs::unverifiable_banner(ctx, e.unverifiable.unwrap_or(Unverifiable::Syntax), e.unsafe_key.is_some(), true)
                    }
                    Some((k, label)) => view! { <div class="banner bad" role="alert">{icon(I::Lock)}<span>{move || ctx.tr(label)}" "<code>{k.clone()}</code></span></div> }.into_any(),
                    None => {
                        let line = e.line;
                        let where_ = (line > 0).then(|| format!("{} {line} · ", ctx.tr(K::Line)));
                        view! {
                            <button type="button" class="banner bad cfg-err" role="alert" on:click=move |_| { if line > 0 { jump.set(Some(line)) } }>
                                {icon(I::Error)}<span>{where_.unwrap_or_default()}{e.message.clone()}</span>
                            </button>
                        }.into_any()
                    }
                }
            })}
            {move || if ed.loading.get() {
                view! { <div class="cfg-skeleton skeleton"></div> }.into_any()
            } else {
                view! {
                    <Show when=move || !known.get()><p class="faint small">{move || ctx.tr(K::PlainText)}</p></Show>
                    <CodeEditor ed=ed jump=jump/>
                }.into_any()
            }}
        </section>
        <Show when=move || diff_open.get()>
            <DiffModal ed=ed open=diff_open saving=saving on_save=save/>
        </Show>
    }
}

fn confirm(text: &str) -> bool {
    web_sys::window().and_then(|w| w.confirm_with_message(text).ok()).unwrap_or(true)
}

#[component]
fn TrashView(
    id: i64,
    trash: RwSignal<Option<Vec<TrashItem>>>,
    msg: RwSignal<Option<K>>,
    reload: impl Fn() + Copy + Send + Sync + 'static,
    busy: Signal<bool>,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let gone = move |tid: &str| {
        trash.update(|t| {
            if let Some(t) = t {
                t.retain(|x| x.id != tid)
            }
        });
        reload();
    };
    let restore = move |tid: String| {
        let csrf = ctx.csrf();
        spawn_local(async move {
            let path = format!("/api/servers/{id}/files/trash/restore");
            match api::post_empty(&path, &TrashRequest { id: tid.clone() }, csrf.as_deref()).await {
                Ok(()) => gone(&tid),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    // Effacement définitif : administrateurs, ré-authentification (mot de passe, + code TOTP).
    let admin = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.is_admin));
    let totp_on = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
    let purging = RwSignal::new(None::<(String, String)>);
    let pw = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let purge_msg = RwSignal::new(None::<K>);
    let sending = RwSignal::new(false);
    let purge = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some((tid, _)) = purging.get_untracked() else { return };
        let req = TrashPurgeRequest {
            id: tid.clone(),
            reauth: Reauth { password: pw.get_untracked(), code: totp_on().then(|| code.get_untracked()) },
        };
        sending.set(true);
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post_empty(&format!("/api/servers/{id}/files/trash/purge"), &req, csrf.as_deref()).await {
                Ok(()) => {
                    purging.set(None);
                    purge_msg.set(None);
                    gone(&tid);
                }
                Err(e) => ctx.on_err(&e, purge_msg),
            }
            pw.set(String::new());
            code.set(String::new());
            sending.set(false);
        });
    };
    view! {
        <section class="panel fm-trash">
            <h2 class="panel-title">{icon(I::Trash)}{move || ctx.tr(K::Trash)}</h2>
            <p class="faint small">{move || ctx.tr(K::TrashKept)}</p>
            {move || match trash.get() {
                None => view! { <div class="cfg-skeleton skeleton"></div> }.into_any(),
                Some(t) if t.is_empty() => view! { <p class="muted">{move || ctx.tr(K::TrashEmpty)}</p> }.into_any(),
                Some(t) => {
                    let lang = ctx.lang.get_untracked();
                    view! {
                        <ul class="hist">
                            {t.into_iter().map(|it| {
                                let a = it.id.clone();
                                let target = (it.id.clone(), it.path.clone());
                                let who = it.user.clone().unwrap_or_default();
                                view! {
                                    <li class="hist-item">
                                        <span class=format!("fm-ico {}", if it.kind == FileKind::Dir { "t-accent" } else { "t-faint" })>
                                            {if it.kind == FileKind::Dir { icon(I::Folder).into_any() } else { icon(I::FileText).into_any() }}</span>
                                        <span class="hist-text">
                                            <span class="fm-name">{it.path.clone()}</span>
                                            <span class="faint small">{format!("{} · {who} · {}", local_date(it.deleted, lang), fmt_size(it.size, lang))}</span>
                                        </span>
                                        <span class="row">
                                            <button type="button" class="btn small" disabled=busy on:click=move |_| restore(a.clone())>
                                                {icon(I::Undo)}{move || ctx.tr(K::Restore)}</button>
                                            <Show when=admin>
                                                <button type="button" class="btn small icon-btn ghost danger-ghost" aria-label=move || ctx.tr(K::DeleteForever)
                                                    title=move || ctx.tr(K::DeleteForever)
                                                    on:click={
                                                        let target = target.clone();
                                                        move |_| { purge_msg.set(None); purging.set(Some(target.clone())) }
                                                    }>{icon(I::Close)}</button>
                                            </Show>
                                        </span>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }
            }}
            <Show when=move || purging.with(Option::is_some)>
                <form class="stack danger-zone" on:submit=purge>
                    <h3>{move || purging.with(|p| p.as_ref().map(|p| p.1.clone()).unwrap_or_default())}</h3>
                    <p class="faint small">{move || ctx.tr(K::DeleteForeverConfirm)}</p>
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
                    <Msg msg=purge_msg/>
                    <div class="row">
                        <button type="submit" class="btn danger" disabled=move || sending.get()>{icon(I::Trash)}{move || ctx.tr(K::DeleteForever)}</button>
                        <button type="button" class="btn ghost" on:click=move |_| purging.set(None)>{move || ctx.tr(K::Cancel)}</button>
                    </div>
                </form>
            </Show>
        </section>
    }
}
