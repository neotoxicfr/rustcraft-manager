//! Onglet « Adresse » d'un serveur : nom public et mode (enregistrement direct ou aiguilleur),
//! enregistrements DNS attendus (à créer à la main sans jeton Cloudflare), aperçu des
//! changements puis application, test de joignabilité.

use crate::api;
use crate::i18n::K;
use crate::icons::{I, icon};
use crate::{Ctx, Msg};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::*;

fn change_key(k: ChangeKind) -> (K, &'static str) {
    match k {
        ChangeKind::Create => (K::ChangeCreate, "chg-create"),
        ChangeKind::Update => (K::ChangeUpdate, "chg-update"),
        ChangeKind::Delete => (K::ChangeDelete, "chg-delete"),
    }
}

fn conflict_key(r: ConflictReason) -> K {
    match r {
        ConflictReason::Manual => K::ConflictManual,
        ConflictReason::Edited => K::ConflictEdited,
        ConflictReason::Cname => K::ConflictCname,
    }
}

/// Une ligne d'enregistrement : type, nom, contenu (sélectionnables pour la copie).
#[component]
fn RecordRow(
    r: DnsRecord,
    #[prop(optional)] tag: Option<(K, &'static str)>,
    #[prop(optional)] note: Option<String>,
    #[prop(optional)] warn: bool,
) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    view! {
        <li class="dns-row">
            {tag.map(|(k, class)| view! { <span class=format!("chg {class}")>{move || ctx.tr(k)}</span> })}
            {warn.then(|| view! { <span class="chg chg-conflict" aria-hidden="true">{icon(I::Alert)}</span> })}
            <span class="dns-type">{r.kind.code()}</span>
            <code class="dns-name">{r.name.clone()}</code>
            <code class="dns-content">{r.content.clone()}</code>
            {note.filter(|n| !n.is_empty()).map(|n| view! { <span class="dns-note small">{n}</span> })}
        </li>
    }
}

#[component]
pub fn AddressTab(id: i64) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let view_s = RwSignal::new(None::<AddressView>);
    let host = RwSignal::new(String::new());
    let mode = RwSignal::new(AddressMode::Record);
    let preview = RwSignal::new(None::<AddressPreview>);
    let test = RwSignal::new(None::<ReachTest>);
    let msg = RwSignal::new(None::<K>);
    let note = RwSignal::new(None::<K>);
    let busy = RwSignal::new(false);
    // L'aperçu montré est celui du retrait du nom.
    let removing = RwSignal::new(false);
    let admin = move || ctx.me.with(|m| m.as_ref().is_some_and(|m| m.is_admin));
    let load = move || {
        spawn_local(async move {
            match api::get::<AddressView>(&format!("/api/servers/{id}/address")).await {
                Ok(v) => {
                    if let Some(a) = &v.address {
                        host.set(a.hostname.clone());
                        mode.set(a.mode);
                    }
                    view_s.set(Some(v));
                }
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    load();
    let cloudflare = move || view_s.with(|v| v.as_ref().is_some_and(|v| v.network.cloudflare));
    let router_port = move || view_s.with(|v| v.as_ref().and_then(|v| v.network.router_port));
    let request = move |remove: bool| AddressRequest {
        address: (!remove).then(|| AddressSetting { hostname: host.get_untracked(), mode: mode.get_untracked() }),
        digest: None,
    };
    // Saisie modifiée : l'aperçu montré n'est plus le bon.
    let edited = move || {
        preview.set(None);
        note.set(None);
    };
    let do_preview = move |remove: bool| {
        let (csrf, req) = (ctx.csrf(), request(remove));
        removing.set(remove);
        busy.set(true);
        msg.set(None);
        note.set(None);
        spawn_local(async move {
            match api::post::<_, AddressPreview>(&format!("/api/servers/{id}/address/preview"), &req, csrf.as_deref())
                .await
            {
                Ok(p) => preview.set(Some(p)),
                Err(e) => ctx.on_err(&e, msg),
            }
            busy.set(false);
        });
    };
    // Application de l'aperçu montré (même empreinte), ou enregistrement direct sans Cloudflare
    // (aperçu demandé puis appliqué d'une traite : rien n'est écrit ailleurs).
    let do_apply = move |remove: bool| {
        let csrf = ctx.csrf();
        let mut req = request(remove);
        let shown = preview.get_untracked().map(|p| p.digest);
        busy.set(true);
        msg.set(None);
        spawn_local(async move {
            let digest = match shown {
                Some(d) => Some(d),
                None => match api::post::<_, AddressPreview>(
                    &format!("/api/servers/{id}/address/preview"),
                    &req,
                    csrf.as_deref(),
                )
                .await
                {
                    Ok(p) => Some(p.digest),
                    Err(e) => {
                        ctx.on_err(&e, msg);
                        busy.set(false);
                        return;
                    }
                },
            };
            req.digest = digest;
            match api::post::<_, AddressApplied>(&format!("/api/servers/{id}/address"), &req, csrf.as_deref()).await {
                Ok(a) => {
                    preview.set(None);
                    test.set(None);
                    if remove {
                        host.set(String::new());
                    }
                    if a.sync_failed {
                        msg.set(Some(K::ErrDnsFailed));
                    } else {
                        note.set(Some(K::SavedPlain));
                    }
                    view_s.set(Some(a.view));
                }
                Err(e) => ctx.on_err(&e, msg),
            }
            busy.set(false);
        });
    };
    let do_test = move |_| {
        let csrf = ctx.csrf();
        busy.set(true);
        msg.set(None);
        spawn_local(async move {
            match api::post::<_, ReachTest>(
                &format!("/api/servers/{id}/address/test"),
                &serde_json::Map::new(),
                csrf.as_deref(),
            )
            .await
            {
                Ok(t) => test.set(Some(t)),
                Err(e) => ctx.on_err(&e, msg),
            }
            busy.set(false);
        });
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if cloudflare() { do_preview(false) } else { do_apply(false) }
    };
    let has_address = move || view_s.with(|v| v.as_ref().is_some_and(|v| v.address.is_some()));
    let ip_line = move || {
        view_s.with(|v| {
            let v = v.as_ref()?;
            let ips: Vec<&PublicIp> = [&v.network.ipv4, &v.network.ipv6].into_iter().flatten().collect();
            Some(if ips.is_empty() {
                view! { <p class="banner warn" role="status">{icon(I::Alert)}<span>{move || ctx.tr(K::IpUnknown)}</span></p> }.into_any()
            } else {
                let text = ips
                    .iter()
                    .map(|p| format!("{} ({})", p.ip, ctx.tr(if p.source == IpSource::Fixed { K::IpFixed } else { K::IpDetected })))
                    .collect::<Vec<_>>()
                    .join(" · ");
                view! { <p class="muted small">{move || ctx.tr(K::PublicIp)}" "<span class="num">{text.clone()}</span></p> }.into_any()
            })
        })
    };
    view! {
        <div class="addr">
            <form class="card stack addr-form" on:submit=submit>
                <label class="field">
                    <span class="field-label">{move || ctx.tr(K::PublicName)}</span>
                    <input type="text" inputmode="url" autocomplete="off" spellcheck="false" maxlength="253" required
                        placeholder=move || view_s.with(|v| v.as_ref().and_then(|v| v.network.zone.clone()).map_or("survie.example.org".into(), |z| format!("survie.{z}")))
                        prop:value=move || host.get() on:input=move |ev| { host.set(event_target_value(&ev)); edited(); }/>
                </label>
                <div class="segmented" role="group" aria-label=move || ctx.tr(K::PublicName)>
                    <button type="button" class:on=move || mode.get() == AddressMode::Record aria-pressed=move || (mode.get() == AddressMode::Record).to_string()
                        on:click=move |_| { mode.set(AddressMode::Record); edited(); }>{move || ctx.tr(K::ModeRecord)}</button>
                    <button type="button" class:on=move || mode.get() == AddressMode::Router aria-pressed=move || (mode.get() == AddressMode::Router).to_string()
                        disabled=move || router_port().is_none()
                        on:click=move |_| { mode.set(AddressMode::Router); edited(); }>{move || ctx.tr(K::ModeRouter)}</button>
                </div>
                <Show when=move || view_s.with(Option::is_some) && router_port().is_none()>
                    <p class="hint">{move || ctx.tr(K::RouterOff)}</p>
                </Show>
                <div class="row">
                    <button type="submit" class="btn primary" disabled=move || busy.get() || host.with(|h| h.trim().is_empty()) || !admin()>
                        {move || if cloudflare() { icon(I::Search).into_any() } else { icon(I::Save).into_any() }}
                        {move || ctx.tr(if cloudflare() { K::DnsPreview } else { K::Save })}
                    </button>
                    <Show when=has_address>
                        <button type="button" class="btn ghost" disabled=move || busy.get() || !admin()
                            on:click=move |_| if cloudflare() { do_preview(true) } else { do_apply(true) }>
                            {icon(I::Trash)}{move || ctx.tr(K::RemoveName)}
                        </button>
                    </Show>
                </div>
                <Show when=move || !admin()>
                    <p class="hint">{move || ctx.tr(K::AdminApplies)}</p>
                </Show>
                <Msg msg=msg/>
                {move || note.get().map(|k| view! { <div class="banner ok-banner" role="status">{icon(I::Check)}<span>{move || ctx.tr(k)}</span></div> })}
            </form>

            {move || preview.get().map(|p| {
                let changes = p.changes.clone().unwrap_or_default();
                let empty = changes.is_empty() && p.conflicts.is_empty();
                view! {
                    <section class="card stack" aria-live="polite">
                        <h2 class="panel-title">{move || ctx.tr(K::DnsPreview)}</h2>
                        <Show when=move || empty>
                            <p class="muted">{move || ctx.tr(K::NothingToChange)}</p>
                        </Show>
                        <ul class="dns-list">
                            {changes.into_iter().map(|c| {
                                let note = c.before.clone();
                                view! { <RecordRow r=c.record.clone() tag=change_key(c.kind) note=note.unwrap_or_default()/> }
                            }).collect_view()}
                            {p.conflicts.clone().into_iter().map(|c| {
                                let n = format!("{} : {}", c.existing, ctx.tr(conflict_key(c.reason)));
                                view! { <RecordRow r=c.record.clone() warn=true note=n/> }
                            }).collect_view()}
                        </ul>
                        <div class="row">
                            <button type="button" class="btn primary" disabled=move || busy.get()
                                on:click=move |_| do_apply(removing.get_untracked())>
                                {icon(I::Check)}{move || ctx.tr(K::Apply)}
                            </button>
                        </div>
                    </section>
                }
            })}

            <section class="card stack">
                <div class="row-between">
                    <h2 class="panel-title">{move || ctx.tr(K::DnsRecords)}</h2>
                    <Show when=has_address>
                        <button type="button" class="btn" disabled=move || busy.get() on:click=do_test>
                            {icon(I::Restart)}{move || ctx.tr(K::ReachTest)}
                        </button>
                    </Show>
                </div>
                {ip_line}
                {move || view_s.with(|v| v.as_ref().map(|v| {
                    if v.address.is_none() {
                        return view! { <p class="faint">{move || ctx.tr(K::NoAddress)}</p> }.into_any();
                    }
                    let how = if v.network.cloudflare { K::DnsByCloudflare } else { K::DnsByHand };
                    let failed = v.network.last_sync.as_ref().is_some_and(|s| s.failed);
                    view! {
                        <p class="hint">{move || ctx.tr(how)}</p>
                        <ul class="dns-list">
                            {v.records.iter().cloned().map(|r| view! { <RecordRow r=r/> }).collect_view()}
                        </ul>
                        <Show when=move || failed>
                            <p class="banner bad" role="alert">{icon(I::Alert)}<span>{move || ctx.tr(K::SyncFailed)}</span></p>
                        </Show>
                    }.into_any()
                }))}
                {move || test.get().map(|t| {
                    let resolved = if t.resolved.is_empty() { "—".to_string() } else { t.resolved.join(", ") };
                    let warn_ip = !t.resolved.is_empty() && !t.matches_public;
                    let step = |s: ReachStep| -> &'static str {
                        match (t.failed, s) {
                            (Some(f), s) if f == s => "reach-bad",
                            (Some(ReachStep::Resolve), _) | (Some(ReachStep::Connect), ReachStep::Status) => "reach-skip",
                            _ => "reach-ok",
                        }
                    };
                    let (c_resolve, c_connect, c_status) = (step(ReachStep::Resolve), step(ReachStep::Connect), step(ReachStep::Status));
                    let connect = t.connect_ms.map(|ms| format!(":{} · {ms} ms", t.port)).unwrap_or_else(|| format!(":{}", t.port));
                    let status = t.status.as_ref().map(|s| format!("{} · {}/{} {} · {} ms", s.version, s.online, s.max, ctx.tr(K::PlayersShort), s.ms));
                    view! {
                        <ul class="reach" aria-live="polite">
                            <li class={if warn_ip && c_resolve == "reach-ok" { "reach-warn" } else { c_resolve }}>{icon(if c_resolve == "reach-ok" && !warn_ip { I::Check } else { I::Alert })}
                                <span>{move || ctx.tr(K::ReachResolve)}</span><code>{resolved.clone()}</code>
                                <Show when=move || warn_ip><span class="t-warn small">{move || ctx.tr(K::NotPublicIp)}</span></Show>
                            </li>
                            <li class=c_connect>{icon(if c_connect == "reach-ok" { I::Check } else { I::Alert })}
                                <span>{move || ctx.tr(K::ReachConnect)}</span><code>{connect.clone()}</code></li>
                            <li class=c_status>{icon(if c_status == "reach-ok" { I::Check } else { I::Alert })}
                                <span>{move || ctx.tr(K::ReachStatus)}</span><code>{status.clone().unwrap_or_default()}</code></li>
                        </ul>
                    }
                })}
            </section>
        </div>
    }
}
