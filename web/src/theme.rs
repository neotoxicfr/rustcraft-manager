//! Thème du compte : jetons CSS calculés par `rc_manager_shared::theme` (clair ET sombre d'un seul
//! réglage) et posés sur `<html>` par le CSSOM (permis par la CSP, contrairement à un attribut
//! `style`). Gardé dans le stockage local pour être appliqué avant la réponse de `/me`.

use crate::i18n::{K, Lang};
use crate::{Ctx, api, icons::I, icons::icon};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rc_manager_shared::ThemeSettings;
use rc_manager_shared::theme::{Appearance, PRIMARY, Rgb, SECONDARY, Tone, bar_color, tokens};
use std::cell::RefCell;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;

const STORAGE: &str = "rcm-theme-v2";

/// Écoute du thème du système (apparence automatique).
type MediaWatch = (web_sys::MediaQueryList, Closure<dyn FnMut(web_sys::Event)>);
/// Choix d'un sélecteur segmenté : libellé, actif ?, action.
type Choice = (K, Box<dyn Fn() -> bool + Send + Sync>, Box<dyn Fn() + Send + Sync>);

thread_local! {
    static CURRENT: RefCell<ThemeSettings> = RefCell::new(ThemeSettings::default());
    static MEDIA: RefCell<Option<MediaWatch>> = const { RefCell::new(None) };
}

fn prefers_dark() -> bool {
    web_sys::window()
        .and_then(|w| w.match_media("(prefers-color-scheme: dark)").ok().flatten())
        .is_some_and(|m| m.matches())
}

fn is_dark(s: &ThemeSettings) -> bool {
    match s.appearance {
        Appearance::Dark => true,
        Appearance::Light => false,
        Appearance::Auto => prefers_dark(),
    }
}

/// Pose les jetons du thème (et la couleur de la barre d'état).
pub fn apply(s: &ThemeSettings) {
    CURRENT.with(|c| *c.borrow_mut() = s.clone());
    let dark = is_dark(s);
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else { return };
    if let Some(root) = doc.document_element().and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok()) {
        let style = root.style();
        for (k, v) in tokens(s, dark) {
            let _ = style.set_property(k, &v);
        }
        let _ = root.set_attribute("data-theme", if dark { "dark" } else { "light" });
    }
    if let Ok(metas) = doc.query_selector_all("meta[name=theme-color]") {
        for i in 0..metas.length() {
            if let Some(m) = metas.item(i).and_then(|n| n.dyn_into::<web_sys::Element>().ok()) {
                let _ = m.set_attribute("content", &bar_color(s, dark));
            }
        }
    }
    // Apparence automatique : suivre le système quand il change.
    MEDIA.with(|m| {
        if m.borrow().is_some() {
            return;
        }
        let Some(mq) = web_sys::window().and_then(|w| w.match_media("(prefers-color-scheme: dark)").ok().flatten())
        else {
            return;
        };
        let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            let s = CURRENT.with(|c| c.borrow().clone());
            if s.appearance == Appearance::Auto {
                apply(&s);
            }
        });
        let _ = mq.add_event_listener_with_callback("change", cb.as_ref().unchecked_ref());
        *m.borrow_mut() = Some((mq, cb));
    });
}

/// Thème gardé localement (avant la réponse de `/me`), sinon celui par défaut.
pub fn apply_cached() {
    let s = crate::storage_get(STORAGE)
        .and_then(|j| serde_json::from_str::<ThemeSettings>(&j).ok())
        .filter(ThemeSettings::valid);
    apply(&s.unwrap_or_default());
}

/// Thème du compte connecté.
pub fn apply_account(s: Option<&ThemeSettings>) {
    let s = s.cloned().unwrap_or_default();
    if let Ok(j) = serde_json::to_string(&s) {
        crate::storage_set(STORAGE, &j);
    }
    apply(&s);
}

fn swatch_name(lang: Lang, list: &[(&'static str, &'static str, &'static str); 12], i: usize) -> &'static str {
    match lang {
        Lang::Fr => list[i].0,
        Lang::En => list[i].1,
    }
}

/// Réglage du thème (comme la maquette Theme) : couleurs, fond, apparence, aperçus clair et
/// sombre. Chaque choix s'applique et s'enregistre aussitôt.
#[component]
pub fn ThemePage() -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let cur = RwSignal::new(ctx.me.with_untracked(|m| m.as_ref().and_then(|m| m.theme.clone())).unwrap_or_default());
    let msg = RwSignal::new(None::<K>);
    let save = move |s: ThemeSettings| {
        cur.set(s.clone());
        apply_account(Some(&s));
        ctx.me.update(|m| {
            if let Some(m) = m.as_mut() {
                m.theme = Some(s.clone());
            }
        });
        let csrf = ctx.csrf();
        spawn_local(async move {
            match api::post_empty("/api/account/theme", &s, csrf.as_deref()).await {
                Ok(()) => msg.set(None),
                Err(e) => ctx.on_err(&e, msg),
            }
        });
    };
    let colors = move |primary: bool| {
        let list = if primary { &PRIMARY } else { &SECONDARY };
        let current = move || if primary { cur.with(|c| c.primary.clone()) } else { cur.with(|c| c.secondary.clone()) };
        let is_custom = move || !list.iter().any(|(_, _, h)| *h == current());
        view! {
            <div class="swatches">
                {(0..12).map(|i| {
                    let hex = list[i].2;
                    let on = move || current() == hex;
                    view! {
                        <button type="button" role="radio" class="swatch" class:on=on aria-checked=move || on().to_string()
                            aria-label=move || swatch_name(ctx.lang.get(), list, i)
                            title=move || swatch_name(ctx.lang.get(), list, i)
                            on:click=move |_| {
                                let mut s = cur.get_untracked();
                                if primary { s.primary = hex.into() } else { s.secondary = hex.into() }
                                save(s);
                            }>
                            <ColorDot color=hex.to_string() class="swatch-fill"/>
                        </button>
                    }
                }).collect_view()}
                <label class="swatch custom" class:on=is_custom title=move || ctx.tr(K::ThemeCustom)>
                    <Show when=is_custom><ColorDot color=Signal::derive(current) class="swatch-fill"/></Show>
                    <input type="color" aria-label=move || ctx.tr(K::ThemeCustom)
                        prop:value=current
                        on:change=move |ev| {
                            let v = event_target_value(&ev);
                            if Rgb::parse(&v).is_some() {
                                let mut s = cur.get_untracked();
                                if primary { s.primary = v } else { s.secondary = v }
                                save(s);
                            }
                        }/>
                </label>
            </div>
        }
    };
    let segmented = move |items: Vec<Choice>| {
        view! {
            <div class="segmented" role="radiogroup">
                {items.into_iter().map(|(k, on, pick)| {
                    let on = std::sync::Arc::new(on);
                    let on2 = on.clone();
                    view! {
                        <button type="button" role="radio" class:on=move || on() aria-checked=move || on2().to_string()
                            on:click=move |_| pick()>{move || ctx.tr(k)}</button>
                    }
                }).collect_view()}
            </div>
        }
    };
    let tone_items = Tone::ALL
        .into_iter()
        .map(|t| {
            let k = match t {
                Tone::Cold => K::ToneCold,
                Tone::Neutral => K::ToneNeutral,
                Tone::Warm => K::ToneWarm,
            };
            let on: Box<dyn Fn() -> bool + Send + Sync> = Box::new(move || cur.with(|c| c.tone == t));
            let pick: Box<dyn Fn() + Send + Sync> = Box::new(move || {
                let mut s = cur.get_untracked();
                s.tone = t;
                save(s);
            });
            (k, on, pick)
        })
        .collect();
    let mode_items = Appearance::ALL
        .into_iter()
        .map(|a| {
            let k = match a {
                Appearance::Auto => K::ThemeSystem,
                Appearance::Light => K::ThemeLight,
                Appearance::Dark => K::ThemeDark,
            };
            let on: Box<dyn Fn() -> bool + Send + Sync> = Box::new(move || cur.with(|c| c.appearance == a));
            let pick: Box<dyn Fn() + Send + Sync> = Box::new(move || {
                let mut s = cur.get_untracked();
                s.appearance = a;
                save(s);
            });
            (k, on, pick)
        })
        .collect();
    // Aperçus : les deux thèmes en apparence automatique, sinon celui choisi.
    let previews = move || {
        let s = cur.get();
        let modes: Vec<bool> = match s.appearance {
            Appearance::Auto => vec![true, false],
            Appearance::Light => vec![false],
            Appearance::Dark => vec![true],
        };
        modes
            .into_iter()
            .map(|dark| {
                let t = tokens(&s, dark);
                view! {
                    <figure class="preview">
                        <figcaption>{move || ctx.tr(if dark { K::ThemeDark } else { K::ThemeLight })}</figcaption>
                        <Preview tokens=t/>
                    </figure>
                }
            })
            .collect_view()
    };
    view! {
        <header class="page-head"><h1>{move || ctx.tr(K::ThemeTitle)}</h1></header>
        <div class="theme-layout">
            <div class="theme-controls">
                <div class="field" role="radiogroup" aria-label=move || ctx.tr(K::ThemePrimary)>
                    <span class="field-label">{move || ctx.tr(K::ThemePrimary)}</span>
                    {colors(true)}
                </div>
                <div class="field" role="radiogroup" aria-label=move || ctx.tr(K::ThemeSecondary)>
                    <span class="field-label">{move || ctx.tr(K::ThemeSecondary)}</span>
                    {colors(false)}
                </div>
                <div class="field">
                    <span class="field-label">{move || ctx.tr(K::ThemeTone)}</span>
                    {segmented(tone_items)}
                </div>
                <div class="field">
                    <span class="field-label">{move || ctx.tr(K::ThemeAppearance)}</span>
                    {segmented(mode_items)}
                </div>
                <crate::Msg msg=msg/>
            </div>
            <div class="previews">{previews}</div>
        </div>
    }
}

/// Aperçu d'un thème : ses jetons posés sur le cadre par le CSSOM (aucun style en ligne).
#[component]
fn Preview(tokens: Vec<(&'static str, String)>) -> impl IntoView {
    let ctx = expect_context::<Ctx>();
    let frame = NodeRef::<leptos::html::Div>::new();
    Effect::new(move |_| {
        if let Some(el) = frame.get() {
            let st = web_sys::HtmlElement::style(&el);
            for (k, v) in &tokens {
                let _ = st.set_property(k, v);
            }
        }
    });
    view! {
        <div class="preview-frame" node_ref=frame>
            <div class="row-between">
                <span class="preview-title">{move || ctx.tr(K::PreviewName)}</span>
                <span class="preview-stop">{move || ctx.tr(K::Stop)}</span>
            </div>
            <div class="preview-cards">
                <div class="preview-card"><span class="muted small">{move || ctx.tr(K::MetricTps)}</span><span class="preview-num">"20,0"</span><span class="bar-accent"></span></div>
                <div class="preview-card"><span class="muted small">{move || ctx.tr(K::MetricPlayers)}</span><span class="preview-num">"3 / 20"</span><span class="bar-accent-2"></span></div>
            </div>
            <div class="row">
                <span class="chip">{move || ctx.tr(K::CmdSave)}</span>
                <span class="chip">{move || ctx.tr(K::TimeDay)}</span>
            </div>
            <span class="preview-link">{icon(I::Command)}{move || ctx.tr(K::Console)}</span>
        </div>
    }
}

/// Pastille de couleur (`#rrggbb`), posée par le CSSOM.
#[component]
pub fn ColorDot(#[prop(into)] color: Signal<String>, class: &'static str) -> impl IntoView {
    let el = NodeRef::<leptos::html::Span>::new();
    Effect::new(move |_| {
        let c = color.get();
        if let Some(e) = el.get()
            && Rgb::parse(&c).is_some()
        {
            let _ = web_sys::HtmlElement::style(&e).set_property("--dot", &c);
        }
    });
    view! { <span class=class node_ref=el aria-hidden="true"></span> }
}

/// Couleur stable tirée d'un nom (avatars, pastilles d'objets) : une des couleurs proposées.
pub fn color_for(name: &str) -> String {
    let h = name.bytes().fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619));
    let all: Vec<&str> = PRIMARY.iter().chain(SECONDARY.iter()).map(|c| c.2).collect();
    all[h as usize % all.len()].to_string()
}
