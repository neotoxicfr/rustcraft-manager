//! Icônes SVG (trait fin, couleur héritée de `currentColor` ; la couleur vient des classes CSS).

use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum I {
    Logo,
    Play,
    Stop,
    Restart,
    Plus,
    Star,
    StarFill,
    Gear,
    Trash,
    Search,
    Type,
    Join,
    Leave,
    Chat,
    Save,
    Trophy,
    Alert,
    Error,
    Command,
    Info,
    Palette,
    User,
    Logout,
    Globe,
    Menu,
    Close,
    Check,
    // Logiciels
    Cube,
    Paper,
    Pillar,
    Leaf,
    Thread,
    Patch,
    // Réglages
    Sliders,
    Code,
    History,
    Lock,
    Undo,
    Braces,
    FileText,
    Chevron,
    // Joueurs et fichiers
    Shield,
    Folder,
    Upload,
    Download,
    Ban,
    Crown,
    Users,
    Pencil,
    Move,
    Archive,
    Binary,
    Image,
    Key,
    ListCheck,
    Up,
    At,
}

fn paths(i: I) -> &'static [&'static str] {
    match i {
        I::Logo => &["M12 2l9 5v10l-9 5-9-5V7z", "M12 12l9-5M12 12v10M12 12L3 7"],
        I::Play => &["M7 4.5v15l12-7.5z"],
        I::Stop => &["M7 7h10v10H7z"],
        I::Restart => &["M3 12a9 9 0 1 0 3-6.7", "M3 4v5h5"],
        I::Plus => &["M12 5v14M5 12h14"],
        I::Star | I::StarFill => &["m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z"],
        I::Gear => &[
            "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
            "M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
        ],
        I::Trash => &["M3 6h18", "M8 6V4h8v2", "M19 6l-1 14H6L5 6", "M10 11v6M14 11v6"],
        I::Search => &["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "M21 21l-4.3-4.3"],
        I::Type => &["M4 7V4h16v3", "M9 20h6", "M12 4v16"],
        I::Join => &["M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4", "M10 17l5-5-5-5", "M15 12H3"],
        I::Leave => &["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"],
        I::Chat => &["M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"],
        I::Save => &["M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z", "M17 21v-8H7v8", "M7 3v5h8"],
        I::Trophy => {
            &["M8 21h8", "M12 17v4", "M7 4h10v5a5 5 0 0 1-10 0z", "M17 5h3v2a3 3 0 0 1-3 3", "M7 5H4v2a3 3 0 0 0 3 3"]
        }
        I::Alert => {
            &["M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z", "M12 9v4", "M12 17h.01"]
        }
        I::Error => &["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M15 9l-6 6M9 9l6 6"],
        I::Command => &["M4 17l6-6-6-6", "M12 19h8"],
        I::Info => &["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 16v-4", "M12 8h.01"],
        I::Palette => &[
            "M12 22a10 10 0 1 1 10-10c0 2.8-2.2 4-4 4h-2a2 2 0 0 0-1.5 3.3A1.6 1.6 0 0 1 12 22z",
            "M7.5 10.5h.01M10.5 7h.01M15 7.5h.01",
        ],
        I::User => &["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"],
        I::Logout => &["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"],
        I::Globe => {
            &["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M2 12h20", "M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"]
        }
        I::Menu => &["M4 6h16M4 12h16M4 18h16"],
        I::Close => &["M6 6l12 12M18 6L6 18"],
        I::Check => &["M5 12l5 5L20 7"],
        I::Cube => &["M12 2l9 5v10l-9 5-9-5V7z", "M3 7l9 5 9-5", "M12 12v10"],
        I::Paper => &["M6 2h9l5 5v15H6z", "M14 2v6h6", "M9 13h7M9 17h5"],
        I::Pillar => &["M6 3h12v4H6z", "M6 17h12v4H6z", "M8 7v10M12 7v10M16 7v10"],
        I::Leaf => &["M5 21c8 0 15-6 15-17-11 0-17 7-17 15", "M5 21c2-5 5-8 9-10"],
        I::Thread => &["M8 3h8v18H8z", "M8 7l8 3M8 11l8 3M8 15l8 3"],
        I::Patch => &["M3 3h8v8H3zM13 13h8v8h-8z", "M13 3h8v8h-8zM3 13h8v8H3z"],
        I::Sliders => &["M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3", "M1 14h6M9 8h6M17 16h6"],
        I::Code => &["M16 18l6-6-6-6", "M8 6l-6 6 6 6"],
        I::History => &["M3 12a9 9 0 1 0 3-6.7", "M3 4v5h5", "M12 7v5l3 2"],
        I::Lock => &["M5 11h14v10H5z", "M8 11V7a4 4 0 0 1 8 0v4"],
        I::Undo => &["M9 14L4 9l5-5", "M4 9h11a5 5 0 0 1 0 10h-3"],
        I::Braces => &[
            "M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5a2 2 0 0 0 2 2h1",
            "M16 21h1a2 2 0 0 0 2-2v-5a2 2 0 0 1 2-2 2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1",
        ],
        I::FileText => &["M6 2h9l5 5v15H6z", "M14 2v6h6", "M9 13h6M9 17h6M9 9h2"],
        I::Chevron => &["M9 6l6 6-6 6"],
        I::Shield => &["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", "M9 12l2 2 4-4"],
        I::Folder => &["M3 6a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"],
        I::Upload => &["M12 16V4", "M7 9l5-5 5 5", "M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"],
        I::Download => &["M12 4v12", "M7 11l5 5 5-5", "M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"],
        I::Ban => &["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M5 5l14 14"],
        I::Crown => &["M3 8l4 4 5-7 5 7 4-4-2 11H5z", "M5 19h14"],
        I::Users => &[
            "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2",
            "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
            "M23 21v-2a4 4 0 0 0-3-3.9",
            "M16 3.1a4 4 0 0 1 0 7.8",
        ],
        I::Pencil => &["M17 3l4 4L8 20H4v-4z", "M14 6l4 4"],
        I::Move => &["M5 9l-3 3 3 3M9 5l3-3 3 3M15 19l-3 3-3-3M19 9l3 3-3 3", "M2 12h20M12 2v20"],
        I::Archive => &["M3 4h18v4H3z", "M5 8v12h14V8", "M10 12h4"],
        I::Binary => &["M6 2h9l5 5v15H6z", "M14 2v6h6", "M9 12v5M13 12h2v5h-2z"],
        I::Image => &["M3 3h18v18H3z", "M8.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z", "M21 15l-5-5L5 21"],
        I::Key => &["M15 7a4 4 0 1 1-3.5 6L4 20.5V17h3v-3h3l1.5-1.5A4 4 0 0 1 15 7z", "M16 9h.01"],
        I::ListCheck => &["M10 6h11M10 12h11M10 18h11", "M3 6l1.5 1.5L7 5M3 12l1.5 1.5L7 11M3 18l1.5 1.5L7 17"],
        I::Up => &["M12 19V5", "M5 12l7-7 7 7"],
        I::At => &["M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8"],
    }
}

/// Icône décorative (le libellé voisin ou `aria-label` du bouton la nomme).
pub fn icon(i: I) -> impl IntoView {
    let fill = matches!(i, I::StarFill | I::Play);
    view! {
        <svg class="ico" viewBox="0 0 24 24" aria-hidden="true" fill=if fill { "currentColor" } else { "none" }
            stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            {paths(i).iter().map(|d| view! { <path d=*d/> }).collect_view()}
        </svg>
    }
}
