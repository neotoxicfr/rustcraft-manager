//! Suggestions du constructeur de commandes : noms d'objets en français ET en anglais tirés des
//! fichiers de langue de la version du serveur, joueurs déjà venus (`usercache.json`).
//!
//! - `fr_fr.json` : ressource Mojang de la version (index des ressources vérifié par SHA-1, fichier
//!   vérifié par son SHA-1, qui est aussi son nom) ;
//! - `en_us.json` : dans le jar du serveur (`assets/minecraft/lang/en_us.json`, à l'intérieur du jar
//!   « bundler » depuis 1.18 ; Paper : `cache/mojang_<version>.jar` ou `versions/`). Introuvable :
//!   nom anglais déduit de l'identifiant (`diamond_sword` → « Diamond Sword »).
//!
//! Cache sur disque `<données>/lang/<version>/` et index en mémoire par version. Recherche sans
//! tenir compte des accents ni de la casse.

use crate::download::{Checksum, Expect};
use crate::minecraft::Catalog;
use rc_manager_shared::{ItemSuggestion, PlayerSuggestion};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Taille maximale d'un fichier de langue.
const LANG_MAX: u64 = 8 * 1024 * 1024;
/// Suggestions rendues au plus.
pub const MAX_SUGGESTIONS: usize = 12;

/// Minuscules sans accents (lettres latines courantes du français et de l'anglais).
pub fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        match c {
            'à' | 'â' | 'ä' | 'á' | 'ã' | 'å' => out.push('a'),
            'ç' => out.push('c'),
            'é' | 'è' | 'ê' | 'ë' => out.push('e'),
            'î' | 'ï' | 'í' | 'ì' => out.push('i'),
            'ô' | 'ö' | 'ó' | 'ò' | 'õ' => out.push('o'),
            'ù' | 'û' | 'ü' | 'ú' => out.push('u'),
            'ÿ' | 'ý' => out.push('y'),
            'ñ' => out.push('n'),
            'œ' => out.push_str("oe"),
            'æ' => out.push_str("ae"),
            '’' | '\'' => out.push('\''),
            '_' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

struct Item {
    id: String,
    fr: String,
    en: String,
    key: String,
}

/// Index des objets d'une version.
pub struct ItemIndex {
    items: Vec<Item>,
}

/// Blocs sans objet (fluides, morceaux de plantes, variantes posées au mur…) : jamais suggérés.
fn is_item_id(id: &str) -> bool {
    const NO_ITEM: &[&str] = &[
        "air",
        "cave_air",
        "void_air",
        "water",
        "lava",
        "fire",
        "soul_fire",
        "bubble_column",
        "moving_piston",
        "piston_head",
        "nether_portal",
        "end_portal",
        "end_gateway",
        "frosted_ice",
        "tall_seagrass",
        "kelp_plant",
        "bamboo_sapling",
        "sweet_berry_bush",
        "cocoa",
        "tripwire",
        "redstone_wire",
        "carrots",
        "potatoes",
        "beetroots",
        "melon_stem",
        "pumpkin_stem",
        "attached_melon_stem",
        "attached_pumpkin_stem",
        "twisting_vines_plant",
        "weeping_vines_plant",
        "cave_vines",
        "cave_vines_plant",
        "big_dripleaf_stem",
        "powder_snow",
        "water_cauldron",
        "lava_cauldron",
        "powder_snow_cauldron",
        "light",
        "pitcher_crop",
        "torchflower_crop",
        "wall_torch",
        "soul_wall_torch",
        "redstone_wall_torch",
        "copper_wall_torch",
    ];
    !NO_ITEM.contains(&id)
        && !id.starts_with("potted_")
        && !id.ends_with("_wall_sign")
        && !id.ends_with("_wall_hanging_sign")
        && !id.ends_with("_wall_banner")
        && !id.ends_with("_wall_head")
        && !id.ends_with("_wall_skull")
        && !id.ends_with("_wall_fan")
        && !id.ends_with("_candle_cake")
}

fn title_case(id: &str) -> String {
    id.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl ItemIndex {
    /// Construit l'index depuis les tables (clé de traduction → texte).
    pub fn build(fr: &HashMap<String, String>, en: Option<&HashMap<String, String>>) -> ItemIndex {
        let mut seen = std::collections::HashSet::new();
        let mut items = Vec::new();
        let source = en.unwrap_or(fr);
        let mut keys: Vec<&String> = source.keys().chain(fr.keys()).collect();
        keys.sort();
        for k in keys {
            let id = match k.strip_prefix("item.minecraft.").or_else(|| k.strip_prefix("block.minecraft.")) {
                Some(id) if !id.contains('.') && !id.is_empty() => id,
                _ => continue,
            };
            if !is_item_id(id) || !seen.insert(id.to_string()) {
                continue;
            }
            let item_key = format!("item.minecraft.{id}");
            let block_key = format!("block.minecraft.{id}");
            let pick = |m: &HashMap<String, String>| m.get(&item_key).or_else(|| m.get(&block_key)).cloned();
            let en_name = en.and_then(pick).unwrap_or_else(|| title_case(id));
            let fr_name = pick(fr).unwrap_or_else(|| en_name.clone());
            let key = format!("{}\u{1}{}\u{1}{}", fold(&fr_name), fold(&en_name), fold(id));
            items.push(Item { id: id.to_string(), fr: fr_name, en: en_name, key });
        }
        ItemIndex { items }
    }

    /// Objets dont le nom (fr ou en) ou l'identifiant contient la saisie ; ceux qui COMMENCENT
    /// par la saisie (ou un de ses mots) d'abord, puis les plus courts.
    pub fn search(&self, q: &str) -> Vec<ItemSuggestion> {
        let q = fold(q.trim());
        if q.is_empty() {
            return Vec::new();
        }
        let q_id = q.replace(' ', "_");
        let mut hits: Vec<(u8, usize, &Item)> = self
            .items
            .iter()
            // Chaque mot saisi se trouve dans le même nom (« epee dia » → « épée en diamant »).
            .filter(|it| {
                it.id.contains(&q_id) || it.key.split('\u{1}').any(|n| q.split_whitespace().all(|w| n.contains(w)))
            })
            .map(|it| {
                let starts =
                    it.key.split('\u{1}').any(|n| n.starts_with(&q) || n.split(' ').any(|w| w.starts_with(&q)));
                (if starts { 0 } else { 1 }, it.fr.len().min(it.en.len()), it)
            })
            .collect();
        hits.sort_by(|a, b| (a.0, a.1, &a.2.id).cmp(&(b.0, b.1, &b.2.id)));
        hits.into_iter()
            .take(MAX_SUGGESTIONS)
            .map(|(_, _, it)| ItemSuggestion { id: it.id.clone(), fr: it.fr.clone(), en: it.en.clone() })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Index par version, construits à la demande.
#[derive(Default)]
pub struct Languages {
    cache: Mutex<HashMap<String, Arc<ItemIndex>>>,
    /// Un verrou par version (deux versions se construisent en parallèle, pas deux fois la même).
    building: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Échecs récents par version : pas de nouvel essai réseau à chaque frappe.
    failed: Mutex<HashMap<String, Instant>>,
}

/// Après un échec, pas de nouvel essai avant ce délai.
pub const RETRY_AFTER: Duration = Duration::from_secs(300);

fn parse_table(b: &[u8]) -> Option<HashMap<String, String>> {
    serde_json::from_slice(b).ok()
}

impl Languages {
    /// Échec récent (moins de [`RETRY_AFTER`]) pour cette version ?
    pub fn recently_failed(&self, version: &str, now: Instant) -> bool {
        self.failed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(version)
            .is_some_and(|t| now.saturating_duration_since(*t) < RETRY_AFTER)
    }

    pub fn mark_failed(&self, version: &str, at: Instant) {
        let mut f = self.failed.lock().unwrap_or_else(|p| p.into_inner());
        if f.len() > 256 {
            f.clear();
        }
        f.insert(version.to_string(), at);
    }

    /// Index des objets de `version` (fichiers de langue mis en cache dans `<données>/lang`).
    pub async fn items(
        &self,
        catalog: &Catalog,
        data: &Path,
        version: &str,
        server_dir: &Path,
    ) -> Option<Arc<ItemIndex>> {
        if let Some(i) = self.cache.lock().unwrap_or_else(|p| p.into_inner()).get(version) {
            return Some(i.clone());
        }
        if self.recently_failed(version, Instant::now()) {
            return None;
        }
        let lock =
            self.building.lock().unwrap_or_else(|p| p.into_inner()).entry(version.to_string()).or_default().clone();
        let _g = lock.lock().await;
        if let Some(i) = self.cache.lock().unwrap_or_else(|p| p.into_inner()).get(version) {
            return Some(i.clone());
        }
        let r = self.build(catalog, data, version, server_dir).await;
        if r.is_none() {
            self.mark_failed(version, Instant::now());
        }
        r
    }

    async fn build(&self, catalog: &Catalog, data: &Path, version: &str, server_dir: &Path) -> Option<Arc<ItemIndex>> {
        let dir = crate::paths::lang_dir(data, version)?;
        let fr_path = dir.join("fr_fr.json");
        if !fr_path.is_file() {
            let idx = catalog.asset_index(version).await.ok()?;
            let sum = Checksum::sha1(&idx.sha1)?;
            let bytes = catalog.http.bytes(&idx.url, crate::download::MAX_JSON).await.ok()?;
            let got = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &bytes);
            if Checksum::Sha1(got.as_ref().to_vec()) != sum {
                return None;
            }
            #[derive(serde::Deserialize)]
            struct Index {
                objects: HashMap<String, Obj>,
            }
            #[derive(serde::Deserialize)]
            struct Obj {
                hash: String,
                size: u64,
            }
            let index: Index = serde_json::from_slice(&bytes).ok()?;
            let o = index.objects.get("minecraft/lang/fr_fr.json")?;
            let checksum = Checksum::sha1(&o.hash)?;
            let url = format!("https://resources.download.minecraft.net/{}/{}", &o.hash[..2], o.hash);
            catalog.http.file(&url, &fr_path, Expect { checksum, size: Some(o.size) }, &|_, _| {}).await.ok()?;
        }
        let en_path = dir.join("en_us.json");
        if !en_path.is_file() {
            let sd = server_dir.to_path_buf();
            if let Ok(Some(b)) = tokio::task::spawn_blocking(move || extract_en_us(&sd)).await {
                let _ = crate::fsutil::write_atomic(&en_path, &b);
            }
        }
        let (fr, en) = tokio::task::spawn_blocking(move || {
            let fr = crate::fsutil::read_bounded(&fr_path, LANG_MAX).ok().and_then(|b| parse_table(&b));
            let en = crate::fsutil::read_bounded(&en_path, LANG_MAX).ok().and_then(|b| parse_table(&b));
            (fr, en)
        })
        .await
        .ok()?;
        let index = Arc::new(ItemIndex::build(&fr?, en.as_ref()));
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).insert(version.to_string(), index.clone());
        Some(index)
    }
}

const EN_US: &str = "assets/minecraft/lang/en_us.json";

/// `en_us.json` d'un jar (directement, ou dans le jar intérieur d'un « bundler »).
fn en_us_from_jar(path: &Path) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut z = zip::ZipArchive::new(f).ok()?;
    if let Ok(mut e) = z.by_name(EN_US) {
        if e.size() > LANG_MAX {
            return None;
        }
        let mut b = Vec::new();
        e.read_to_end(&mut b).ok()?;
        return Some(b);
    }
    let inner = (0..z.len()).find_map(|i| {
        let e = z.by_index(i).ok()?;
        let n = e.name().ok()?.into_owned();
        (n.starts_with("META-INF/versions/") && n.ends_with(".jar")).then_some(i)
    })?;
    let mut e = z.by_index(inner).ok()?;
    if e.size() > crate::download::MAX_FILE {
        return None;
    }
    let mut buf = Vec::with_capacity(e.size() as usize);
    e.read_to_end(&mut buf).ok()?;
    let mut iz = zip::ZipArchive::new(std::io::Cursor::new(buf)).ok()?;
    let mut l = iz.by_name(EN_US).ok()?;
    if l.size() > LANG_MAX {
        return None;
    }
    let mut b = Vec::new();
    l.read_to_end(&mut b).ok()?;
    Some(b)
}

fn extract_en_us(server_dir: &Path) -> Option<Vec<u8>> {
    let mut candidates = vec![server_dir.join("server.jar")];
    for sub in ["cache", "versions"] {
        if let Ok(rd) = std::fs::read_dir(server_dir.join(sub)) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "jar") {
                    candidates.push(p);
                } else if p.is_dir()
                    && let Ok(rd2) = std::fs::read_dir(&p)
                {
                    candidates
                        .extend(rd2.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "jar")));
                }
            }
        }
    }
    candidates.into_iter().find_map(|p| en_us_from_jar(&p))
}

/// Joueurs à suggérer : connectés d'abord, puis ceux de `usercache.json` (déjà venus).
pub fn players(server_dir: &Path, online: &[String], q: &str) -> Vec<PlayerSuggestion> {
    #[derive(serde::Deserialize)]
    struct Entry {
        name: String,
    }
    let q = fold(q.trim());
    let mut out: Vec<PlayerSuggestion> = online
        .iter()
        .filter(|n| fold(n).contains(&q))
        .map(|n| PlayerSuggestion { name: n.clone(), online: true })
        .collect();
    if let Ok(b) = crate::fsutil::read_bounded(&server_dir.join("usercache.json"), 4 * 1024 * 1024)
        && let Ok(list) = serde_json::from_slice::<Vec<Entry>>(&b)
    {
        for e in list {
            if crate::console::player_name_ok(&e.name)
                && fold(&e.name).contains(&q)
                && !out.iter().any(|p| p.name.eq_ignore_ascii_case(&e.name))
            {
                out.push(PlayerSuggestion { name: e.name, online: false });
            }
        }
    }
    out.truncate(MAX_SUGGESTIONS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Recherche en français ET en anglais, sans accents ni casse ; blocs sans objet exclus.
    #[test]
    fn recherche_bilingue_sans_accents() {
        let fr = table(&[
            ("item.minecraft.diamond_sword", "Épée en diamant"),
            ("item.minecraft.iron_sword", "Épée en fer"),
            ("block.minecraft.blue_wool", "Laine bleue"),
            ("item.minecraft.elytra", "Élytres"),
            ("block.minecraft.water", "Eau"),
            ("block.minecraft.oak_wall_sign", "Panneau mural en chêne"),
            ("block.minecraft.banner.base.white", "Bannière"),
            ("item.minecraft.ender_pearl", "Perle de l’Ender"),
        ]);
        let en = table(&[
            ("item.minecraft.diamond_sword", "Diamond Sword"),
            ("item.minecraft.iron_sword", "Iron Sword"),
            ("block.minecraft.blue_wool", "Blue Wool"),
            ("item.minecraft.elytra", "Elytra"),
            ("block.minecraft.water", "Water"),
        ]);
        let idx = ItemIndex::build(&fr, Some(&en));
        assert_eq!(idx.len(), 5, "eau, panneau mural et bannière exclus");
        let ids = |q: &str| idx.search(q).into_iter().map(|s| s.id).collect::<Vec<_>>();
        assert_eq!(ids("epee"), ["iron_sword", "diamond_sword"]);
        assert_eq!(ids("ÉPÉE EN D"), ["diamond_sword"]);
        assert_eq!(ids("epee dia"), ["diamond_sword"], "chaque mot dans le même nom");
        assert_eq!(ids("dia sword"), ["diamond_sword"]);
        assert_eq!(ids("sword"), ["iron_sword", "diamond_sword"]);
        assert_eq!(ids("laine bl"), ["blue_wool"]);
        assert_eq!(ids("blue_wool"), ["blue_wool"]);
        assert_eq!(ids("elytres"), ["elytra"]);
        assert_eq!(ids("perle de l'ender"), ["ender_pearl"]);
        assert!(ids("").is_empty());
        let s = &idx.search("ender")[0];
        assert_eq!(
            (s.fr.as_str(), s.en.as_str()),
            ("Perle de l’Ender", "Ender Pearl"),
            "anglais déduit de l'identifiant"
        );
    }

    #[test]
    fn joueurs_connus() {
        let d = std::env::temp_dir().join(format!("rcm-lang-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("usercache.json"),
            r#"[{"name":"Notch","uuid":"x","expiresOn":"y"},{"name":"neo","uuid":"z","expiresOn":"y"},{"name":"bad name","uuid":"w"}]"#,
        )
        .unwrap();
        let p = players(&d, &["Neo".into()], "");
        assert_eq!(
            p.iter().map(|p| (p.name.as_str(), p.online)).collect::<Vec<_>>(),
            [("Neo", true), ("Notch", false)]
        );
        assert_eq!(players(&d, &[], "NOT").len(), 1);
    }

    /// Un échec de téléchargement est mémorisé quelques minutes, par version.
    #[test]
    fn echec_memorise_par_version() {
        let l = Languages::default();
        let t = Instant::now();
        assert!(!l.recently_failed("26.3", t));
        l.mark_failed("26.3", t);
        assert!(l.recently_failed("26.3", t + Duration::from_secs(10)));
        assert!(!l.recently_failed("26.3", t + RETRY_AFTER + Duration::from_secs(1)));
        assert!(!l.recently_failed("26.2", t));
    }

    #[test]
    fn plis_des_accents() {
        assert_eq!(fold("Épée À Œil"), "epee a oeil");
        assert_eq!(fold("blue_wool"), "blue wool");
    }
}
