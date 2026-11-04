//! Chemins construits à partir d'une saisie (identifiant de serveur, version du jeu, version de
//! Java, coordonnée Maven) : validés ici, en un seul endroit, avant de toucher au disque.
//!
//! Règle : un segment de chemin vient d'une valeur VALIDÉE (chiffres, ou caractères d'une liste
//! courte sans séparateur ni `..`), jamais d'un texte brut.

use std::path::{Path, PathBuf};

/// Identifiant de serveur : entier strictement positif écrit en chiffres ASCII (pas de signe, pas
/// de zéro en tête, au plus 18 chiffres).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServerId(i64);

impl ServerId {
    pub fn parse(s: &str) -> Option<ServerId> {
        if s.is_empty() || s.len() > 18 || !s.bytes().all(|b| b.is_ascii_digit()) || s.starts_with('0') {
            return None;
        }
        s.parse::<i64>().ok().filter(|n| *n > 0).map(ServerId)
    }
    pub fn from_db(n: i64) -> Option<ServerId> {
        (n > 0).then_some(ServerId(n))
    }
    pub fn get(self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for ServerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Dossier d'un serveur : `<données>/servers/<id>`.
pub fn server_dir(data: &Path, id: ServerId) -> PathBuf {
    data.join("servers").join(id.to_string())
}

/// Dossier de la corbeille (serveurs supprimés) : `<données>/trash/<id>-<instant>`.
pub fn trash_dir(data: &Path, id: ServerId, ts: i64) -> PathBuf {
    data.join("trash").join(format!("{id}-{}", ts.max(0)))
}

/// Version du jeu ou d'un chargeur (`26.3`, `1.21.11`, `0.18.2`, `26.4-snapshot-4`,
/// `0.30.0-beta.4`, `1.21.11-rc3`) : lettres, chiffres, `.`, `-`, `_`, `+` ; ni `..`, ni point en
/// tête ; 1 à 48 caractères.
pub fn version_valid(v: &str) -> bool {
    (1..=48).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
        && !v.contains("..")
        && !v.starts_with('.')
        && !is_windows_reserved(v)
}

/// Noms réservés de Windows (`CON`, `NUL`, `COM1`…, `COM¹`–`COM³` et `LPT¹`–`LPT³` compris), avec
/// ou sans extension, espaces finaux du radical ignorés (Windows les retire : `NUL .txt`).
pub fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    let mut chars = stem.chars();
    let head: String = chars.by_ref().take(3).collect();
    let tail: Vec<char> = chars.collect();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((head == "COM" || head == "LPT")
            && matches!(tail.as_slice(), [c] if c.is_ascii_digit() || matches!(c, '¹' | '²' | '³')))
}

/// Nom au format court 8.3 de Windows (`SERVER~1.PRO`, `RCM~1`) : `~` suivi d'un chiffre. Un tel
/// nom désigne, sur un volume qui les crée, un fichier dont le vrai nom est tout autre : refusé
/// partout où un chemin est demandé.
pub fn is_short_name(name: &str) -> bool {
    name.as_bytes().windows(2).any(|w| w[0] == b'~' && w[1].is_ascii_digit())
}

/// Forme d'un nom pour les règles de chemin : sans casse (Windows ignore la casse : `Server.Properties`
/// EST `server.properties`). Majuscules puis minuscules : `ſ` (s long) et `K` (signe kelvin) se
/// ramènent aussi à `s` et `k` ; comparer plus large ne fait qu'appliquer une règle de plus.
pub fn fold(name: &str) -> String {
    name.to_uppercase().to_lowercase()
}

/// Les composants réels de `real` sous `canon_root` (formes canoniques : vrais noms longs, vraie
/// casse) sont exactement les segments demandés, casse à part. Un nom court 8.3, ou tout autre
/// alias qu'accepterait le système, ne passe pas.
pub fn real_names_match(canon_root: &Path, real: &Path, segs: &[&str]) -> bool {
    let Ok(rest) = real.strip_prefix(canon_root) else { return false };
    let names: Vec<String> = rest.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    names.len() == segs.len() && names.iter().zip(segs).all(|(a, b)| fold(a) == fold(b))
}

/// Dossier des fichiers de langue d'une version : `<données>/lang/<version>`.
pub fn lang_dir(data: &Path, version: &str) -> Option<PathBuf> {
    version_valid(version).then(|| data.join("lang").join(version))
}

/// Dossier d'un Java géré : `<données>/java/<majeure>`.
pub fn java_dir(data: &Path, major: u32) -> PathBuf {
    data.join("java").join(major.to_string())
}

/// Chemin relatif d'une bibliothèque Maven (`groupe:artefact:version`) :
/// `groupe/en/dossiers/artefact/version/artefact-version.jar`. Chaque segment est validé.
pub fn maven_path(coord: &str) -> Option<PathBuf> {
    let mut parts = coord.split(':');
    let (g, a, v) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 96
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
            && !s.contains("..")
            && !s.starts_with('.')
            && !is_windows_reserved(s)
    };
    let groups: Vec<&str> = g.split('.').collect();
    if !groups.iter().all(|s| seg_ok(s)) || !seg_ok(a) || !seg_ok(v) {
        return None;
    }
    let mut p = PathBuf::new();
    for s in groups {
        p.push(s);
    }
    p.push(a);
    p.push(v);
    p.push(format!("{a}-{v}.jar"));
    Some(p)
}

/// `relatif` reste-t-il sous `racine` ? (aucun composant `..`, racine, préfixe de lecteur).
pub fn is_confined(rel: &Path) -> bool {
    use std::path::Component;
    rel.components().all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identifiants hostiles refusés : chemin, traversée, encodages, signe, zéro, nombres géants,
    /// noms réservés, espaces, Unicode.
    #[test]
    fn identifiants_hostiles_refuses() {
        assert_eq!(ServerId::parse("1"), Some(ServerId(1)));
        assert_eq!(ServerId::parse("42").map(|i| i.get()), Some(42));
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            "01",
            "1.0",
            "1e3",
            "..",
            "../1",
            "1/../2",
            "%2e%2e",
            "%2e%2e%2f1",
            "1%00",
            "1\0",
            "CON",
            "NUL",
            "1 ",
            " 1",
            "١",
            "9223372036854775808",
            "99999999999999999999",
            "0x10",
            "1;rm",
            "1\\..\\2",
            "C:\\1",
        ] {
            assert_eq!(ServerId::parse(bad), None, "{bad:?}");
        }
        let data = Path::new("data");
        let d = server_dir(data, ServerId::parse("7").unwrap());
        assert_eq!(d, Path::new("data").join("servers").join("7"));
        assert!(is_confined(d.strip_prefix(data).unwrap()));
        assert_eq!(ServerId::from_db(0), None);
    }

    #[test]
    fn versions_hostiles_refusees() {
        for ok in ["26.3", "1.21.11", "26.4-snapshot-4", "0.30.0-beta.4", "1.21.11-rc3", "0.16.5+mixin.0.8.7", "b1.7.3"]
        {
            assert!(version_valid(ok), "{ok}");
        }
        for bad in [
            "",
            "..",
            "../26.3",
            "26.3/..",
            "26.3\\x",
            "26 3",
            ".hidden",
            "a..b",
            "CON",
            "nul.txt",
            "COM1",
            "lpt9",
            "COM¹",
            "lpt³.txt",
            "NUL .txt",
            "com²",
            "26.3\0",
            "%2e%2e",
            &"9".repeat(49),
            "é",
        ] {
            assert!(!version_valid(bad), "{bad:?}");
            assert!(lang_dir(Path::new("d"), bad).is_none());
        }
    }

    #[test]
    fn coordonnees_maven_hostiles_refusees() {
        assert_eq!(
            maven_path("net.fabricmc:fabric-loader:0.18.2").unwrap(),
            Path::new("net").join("fabricmc").join("fabric-loader").join("0.18.2").join("fabric-loader-0.18.2.jar")
        );
        assert!(maven_path("net.fabricmc:sponge-mixin:0.16.5+mixin.0.8.7").is_some());
        for bad in [
            "a:b",
            "a:b:c:d",
            "..:b:c",
            "a:..:c",
            "a:b:..",
            "a/b:c:d",
            "a:b\\c:d",
            "a..b:c:d",
            ":b:c",
            "a::c",
            "a:b:c/../../x",
            "CON:b:c",
            "a:b:%2e%2e",
            "a:b:x..y",
            "a:x..y:1",
        ] {
            assert!(maven_path(bad).is_none(), "{bad}");
        }
        assert!(!is_confined(Path::new("../x")));
        assert!(!is_confined(Path::new("/etc/passwd")));
        assert!(is_confined(Path::new("a/b.jar")));
    }

    /// Noms réservés de Windows, y compris les chiffres en exposant et les espaces finaux.
    #[test]
    fn noms_reserves() {
        for r in
            ["CON", "con.txt", "NUL .txt", "aux", "COM1", "lpt9.log", "COM¹", "com².x", "LPT³", "CONIN$", "conout$.a"]
        {
            assert!(is_windows_reserved(r), "{r}");
        }
        for ok in ["CONSOLE", "COM", "COM10", "LPT⁴", "world", "nul_", "comx", "a.CON"] {
            assert!(!is_windows_reserved(ok), "{ok}");
        }
    }
}
