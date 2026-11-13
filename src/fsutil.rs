//! Fichiers : écriture atomique (temporaire dans le même dossier, fsync, renommage, fsync du
//! dossier, rien si identique), lecture bornée.

use std::path::Path;

/// fsync d'un dossier (Unix : rend le renommage durable ; sans effet sous Windows).
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Écrit `data` dans `path` de façon atomique. Rend `false` si le contenu était déjà identique
/// (rien n'est écrit).
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<bool> {
    use std::io::Write;
    if read_bounded(path, data.len() as u64).is_ok_and(|old| old == data) {
        return Ok(false);
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    // Nom du temporaire indépendant de celui du fichier : un nom de 250 octets (permis) ne doit
    // pas donner un temporaire trop long pour le système. Reconnaissable ([`is_atomic_tmp`]) :
    // les restes d'un plantage sont effacés au démarrage.
    let tmp = dir.join(format!(".rcm-{}.tmp", crate::crypto::base32(&crate::crypto::random_bytes::<5>())));
    let res = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        // Droits du fichier remplacé conservés (Unix).
        #[cfg(unix)]
        if let Ok(m) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&tmp, m.permissions());
        }
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res?;
    sync_dir(dir);
    Ok(true)
}

/// Nom d'un temporaire de [`write_atomic`] : `.rcm-` + 8 caractères base32 + `.tmp`.
pub fn is_atomic_tmp(name: &str) -> bool {
    name.strip_prefix(".rcm-")
        .and_then(|r| r.strip_suffix(".tmp"))
        .is_some_and(|m| m.len() == 8 && m.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)))
}

/// Place gardée libre sur le disque : un envoi qui la consommerait est refusé.
pub const DISK_RESERVE: u64 = 256 << 20;

/// Place libre sur le volume qui porte `p` (point de montage le plus long qui le contient) ;
/// `None` si inconnue.
pub fn free_space(p: &Path) -> Option<u64> {
    let p = std::fs::canonicalize(p).ok()?;
    // Windows : `\\?\D:\…` (forme canonique) comparé à `D:\` (point de montage).
    let s = p.to_string_lossy();
    let p =
        std::path::PathBuf::from(s.strip_prefix(r"\\?\").filter(|r| r.as_bytes().get(1) == Some(&b':')).unwrap_or(&s));
    let disks = sysinfo::Disks::new_with_refreshed_list().ok()?;
    disks
        .iter()
        .filter(|d| p.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| d.available_space())
}

/// `need` octets de plus tiennent-ils sur le volume de `p` en gardant [`DISK_RESERVE`] libres ?
/// Place inconnue : oui (rien à mesurer).
pub fn room_for(p: &Path, need: u64) -> bool {
    free_space(p).is_none_or(|free| free >= need.saturating_add(DISK_RESERVE))
}

/// Lit au plus `max` octets (fichier plus grand, même s'il grandit pendant la lecture : erreur de
/// genre `Other`). Jamais au travers d'un lien sur le dernier composant (un processus du serveur
/// pourrait pointer `whitelist.json` ou `server.properties` vers un fichier du gestionnaire) :
/// erreur `InvalidInput`, comme pour ce qui n'est pas un fichier ordinaire.
pub fn read_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = crate::files::open_file(path).map_err(|e| match e {
        crate::files::FsErr::NotFound => std::io::Error::from(std::io::ErrorKind::NotFound),
        _ => std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} : pas un fichier ordinaire", path.display()),
        ),
    })?;
    let mut b = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut b)?;
    if b.len() as u64 > max {
        return Err(std::io::Error::other(format!("{} : plus de {max} octets", path.display())));
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecriture_atomique_et_rien_si_identique() {
        let d = std::env::temp_dir().join(format!("rcm-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("a.txt");
        assert!(write_atomic(&p, b"un").unwrap());
        assert!(!write_atomic(&p, b"un").unwrap(), "identique : rien");
        assert!(write_atomic(&p, b"deux").unwrap());
        assert_eq!(std::fs::read(&p).unwrap(), b"deux");
        let names: Vec<_> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("a.txt")], "aucun temporaire restant");
        assert!(read_bounded(&p, 3).is_err());
        assert_eq!(read_bounded(&p, 4).unwrap(), b"deux");
        // Nom de 250 octets (segment permis) : le temporaire ne doit pas dépasser la limite.
        let long = d.join(format!("{}.txt", "n".repeat(246)));
        assert!(write_atomic(&long, b"x").unwrap());
        assert!(write_atomic(&long, b"y").unwrap());
        assert_eq!(std::fs::read(&long).unwrap(), b"y");
    }

    /// Place libre mesurée sur le volume du dossier (forme canonique de Windows comprise).
    #[test]
    fn place_libre_du_volume() {
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
        assert!(free_space(&d).is_some_and(|f| f > 0), "volume trouvé");
        assert!(room_for(&d, 0));
        assert!(!room_for(&d, u64::MAX / 2), "plus que le disque");
    }
}
