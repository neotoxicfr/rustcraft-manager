//! Dossier de données : droits (0700 pour le dossier, 0600 pour la base et la clé sous Unix),
//! sonde d'écriture au démarrage, clé de chiffrement fournie ou créée au premier lancement.
//!
//! `create_dir_all` ne change pas les droits d'un dossier existant : ils sont
//! posés explicitement à chaque démarrage. Un volume Docker monté depuis l'hôte (NAS…) qui
//! n'appartient pas à l'utilisateur du conteneur se voit tout de suite, avec la commande `chown`
//! exacte.

use crate::config::Config;
use crate::crypto::MasterKey;
use std::path::Path;

/// Crée le dossier si besoin, le restreint au propriétaire et vérifie qu'on peut y écrire.
pub fn prepare(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| probe_message(dir, &e))?;
    restrict_dir(dir).map_err(|e| format!("dossier de données {} : droits 0700 impossibles ({e})", dir.display()))?;
    probe(dir)
}

/// Écrit puis efface un fichier témoin.
pub fn probe(dir: &Path) -> Result<(), String> {
    let p = dir.join(".rcm-sonde-ecriture");
    std::fs::write(&p, b"ok").and_then(|_| std::fs::remove_file(&p)).map_err(|e| probe_message(dir, &e))
}

/// Message d'une écriture impossible : uid effectif et commande à lancer sur l'hôte.
pub fn probe_message(dir: &Path, err: &std::io::Error) -> String {
    let mut m = format!("dossier de données {} : écriture impossible ({err})", dir.display());
    if let Some(uid) = effective_uid() {
        m.push_str(&format!(
            ". Le processus tourne avec l'uid {uid} : sur l'hôte, donner le dossier monté à cet \
             utilisateur, par exemple `chown -R {uid}:{uid} <dossier de l'hôte>` (ou lancer le \
             conteneur avec `--user <uid>:<gid>` du propriétaire)"
        ));
    }
    m
}

/// Uid effectif (Linux : `/proc/self/status`, sans `libc` ni code `unsafe`).
pub fn effective_uid() -> Option<u32> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("Uid:"))?;
    // Uid: réel effectif sauvé système de fichiers
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(unix)]
pub fn restrict_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub fn restrict_dir(_dir: &Path) -> std::io::Result<()> {
    // Windows : le dossier hérite des droits du profil (%LOCALAPPDATA%), déjà propres à l'utilisateur.
    Ok(())
}

/// Restreint un fichier existant au propriétaire (0600 sous Unix).
#[cfg(unix)]
pub fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn restrict_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Crée un fichier neuf (erreur s'il existe) directement en 0600 sous Unix, et y écrit `data`.
pub fn create_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Clé de chiffrement : fournie (`RCM_ENCRYPTION_KEY(_FILE)`), sinon lue dans `manager.key`, sinon
/// créée au premier lancement hors conteneur. Dans l'image Docker, elle doit être fournie (secret
/// Docker) : une clé générée dans le volume serait sauvegardée avec la base qu'elle protège.
/// `db_has_data` : la base existe déjà avec des données chiffrées (alors pas de nouvelle clé : on
/// ne pourrait plus rien déchiffrer).
pub fn master_key(cfg: &Config, db_has_data: bool) -> Result<(MasterKey, KeySource), String> {
    if let Some(k) = &cfg.encryption_key {
        return Ok((k.clone(), KeySource::Provided));
    }
    // Conteneur : la clé doit venir d'un secret, MÊME si un `manager.key` traîne dans le volume
    // (il serait sauvegardé avec la base qu'il protège ; mineur 2 de la seconde revue).
    if cfg.container {
        return Err("RCM_CONTAINER=true : fournir la clé de chiffrement par un secret Docker \
                    (RCM_ENCRYPTION_KEY_FILE=/run/secrets/<nom>, 32 octets aléatoires en base64, \
                    par exemple `openssl rand -base64 32`) ; un manager.key du volume n'est jamais \
                    utilisé ni généré"
            .into());
    }
    let path = cfg.key_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            restrict_file(&path).map_err(|e| format!("{} : droits 0600 impossibles ({e})", path.display()))?;
            let k = MasterKey::parse(&s).map_err(|e| format!("{} : {e}", path.display()))?;
            return Ok((k, KeySource::File));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("{} : lecture impossible ({e})", path.display()));
        }
        Err(_) => {}
    }
    if db_has_data {
        return Err(format!(
            "clé de chiffrement introuvable ({} absent, RCM_ENCRYPTION_KEY non définie) alors que la \
             base contient des données chiffrées : restaurer le fichier de clé",
            path.display()
        ));
    }
    let k = MasterKey::generate();
    create_private(&path, format!("{}\n", k.to_base64()).as_bytes())
        .map_err(|e| format!("{} : création impossible ({e})", path.display()))?;
    Ok((k, KeySource::Generated))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Provided,
    File,
    Generated,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rcm-datadir-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sonde_d_ecriture() {
        let d = tmp("sonde");
        assert!(prepare(&d.join("sous")).is_ok());
        // Dossier existant où l'on ne peut pas écrire (le témoin est pris par un dossier) : refus.
        std::fs::create_dir_all(d.join("bloque").join(".rcm-sonde-ecriture")).unwrap();
        assert!(prepare(&d.join("bloque")).unwrap_err().contains("écriture impossible"));
        assert!(!d.join("sous").join(".rcm-sonde-ecriture").exists(), "témoin effacé");
        // Un fichier à la place du dossier : refus explicite qui nomme le dossier.
        let f = d.join("fichier");
        std::fs::write(&f, b"x").unwrap();
        let e = prepare(&f).unwrap_err();
        assert!(e.contains("écriture impossible") && e.contains("fichier"), "{e}");
        // Message avec l'uid et la commande chown quand l'uid est connu.
        let m = probe_message(&d, &std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        if effective_uid().is_some() {
            assert!(m.contains("chown -R"), "{m}");
        }
    }

    #[test]
    fn cle_fournie_lue_creee_ou_refusee() {
        let d = tmp("cle");
        let mut cfg = Config::with_data_dir(d.clone());
        // Premier lancement hors conteneur : créée, puis relue identique.
        let (k1, s1) = master_key(&cfg, false).unwrap();
        assert_eq!(s1, KeySource::Generated);
        let (k2, s2) = master_key(&cfg, true).unwrap();
        assert_eq!((k1.clone(), s2), (k2, KeySource::File));
        // Fournie : prioritaire.
        let k3 = MasterKey::generate();
        cfg.encryption_key = Some(k3.clone());
        assert_eq!(master_key(&cfg, true).unwrap(), (k3, KeySource::Provided));
        // Fichier absent mais base déjà chiffrée : refus (pas de nouvelle clé).
        cfg.encryption_key = None;
        std::fs::remove_file(cfg.key_path()).unwrap();
        assert!(master_key(&cfg, true).unwrap_err().contains("introuvable"));
        // Conteneur : jamais générée.
        cfg.container = true;
        assert!(master_key(&cfg, false).unwrap_err().contains("RCM_ENCRYPTION_KEY_FILE"));
        assert!(!cfg.key_path().exists());
        // Conteneur avec un manager.key dans le volume : refusé quand même.
        std::fs::write(cfg.key_path(), format!("{}\n", MasterKey::generate().to_base64())).unwrap();
        assert!(master_key(&cfg, true).is_err(), "clé du volume utilisée en conteneur");
        std::fs::remove_file(cfg.key_path()).unwrap();
        // Fichier corrompu : refus.
        cfg.container = false;
        std::fs::write(cfg.key_path(), "abc").unwrap();
        assert!(master_key(&cfg, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn droits_unix() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("droits");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare(&d).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        let cfg = Config::with_data_dir(d.clone());
        master_key(&cfg, false).unwrap();
        assert_eq!(std::fs::metadata(cfg.key_path()).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
