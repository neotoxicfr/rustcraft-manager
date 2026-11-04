//! Lecture de l'environnement derrière un trait : la configuration se teste sans toucher aux
//! variables du processus.
//!
//! Secrets : `RCM_<NOM>_FILE` (chemin d'un fichier, secrets Docker) ou `RCM_<NOM>` ; les deux
//! définis = erreur ; fichier illisible ou vide = erreur (refus de démarrer, jamais de repli
//! silencieux sur la variable). La valeur n'apparaît jamais dans un
//! message d'erreur.

use std::collections::HashMap;
use std::path::Path;

pub trait Env {
    /// Valeur d'une variable ; `Err` si elle existe mais n'est pas de l'UTF-8 (l'erreur la nomme).
    fn var(&self, name: &str) -> Result<Option<String>, String>;
    /// Contenu d'un fichier de secret.
    fn read_file(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
}

/// Environnement du processus.
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Result<Option<String>, String> {
        match std::env::var(name) {
            Ok(v) => Ok(Some(v)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} : valeur qui n'est pas de l'UTF-8")),
        }
    }
}

/// Environnement en mémoire (tests, outils) : variables et fichiers.
#[derive(Default, Clone)]
pub struct MapEnv {
    pub vars: HashMap<String, String>,
    pub files: HashMap<String, String>,
}

impl MapEnv {
    pub fn new(vars: &[(&str, &str)]) -> Self {
        MapEnv { vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), files: HashMap::new() }
    }
    pub fn file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.to_string(), content.to_string());
        self
    }
}

impl Env for MapEnv {
    fn var(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self.vars.get(name).cloned())
    }
    fn read_file(&self, path: &Path) -> std::io::Result<String> {
        self.files
            .get(&path.to_string_lossy().to_string())
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "absent"))
    }
}

/// Secret `name` : `name_FILE` (contenu du fichier, espaces de bord retirés) ou `name`.
pub fn secret(env: &dyn Env, name: &str) -> Result<Option<String>, String> {
    let file_var = format!("{name}_FILE");
    let direct = env.var(name)?;
    let file = env.var(&file_var)?;
    match (direct, file) {
        (Some(_), Some(_)) => Err(format!("{name} et {file_var} sont définies toutes les deux : n'en garder qu'une")),
        (_, Some(path)) => {
            let path = path.trim();
            if path.is_empty() {
                return Err(format!("{file_var} : chemin vide"));
            }
            let content =
                env.read_file(Path::new(path)).map_err(|e| format!("{file_var} : fichier {path} illisible ({e})"))?;
            let content = content.trim();
            if content.is_empty() {
                return Err(format!("{file_var} : fichier {path} vide"));
            }
            Ok(Some(content.to_string()))
        }
        (Some(v), None) => {
            let v = v.trim();
            if v.is_empty() {
                return Err(format!("{name} : valeur vide"));
            }
            Ok(Some(v.to_string()))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_par_fichier_prioritaire_et_ferme() {
        let k = "RCM_ENCRYPTION_KEY";
        // Rien : pas de secret.
        assert_eq!(secret(&MapEnv::default(), k).unwrap(), None);
        // Variable seule.
        let e = MapEnv::new(&[(k, " abc ")]);
        assert_eq!(secret(&e, k).unwrap().as_deref(), Some("abc"));
        // Fichier seul, espaces et fin de ligne retirés.
        let e = MapEnv::new(&[("RCM_ENCRYPTION_KEY_FILE", "/run/secrets/k")]).file("/run/secrets/k", "xyz\n");
        assert_eq!(secret(&e, k).unwrap().as_deref(), Some("xyz"));
        // Les deux : erreur (et la valeur n'est pas citée).
        let e = MapEnv::new(&[(k, "en-clair"), ("RCM_ENCRYPTION_KEY_FILE", "/run/secrets/k")])
            .file("/run/secrets/k", "xyz");
        let err = secret(&e, k).unwrap_err();
        assert!(err.contains("RCM_ENCRYPTION_KEY_FILE") && !err.contains("en-clair"), "{err}");
        // Fichier illisible : erreur, jamais de repli.
        let e = MapEnv::new(&[("RCM_ENCRYPTION_KEY_FILE", "/absent")]);
        assert!(secret(&e, k).unwrap_err().contains("illisible"));
        // Fichier vide : erreur.
        let e = MapEnv::new(&[("RCM_ENCRYPTION_KEY_FILE", "/vide")]).file("/vide", " \n");
        assert!(secret(&e, k).unwrap_err().contains("vide"));
        // Variable vide : erreur.
        assert!(secret(&MapEnv::new(&[(k, "  ")]), k).is_err());
    }
}
