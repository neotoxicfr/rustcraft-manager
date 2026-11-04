//! Mots de passe : Argon2id, paramètres par défaut de la crate (19 Mio, 2 passes, 1 voie : le
//! minimum recommandé par l'OWASP), sel aléatoire, chaîne PHC en base.
//!
//! Chaque hachage prend ≈ 19 Mio pendant ≈ 25 ms : le nombre de hachages simultanés est borné
//! par un sémaphore à min(cœurs, [`MAX_CONCURRENT_HASHES`]). Mesuré sous 50 connexions qui se
//! connectent en boucle (docs/perf.md) : 32 hachages simultanés = 519 connexions/s pour 625 Mo de
//! pic ; 4 = 263/s pour 90 Mo. Le hachage tourne dans un fil bloquant.

use crate::error::AppError;
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Plafond des hachages simultanés (mémoire bornée à ≈ 4 × 19 Mio).
pub const MAX_CONCURRENT_HASHES: usize = 4;

#[derive(Clone)]
pub struct Hasher {
    permits: Arc<Semaphore>,
    /// Attente maximale d'une place : au-delà, 503 + `Retry-After` plutôt qu'une file sans fin
    /// (sous une rafale, les requêtes s'empileraient et tiendraient leurs connexions).
    wait: Duration,
    /// Empreinte d'un mot de passe jetable : vérifiée quand le compte n'existe pas, pour que la
    /// durée de la réponse ne révèle pas les noms de comptes.
    dummy: Arc<String>,
    /// Hachages en cours dans les fils bloquants, et le plus haut observé (mesure, tests).
    running: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

/// Compte un hachage en cours tant qu'il vit (dans le fil bloquant).
struct Running(Arc<AtomicUsize>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Hasher {
    pub fn new(concurrency: usize, wait: Duration) -> Self {
        let dummy = hash_blocking(&crate::crypto::token()).expect("Argon2 indisponible");
        Hasher {
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            wait,
            dummy: Arc::new(dummy),
            running: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Place de hachage POSSÉDÉE : elle part avec le travail dans le fil bloquant. Si le client
    /// coupe la connexion, hyper abandonne le futur de la requête, mais Argon2 continue dans
    /// `spawn_blocking` : avec un permis emprunté, la place était rendue alors que le calcul
    /// tournait encore, et les hachages simultanés n'étaient plus bornés que par les fils
    /// bloquants (revue B-A).
    async fn permit(&self) -> Result<OwnedSemaphorePermit, AppError> {
        match tokio::time::timeout(self.wait, self.permits.clone().acquire_owned()).await {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(_)) => Err(AppError::internal()),
            Err(_) => Err(AppError::busy()),
        }
    }

    /// Exécute `f` dans un fil bloquant en y gardant la place jusqu'à la fin du calcul.
    async fn run<R: Send + 'static>(&self, f: impl FnOnce() -> R + Send + 'static) -> Result<R, AppError> {
        let permit = self.permit().await?;
        let (running, peak) = (self.running.clone(), self.peak.clone());
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            let _running = Running(running);
            f()
        })
        .await
        .map_err(|_| AppError::internal())
    }

    pub async fn hash(&self, password: String) -> Result<String, AppError> {
        self.run(move || hash_blocking(&password)).await?
    }

    /// Vérifie `password` contre `phc` (ou contre l'empreinte jetable si `None`, résultat faux).
    /// `Err` (503) si aucune place ne se libère à temps.
    pub async fn verify(&self, password: String, phc: Option<String>) -> Result<bool, AppError> {
        let known = phc.is_some();
        let phc = phc.unwrap_or_else(|| (*self.dummy).clone());
        let ok = self.run(move || verify_blocking(&password, &phc)).await?;
        Ok(ok && known)
    }

    /// Plus grand nombre de hachages simultanés observé.
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

pub fn hash_blocking(password: &str) -> Result<String, AppError> {
    Argon2::default().hash_password(password.as_bytes()).map(|h| h.to_string()).map_err(|_| AppError::internal())
}

pub fn verify_blocking(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) => Argon2::default().verify_password(password.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_aller_retour() {
        let h = hash_blocking("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify_blocking("correct horse battery", &h));
        assert!(!verify_blocking("correct horse batterie", &h));
        assert!(!verify_blocking("x", "pas une chaîne PHC"));
        // Sel aléatoire : deux empreintes différentes.
        assert_ne!(h, hash_blocking("correct horse battery").unwrap());
    }

    /// Plus aucune place après le délai : 503 au lieu d'une attente sans fin.
    #[tokio::test]
    async fn semaphore_avec_delai() {
        let h = Hasher::new(1, Duration::from_millis(20));
        let held = h.permits.clone().acquire_owned().await.unwrap();
        let e = tokio::time::timeout(Duration::from_secs(2), h.verify("x".into(), None))
            .await
            .expect("attente sans fin d'une place de hachage")
            .unwrap_err();
        assert_eq!(e.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(e.retry_after.is_some());
        drop(held);
        assert_eq!(h.verify("x".into(), None).await, Ok(false));
    }

    /// Revue B-A : des requêtes coupées pendant le hachage (futur abandonné) ne libèrent pas la
    /// place tant qu'Argon2 tourne : jamais plus de `concurrency` hachages simultanés.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn coupures_pendant_le_hachage_bornees() {
        let h = Hasher::new(2, Duration::from_secs(5));
        for _ in 0..8 {
            let before = h.running.load(Ordering::SeqCst);
            let h2 = h.clone();
            let task = tokio::spawn(async move {
                let _ = h2.verify("x".into(), None).await;
            });
            // Le « client » coupe dès que son hachage tourne (ou au bout de 200 ms s'il attend
            // une place) : le futur de la requête est abandonné, Argon2 continue.
            let deadline = std::time::Instant::now() + Duration::from_millis(200);
            while h.running.load(Ordering::SeqCst) <= before && std::time::Instant::now() < deadline {
                tokio::task::yield_now().await;
            }
            task.abort();
            let _ = task.await;
        }
        // Laisser finir les calculs encore en cours.
        while h.running.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(h.peak() <= 2, "{} hachages simultanés pour 2 places", h.peak());
        assert!(h.peak() >= 1);
    }
}
