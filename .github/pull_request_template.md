## Quoi et pourquoi

<!-- Le scénario : ce qui manquait ou clochait, ce que la PR change. -->

## Vérifié

<!-- Tests, capture d'écran pour l'interface (bureau et mobile). -->

## Mesures

<!-- Pour une optimisation : avant / après, méthode, machine. Sinon : « sans objet ». -->

## Liste

- [ ] `cargo fmt`, clippy `-D warnings` (natif et wasm), `cargo test --release --workspace`
- [ ] Toute route qui modifie passe par session, CSRF et audit ; entrées bornées
- [ ] Un test qui échoue sans le correctif (pour un bogue ou une faille)
- [ ] Textes en français et en anglais, aucune information répétée à l'écran
- [ ] Résultats ajoutés à `docs/perf.md` si c'est une optimisation
