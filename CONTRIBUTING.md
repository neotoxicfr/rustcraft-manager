# Contribuer à Rustcraft Manager

Merci de vouloir aider. Rustcraft Manager vise un gestionnaire de serveurs Minecraft sûr, rapide
et agréable : chaque contribution est jugée sur la sécurité, la mesure et la finition.

## Règles

- **Rien de Mojang dans le dépôt** : ni `server.jar`, ni ressource du jeu. Les logiciels serveur
  sont téléchargés à l'exécution depuis leurs sources officielles, somme de contrôle vérifiée.
- **Sécurité d'abord** : toute route qui modifie quelque chose passe par la session, le jeton CSRF
  et l'audit ; toute entrée est bornée ; aucun appel à un shell. Un correctif de sécurité arrive
  avec un test qui échoue sans lui.
- **Mesure** : une optimisation arrive avec ses chiffres avant et après, la méthode et la machine,
  notés dans `docs/perf.md` (variantes écartées comprises).
- **Interface** : chaque information une seule fois (pas de surtitre, pas de sous-titre qui
  reformule, pas d'aide qui répète le libellé), tous les états soignés (survol, focus, chargement,
  erreur), mobile compris. Une modification d'interface n'est finie que vue à l'écran : joins une
  capture à la PR. Les couleurs, espacements et typographies passent par les variables du thème.
- **Traductions** : chaque texte existe en français et en anglais ; une clé manquante ne compile pas.

## Avant d'ouvrir une PR

Les PR visent la branche `dev` : chaque arrivée y publie l'image `ghcr.io/neotoxicfr/rustcraft-manager:dev`.
`main` ne reçoit que les releases (étiquettes `X.Y.Z` et `latest`).

Une seule commande, la même que le hook `pre-push` et la CI (GitHub Actions) :

```
scripts/check.sh
```

Elle enchaîne le format (natif et interface), clippy `-D warnings` sur la cible wasm puis la
construction de l'interface (`trunk build`, embarquée ensuite dans le binaire), clippy natif, les
tests, `cargo deny check` et `cargo audit` (natif et interface). Sous Windows, la lancer depuis Git
Bash. `RCM_CARGO="<commande>"` remplace `cargo` pour les étapes natives (file de compilation).

Activer le hook versionné une fois par clone :

```
git config core.hooksPath .githooks
```

Outils : `rustup target add wasm32-unknown-unknown`, `cargo install --locked trunk --version
0.21.14`, `cargo install --locked wasm-bindgen-cli --version 0.2.129`, `cargo install --locked
cargo-deny cargo-audit`, et `wasm-opt` de binaryen version_133 dans le `PATH` (archive officielle
de GitHub, `bin/wasm-opt.exe` seul : trunk l'emploie hors ligne). Un écart accepté (avis, licence) se justifie dans `deny.toml`.

## Style

- Code, commentaires et documentation en français. Messages de commit en anglais, au format
  [Conventional Commits](https://www.conventionalcommits.org/) (`feat(auth): …`, `fix(web): …`,
  `perf(api): …`), avec un corps qui explique le scénario et la raison.
- Suis le code voisin : même densité de commentaires, mêmes noms, mêmes idiomes.
- Une PR = un sujet.

## Signaler un problème

Ouvre une issue avec le modèle adapté. Pour une faille de sécurité, n'ouvre pas d'issue publique :
suis [SECURITY.md](SECURITY.md).

En participant, tu acceptes le [code de conduite](CODE_OF_CONDUCT.md).
