## Rustcraft Manager

Phase 1 (socle), 20/10/2026. Binaire en vrai profil release (`RUSTCRAFT_FULL_RELEASE=1`),
machine calme (aucune compilation ni client pendant les mesures), banc
`examples/charge.rs` (50 connexions HTTP/1.1 gardées ouvertes, 10 s, 2 passes),
mémoire et CPU lus sur le processus (`Get-Process` : ensemble de travail, mémoire privée, temps
processeur). Réglage par défaut : fils = cœurs logiques (32), 4 hachages Argon2 simultanés.

| Mesure | Valeur |
|---|---|
| Binaire `rustcraft-manager.exe` (interface embarquée) | 4,7 Mio |
| Interface : wasm / js / css (brut → gzip embarqué) | 344 → 126 Kio / 39 → 7,2 Kio / 11,3 → 3,9 Kio ; premier chargement ≈ 140 Kio transférés |
| Démarrage (lancement → écoute, mesuré dans le processus) | 15-17 ms |
| Repos (10 s sans requête, compte créé) | 0 ms de CPU ; ensemble de travail 8,8 Mo, privé 3,1 Mo, 37 fils |
| 50 connexions, session vérifiée (`GET /api/auth/me`) | 23 800-23 950 req/s, p50 2,1 ms, p99 5,7 ms ; 3 cœurs ; pic 27,8 Mo |
| 50 connexions, page (`GET /`, gzip) | 144 000-151 000 req/s, p50 0,3 ms, p99 0,75 ms ; 5,1 cœurs ; pic 27,8 Mo |
| 50 connexions qui se connectent en boucle (Argon2id) | 262-273 connexions/s, p50 186-194 ms, p99 200-214 ms ; 4,2 cœurs ; pic 94 Mo |
| Après la charge | ensemble de travail 17 Mo, privé 14-15 Mo |

La page servie a grossi entre deux séries (index 1,5 → 2,6 Kio : métas de l'appli installée
iOS, bande fixe du haut) : 154-155 k req/s avant, 144-151 k après, à contenu différent. La CSP
est calculée une fois (`LazyLock`) au lieu d'un `format!` par réponse.

Fils du moteur (une passe chacun, mêmes scènes) :

| Fils | Repos (WS / privé) | Session req/s (p99) | Page req/s | Connexions/s (pic mémoire) avec hachages = fils |
|---|---|---|---|---|
| 1 | 8,0 / 1,4 Mo | 26 100 (5,5 ms) | 56 000 | 82 (30 Mo) |
| 2 | 8,0 / 1,5 Mo | 24 300 (5,3 ms) | 100 100 | 146 (52 Mo) |
| 4 | 8,1 / 1,6 Mo | 23 700 (5,7 ms) | 149 600 | 263 (90 Mo) |
| 8 | 8,2 / 1,7 Mo | 23 700 (5,7 ms) | 160 500 | 422 (169 Mo) |
| 32 | 8,8 / 3,1 Mo | 23 600 (5,7 ms) | 154 500 | 519 (625 Mo) |

Décisions :

- **Hachages simultanés = min(cœurs, 4)** (adoptée) : 32 hachages Argon2 simultanés = 625 Mo de
  pic pour 519 connexions/s ; 4 = 90-94 Mo pour 263/s, bien au-delà du besoin (quelques
  connexions par minute). Le nombre de fils du moteur ne pèse presque pas au repos (+0,8 Mo de
  1 à 32 fils) et sert les pages statiques (×2,8 de 1 à 8 fils) : il reste au nombre de cœurs.
- **`RCM_THREADS` borné à 4 × les cœurs** (adoptée) : une valeur aberrante a lancé 124 832 fils
  (2,8 Go au repos, 7,6 s de démarrage) pendant les mesures.
- **Interface compressée à la construction** (adoptée) : gzip niveau max calculé une fois par
  `build.rs` (0 CPU de compression à l'exécution), 388 → 135 Kio ; ETag par représentation, cache
  d'un an pour les fichiers à empreinte.
- **Une connexion SQLite derrière un verrou** (gardée) : la vérification de session plafonne à
  ≈ 24 000 req/s quel que soit le nombre de fils (le verrou sérialise) ; plusieurs ordres de
  grandeur au-dessus du besoin, un réservoir de connexions ou un cache de sessions en mémoire
  sont notés à remesurer si l'API sert un jour un flux par requête (console en direct : WebSocket).
- À mesurer : `wasm-opt` (binaryen, non installé : téléchargement non autorisé dans cette
  mission) sur le wasm de 344 Kio ; allocateur mimalloc pour la mémoire privée sous charge ;
  50 WebSocket ouverts au repos.

### Série de corrections de sécurité (20/10/2026, branche `fix/securite-phase1`)

Banc A/B, vrai release, machine calme, 2 passes alternées : référence `main` 919800d et branche,
même interface embarquée (`RC_MANAGER_WEB_DIST`). La connexion se mesure avec 4 connexions (plafond
des requêtes d'authentification en cours par adresse de la branche ; mêmes conditions pour les
deux). Script : `MANAGER-FIX-bench.ps1` (bloc-notes de la mission).

| Mesure | main | branche |
|---|---|---|
| Binaire | 4,76 Mio | 4,98 Mio (hyper en direct, chiffrement, audit) |
| Démarrage (interne) | 14-16 ms | 16-18 ms (clé dérivée, témoin de clé, sonde d'écriture) |
| Repos 10 s | 0 ms CPU, privé 3,0-3,1 Mo, 37 fils | 0 ms CPU, privé 3,1-3,3 Mo, 37 fils |
| Session `me`, 50 conn. | 23 590-23 670 req/s, p99 5,6-5,7 ms | 23 110-23 260 req/s (−1,8 %), p99 5,6 ms |
| Page `/`, 50 conn. | 153 150-154 090 req/s | 143 480-151 840 req/s (−1,3 à −4 %) |
| Connexion Argon2, 4 conn. | 239-252/s, p99 19,1-19,4 ms | 244-247/s, p99 19,4-20,0 ms |
| Pic mémoire (connexions) | 92,8-93,2 Mo | 94,2-94,4 Mo |

Pistes et décisions :

- **`sleep(0)` évité** (adoptée) : la première version attendait le ralentissement du compte même
  nul ; sous Windows un `tokio::time::sleep(0)` attend le tic suivant de l'horloge : connexion
  206/s, p99 31 ms. Sans minuterie quand l'attente est nulle : 244-247/s, p99 19-20 ms (= main).
- **Délai par requête sur l'API seulement** (adoptée) : les fichiers de l'interface ne lisent
  aucun corps ; travail évité, écart sur la page dans le bruit du banc.
- **Minuterie des en-têtes de hyper** (gardée, exigée par la revue I4) : isolée en la retirant
  (variante de mesure seulement), la page passe de −4 % à −1,3 % de main. Ce coût (≈ 3 % à
  150 000 pages/s) reste très au-delà du besoin ; rien de moins cher ne borne une tête lente.
- **Journal d'audit sans minuterie au repos** (adoptée) : l'échéance n'existe que si un événement
  attend (avant : réveil chaque seconde).
- Session : −1,8 % (extracteur de session avec `ClientInfo`, délai par requête de l'API) ; la base
  derrière un verrou reste le plafond (≈ 23 000 req/s).
- Non applicables ici : GPU, VRAM, multi-cœurs (le travail lourd, Argon2, est déjà borné à 4
  hachages parallèles), réseau (mêmes octets, en-têtes CORP et Permissions-Policy en plus :
  ≈ 270 octets par réponse).

### Ajouts : audit chiffré, traductions, passkeys (20/10/2026)

Une passe A/B de plus après ces ajouts (même banc, passkeys non configurées) :

| Mesure | main | branche |
|---|---|---|
| Binaire | 4,76 Mio | 7,19 Mio (+2,2 Mio : webauthn-rs, x509-parser, rsa, p384 ; 147 → 306 crates) |
| Démarrage | 16 ms | 18 ms |
| Repos | privé 3,1 Mo | privé 3,2 Mo |
| Session / page / connexion | 23 660 req/s, 149 050 req/s, 252/s | 23 030 req/s, 148 110 req/s, 246/s (p99 19,3 ms) |

- Audit chiffré : un AES-GCM par champ (adresse, `User-Agent`), dans la tâche d'écriture en lots,
  hors du chemin des requêtes ; `User-Agent` lu pour l'API seulement (aucune copie pour les
  fichiers de l'interface).
- Passkeys : 0.6.1-dev plutôt que 0.5.5 (OpenSSL) : rien de natif à installer ; le poids sur
  disque (+2,2 Mio) est accepté, la mémoire au repos ne bouge pas (+0,1 Mo). Défis en mémoire
  (pas d'écriture en base par défi), table bornée à 1 024. La connexion par passkey (une
  vérification de signature ECDSA, pas d'Argon2) n'a pas de banc : il faudrait un authentificateur
  dans `examples/charge.rs`, noté pour plus tard.
- Interface wasm : 344 → 410 Kio bruts (+66 Kio : section Passkeys, formulaires de
  ré-authentification, suivi de `/version`) ; passkeys par `Reflect` (aucune fonction web-sys de
  plus). `wasm-opt` reste à mesurer (non installé).

### Phase 2 : serveurs pilotés (20/10/2026, branche `feat/phase2`)

Machine de développement (Windows 11, 32 fils), aucune compilation pendant les mesures, un seul
serveur Minecraft à la fois (vanilla 26.3, 2 Gio, `server-ip=127.0.0.1`). Gestionnaire en vrai
release (`RUSTCRAFT_FULL_RELEASE=1`) ; mémoire et CPU lus par `Get-Process` (script
`MANAGER2-mesure.py` du bloc-notes de la mission : 10 s de repos, puis 20 s par scène).

| Mesure | Phase 1 (`main`) | Phase 2 |
|---|---|---|
| Binaire | 7,19 Mio | 12,4 Mio (+5,2 : reqwest/rustls, zip, tar, sysinfo, objet Job, interface plus grosse embarquée deux fois, brute et gzip) |
| Démarrage (interne) | 18 ms | 19-28 ms (8 serveurs chargés, historiques de console relus) |
| Repos, 8 serveurs configurés, aucun en marche | 0 ms CPU, privé 3,2 Mo | 0 ms CPU / 10 s, privé 4,6-5,1 Mo, travail 14,2 Mo |
| 1 serveur en marche, personne ne regarde | — | 16-31 ms CPU / 20 s (≤ 0,16 % d'un cœur), privé 5,4-5,6 Mo |
| 1 serveur en marche, suivi par un WebSocket (mesures toutes les 2 s, RCON toutes les 4 s) | — | 31-62 ms CPU / 20 s (≤ 0,31 % d'un cœur), privé 5,5-5,8 Mo |
| Ingestion de la console (banc `banc_flux_console`, 200 000 lignes, analyse + historique mémoire et disque + un abonné) | — | 250 000 à 700 000 lignes/s (profil essai ; un serveur réel en écrit quelques centaines par seconde au plus) |
| Interface wasm / css / js (brut → gzip) | 410 → 126 Kio / 11 → 4 / 39 → 7 | 1 161 → 403 Kio / 34 → 7 / 45 → 8 ; polices 76 Kio (woff2) |

Décisions et pistes :

- **Mesures seulement quand quelqu'un regarde** (adoptée, règle des bonnes pratiques) : sans
  abonné, aucune tâche d'échantillonnage ni connexion RCON ; la tâche s'arrête au départ du
  dernier abonné. Le surcoût d'un abonné (≈ 0,15 % d'un cœur) vient de `sysinfo` (un processus
  rafraîchi) et de trois commandes RCON.
- **Aucune minuterie par serveur au repos** (adoptée) : la supervision vidait l'historique sur le
  disque chaque seconde ; elle le vide quand plus aucune ligne n'attend. Gain sous le bruit de la
  mesure (16 à 31 ms / 20 s dans les deux cas), mais 1 réveil par seconde et par serveur évité.
  La sonde du port n'existe que pendant l'état « démarrage ».
- **Console : un seul chemin simple** (gardé) : ligne lue bornée (64 Kio), analysée sans
  expression régulière, sérialisée en JSON vers un tampon disque, diffusée par `Arc`. À plus de
  250 000 lignes/s, rien à gagner pour un serveur Minecraft (3 ordres de grandeur de marge) ; noté
  pour remesure si un serveur moddé très bavard pose problème.
- **`wasm-opt` mesuré** (écarté) : binaryen 133 (téléchargé dans `target/` pour la mesure
  seulement), `-Oz` : 1 161 → 1 057 Kio bruts mais 403 → 399 Kio en gzip (−1 %, ce qui est
  transféré) ; `-Os` pareil. Pas assez pour ajouter un outil à la construction (poste, image).
- **Interface wasm ×2,8** (à enquêter) : quatre écrans de plus (serveur, assistant, console avec
  constructeur, thème) ; Leptos monomorphise chaque `view!`. Chargée une fois puis gardée en cache
  (fichier à empreinte, cache d'un an, service worker) ; 403 Kio compressés au premier
  chargement. Piste suivante : `twiggy` pour trouver les plus gros blocs, `into_any()` aux
  frontières des gros composants.
- Non applicables : GPU, VRAM, chunks (aucun rendu de jeu ici) ; multi-cœurs : le travail est
  déjà réparti par tâches tokio (une supervision par serveur, une lecture par flux).

### Réglages : fichiers de configuration (20/10/2026, branche `feat/reglages`)

Banc `examples/banc_configs.rs` (profil essai, 200 tours par fichier, fichiers réels de
`tests/fixtures/configs`) : analyse seule (`check` sans édition) et une édition ciblée de la
dernière valeur du fichier (pire cas : relecture complète comprise).

| Fichier | Taille | Analyse | Édition avant → après réemploi de l'arbre relu |
|---|---|---|---|
| `server.properties` 26.3 | 1,8 Ko | 16 µs | 64 → 47 µs |
| `paper-world-defaults.yml` | 8,7 Ko | 215 µs | 929 → 711 µs |
| `servercore/config.yml` (Fabric) | 12,7 Ko | 200-208 µs | 791 → 606 µs |
| `c2me.toml` | 11,6 Ko | 123-130 µs | 354 → 288 µs |
| `purpur.yml` | 48 Ko | 1,43-1,46 ms | 6,14 → 4,76 ms |

| Interface | Avant (phase 2) | Après |
|---|---|---|
| wasm brut → gzip | 1 161 → 403 Kio | 1 482 → 517 Kio |
| css gzip | 7 Kio | 9,9 Kio |

Décisions et pistes :

- **Éditions par le serveur, pas dans l'interface** (adoptée) : les analyseurs (saphyr, toml_edit,
  JSON/JSON5, propriétés) restent dans le binaire natif ; l'interface n'envoie que le texte et
  l'édition. Les embarquer en wasm aurait évité un aller-retour (quelques ms en local) mais
  ajouté les analyseurs au téléchargement de chaque navigateur, et la vérification par le vrai
  analyseur doit de toute façon se faire côté serveur.
- **Arbre relu réemployé** (adoptée, −22 à −27 % par édition) : l'arbre lu pour vérifier une
  édition sert de réponse au lieu d'une quatrième analyse.
- **Saisie en texte vérifiée après 350 ms de pause** (adoptée) : une vérification par arrêt de
  frappe, pas par touche ; les réponses dépassées sont ignorées (numéro de vérification).
- **Écart et fins de ligne dans l'interface** (adoptée) : préfixe et suffixe communs retirés
  avant la plus longue sous-suite commune ; une frappe dans `purpur.yml` ne compare que la zone
  changée.
- À mesurer : analyse YAML (≈ 30 Mo/s sur `purpur.yml`, dont la recherche du commentaire de
  chaque clé) ; interface +114 Kio gzip (formulaire et schéma de `server.properties`, arbre,
  éditeur coloré, historique) : `twiggy` et `into_any()` aux frontières, comme noté plus haut.
- Non applicables : GPU, VRAM, chunks ; multi-cœurs : une requête = un fichier de 1 Mio au plus,
  analysé en quelques millisecondes dans un fil bloquant (`spawn_blocking`).

## Interface plus légère (20/10/2026, branche `feat/listes-fichiers`)

Mesure : `wasm-bindgen` puis `gzip -9` sur le wasm de release complet (LTO, une unité, `opt-level
= "z"`, `panic = "abort"`), script `m4_wasmsize.sh` (même source, réglages seuls changés), avant
l'ajout des onglets Joueurs et Fichiers. Analyse par `twiggy` sur un wasm gardant ses noms :
22 % du code dans les fermetures des composants, 22 % dans `Render::build` des vues (types de
vues imbriqués, un par écran), 11 % dans la désérialisation serde (`ConsoleEvent` 33 Ko,
`ErrorCode` 17 Ko, `WsServerMessage` 16 Ko), 8 % de données (textes, schéma).

| Piste (seule puis combinée) | wasm brut | gzip -9 | Écart gzip |
|---|---|---|---|
| Référence (`opt-level = "z"`) | 1 543 621 | 538 005 | — |
| `wasm-opt -Oz` seul | 1 405 813 | 534 052 | −0,7 % |
| `--cfg erase_components` (Leptos 0.8) | 1 238 227 | 415 345 | **−22,8 %** |
| erase + `opt-level = "s"` | 1 547 934 | 481 051 | −10,6 % |
| erase + `"s"` + `wasm-opt -Oz` | 1 370 662 | 474 505 | −11,8 % |
| **erase + `"z"` + `wasm-opt -Oz`** (gardée) | **1 125 327** | **412 554** | **−23,3 %** |

Décisions :

- **Composants effacés** (gardée) : `web/.cargo/config.toml` pose `--cfg erase_components` pour la
  cible wasm (trunk et clippy de `scripts/check.sh` la lisent ; depuis la racine :
  `--config web/.cargo/config.toml`). Les vues changent de type aux frontières des composants,
  le rendu reste le même (vérifié au navigateur, bureau et 390 px).
- **`wasm-opt -Oz`** (gardée, inversion de la décision du 20/10 : aucun gain jeté) : −0,7 % en
  gzip mais −9 % de wasm brut, que le navigateur compile à chaque premier chargement.
  binaryen 133 installé (journal des installations), fonctions de la cible wasm32 de Rust
  activées explicitement dans `index.html`.
- Après l'ajout des onglets Joueurs et Fichiers (même réglage gardé) : 1 320 619 octets bruts,
  484 249 en gzip -9 (+71 Ko pour deux écrans), toujours sous les 538 005 du départ et sous les
  517 Kio de `feat/reglages`.
- `opt-level = "s"` (écartée) : +16 % en gzip contre `"z"`, avec ou sans `wasm-opt`.
- À mesurer : désérialisation sans mise en mémoire tampon (`ConsoleEvent` à étiquette interne :
  le format est aussi celui de `console.jsonl` sur le disque, changement à migrer) ; table de
  noms à la main pour `ErrorCode` (≈ 15 Ko bruts) ; compression brotli des fichiers embarqués
  (réseau, pas la taille du wasm).
- Axes non concernés : serveur, GPU, VRAM, chunks ; seul le téléchargement et la compilation
  du wasm par le navigateur changent (CPU au premier chargement : moins de code à compiler).
