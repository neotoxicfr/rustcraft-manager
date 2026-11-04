<p align="center">
  <img src="web/public/icon.svg" width="88" height="88" alt="">
</p>

<h1 align="center">Rustcraft Manager</h1>

<p align="center">
  <strong>Le gestionnaire web de serveurs Minecraft, sûr par défaut et léger, écrit en Rust.</strong><br>
  Un seul exécutable : l'API, la console en direct et l'interface (Leptos, WebAssembly) embarquée.
</p>

<p align="center">
  <a href="https://github.com/neotoxicfr/rustcraft-manager/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/neotoxicfr/rustcraft-manager/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/neotoxicfr/rustcraft-manager/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/neotoxicfr/rustcraft-manager?sort=semver&label=release"></a>
  <a href="https://github.com/neotoxicfr/rustcraft-manager/pkgs/container/rustcraft-manager"><img alt="Image ghcr.io" src="https://img.shields.io/badge/ghcr.io-rustcraft--manager-2496ED?logo=docker&logoColor=white"></a>
  <a href="#licence"><img alt="Licence MIT ou Apache-2.0" src="https://img.shields.io/badge/licence-MIT%20%7C%20Apache--2.0-blue"></a>
</p>

---

Rustcraft Manager installe, lance et surveille vos serveurs Minecraft depuis le navigateur, sur
ordinateur comme sur téléphone. Il télécharge lui-même le logiciel serveur et le bon Java depuis
leurs sources officielles, sommes de contrôle vérifiées, et ne demande ni base externe, ni shell,
ni runtime : un binaire (ou une image Docker distroless) et un dossier de données.

## Fonctionnalités

**Serveurs**
- Création guidée de serveurs officiels (vanilla), Paper, Purpur, Folia, Fabric et Quilt.
- Java Temurin choisi selon la version du jeu et téléchargé une fois ; un Java déjà installé reste
  sélectionnable.
- Marche, arrêt propre, redémarrage, détection des plantages et redémarrage automatique borné ;
  les serveurs qui tournaient repartent au redémarrage du gestionnaire.
- Bornes globales : nombre de serveurs, mémoire totale, installations simultanées.

**Console et joueurs**
- Console en direct (WebSocket) : vue lisible (connexions, chat, progrès, sauvegardes, retards
  surlignés) et vue brute, constructeur de commandes avec suggestions en français et en anglais,
  favoris.
- Joueurs connectés, processeur, mémoire et ticks par seconde tant que quelqu'un regarde.
- Listes d'accès en visuel ⇄ JSON : liste blanche, opérateurs, bannis, adresses bannies.

**Réglages et fichiers**
- `server.properties`, Bukkit, Spigot, Paper, Purpur et les `config/` des mods (JSON, JSON5, TOML,
  YAML, propriétés) : formulaire visuel ou texte brut, sur le même texte, sans perte (commentaires,
  ordre, clés inconnues). Vérification par le vrai analyseur avant écriture, écart avant
  enregistrement, historique chiffré et restauration.
- Gestionnaire de fichiers confiné au dossier du serveur : éditeur coloré, envoi en flux avec
  progression et glisser-déposer, téléchargement et zip en flux, corbeille.

**Adresse publique**
- Un nom public par serveur, en enregistrement direct (A/AAAA + SRV) ou derrière l'**aiguilleur**
  intégré : un seul port public partagé, routage par le nom lu dans la poignée de main du joueur.
- Enregistrements DNS tenus chez Cloudflare (jeton limité, aperçu avant application), ou donnés à
  créer à la main ; test de joignabilité.

**Sécurité**
- Mots de passe Argon2id, double authentification TOTP, codes de secours, passkeys (WebAuthn),
  ré-authentification pour les actions sensibles, réglages dangereux réservés aux
  administrateurs, journal d'audit chiffré.
- Échec fermé sur toute configuration invalide, CSP stricte, CSRF, limites de tentatives
  réservées avant le hachage. Détails : [Sécurité](#sécurité) et [SECURITY.md](SECURITY.md).

**Interface**
- Français et anglais (langue du navigateur par défaut), thème par compte (couleurs, fond ; clair,
  sombre ou automatique) aux contrastes garantis, mobile compris.
- Appli installable (PWA) : coquille hors ligne, rechargement automatique après une mise à jour.

## Démarrage rapide (Docker Compose)

Images publiées pour `linux/amd64` et `linux/arm64` sur
[`ghcr.io/neotoxicfr/rustcraft-manager`](https://github.com/neotoxicfr/rustcraft-manager/pkgs/container/rustcraft-manager)
(étiquettes `X.Y.Z`, `X.Y` et `latest`).

1. Générer la clé de chiffrement, **à part du dossier de données** (elle protège les secrets de la
   base : sauvegardez-la séparément), et préparer le dossier de données :

   ```sh
   openssl rand -base64 32 > rcm.key && chmod 600 rcm.key && sudo chown 65532:65532 rcm.key
   mkdir -p data && sudo chown 65532:65532 data
   ```

2. `compose.yaml` :

   ```yaml
   services:
     rustcraft-manager:
       image: ghcr.io/neotoxicfr/rustcraft-manager:0.1.0
       init: true                   # signaux transmis, processus Java récoltés
       stop_grace_period: 120s      # save-all puis stop de chaque serveur
       restart: unless-stopped
       ports:
         - "127.0.0.1:8580:8580"     # interface : locale, ou derrière un mandataire HTTPS
         - "25565-25569:25565-25569" # ports de JEU (TCP), un par serveur créé
       volumes:
         - ./data:/data
       secrets:
         - rcm_key
       environment:
         RCM_ENCRYPTION_KEY_FILE: /run/secrets/rcm_key
         # RCM_PUBLIC_URL: https://minecraft.example.com   # active les passkeys

   secrets:
     rcm_key:
       file: ./rcm.key
   ```

3. Lancer, puis ouvrir l'adresse affichée dans le journal :

   ```sh
   docker compose up -d
   docker compose logs rustcraft-manager   # http://127.0.0.1:8580/setup#token=…
   ```

Au premier lancement (aucun compte), le journal affiche un **jeton à usage unique** :
l'assistant crée le compte administrateur. Le jeton est dans le fragment de l'adresse (jamais
envoyé au serveur dans une URL), meurt à son premier usage ou à l'arrêt du processus ; un nouveau
est tiré à chaque démarrage tant qu'aucun compte n'existe.

> [!IMPORTANT]
> L'**EULA de Mojang** n'est jamais acceptée à votre place : l'interface montre le lien, vous
> cochez, et l'acceptation (compte, instant) est enregistrée avant l'écriture de `eula.txt`.

À savoir :

- `init: true` est nécessaire : sans lui, le gestionnaire est le processus 1 et ni les signaux de
  `docker stop` ni la récolte des processus Java terminés ne se font bien.
- Un port de jeu choisi à la création d'un serveur doit être dans la plage publiée. Le « query »
  UDP demande de publier aussi la plage en `/udp`. RCON est coupé par le gestionnaire : aucun port
  RCON à publier.
- Le dossier monté sur `/data` doit appartenir à l'uid du conteneur (65532) ; sinon le démarrage
  s'arrête en donnant la commande `chown` exacte.
- L'image : `distroless/cc-debian12:nonroot` (pas de shell, uid 65532), images de base épinglées
  par empreinte, `HEALTHCHECK` par `rustcraft-manager --healthcheck`, `RCM_COOKIE_SECURE=always`
  et `RCM_CONTAINER=true` (clé obligatoire, jamais générée dans le volume). Java ne demande que la
  glibc de l'image (la JVM tourne sans affichage) ; il est téléchargé dans `/data/java`, les mondes
  vivent dans `/data/servers`.

## Configuration

Ordre (le dernier gagne) : défauts < fichier TOML < variables d'environnement < arguments.
Fichier : `--config <fichier>`, `RCM_CONFIG`, sinon `<dossier de données>/manager.toml` s'il
existe (clé inconnue = erreur). **Échec fermé** : une valeur invalide ou hors bornes arrête le
démarrage avec un message qui nomme la variable (ou la clé) ; booléens `true`/`false` seulement.
`rustcraft-manager --help` liste les arguments.

| Clé TOML | Variable | Défaut | Bornes, rôle |
|---|---|---|---|
| `data_dir` | `RCM_DATA_DIR` (`--data-dir`) | `%LOCALAPPDATA%\rustcraft-manager` (Windows), `/data` (ailleurs, Docker) | base `manager.db`, clé `manager.key`, serveurs, réglages |
| `listen` | `RCM_LISTEN` (`--listen`) | `127.0.0.1` (`0.0.0.0` dans l'image) | adresse IP d'écoute |
| `port` | `RCM_PORT` (`--port`) | `8580` | 1 à 65 535 |
| `trusted_proxies` | `RCM_TRUSTED_PROXIES` (virgules) | vide | mandataires de confiance : IP, CIDR ou **nom d'hôte** (`traefik`) |
| `cookie_secure` | `RCM_COOKIE_SECURE` | `auto` (`always` dans l'image) | `auto` (Secure si HTTPS vu par un mandataire de confiance), `always`, `never` |
| `session_idle_minutes` | `RCM_SESSION_IDLE_MINUTES` | 60 | 1 à 43 200 ; session fermée après cette inactivité |
| `session_max_hours` | `RCM_SESSION_MAX_HOURS` | 12 | 1 à 2 160 ; durée de vie maximale d'une session |
| `login_max_failures` | `RCM_LOGIN_MAX_FAILURES` | 5 | 1 à 1 000 ; échecs par (réseau, compte) et fenêtre, 4× pour le réseau seul |
| `login_window_minutes` | `RCM_LOGIN_WINDOW_MINUTES` | 15 | 1 à 1 440 ; fenêtre des limites |
| `threads` | `RCM_THREADS` | 0 (= cœurs logiques) | 0 à 4 096, ramené à 4× les cœurs ; fils du moteur asynchrone |
| `max_connections` | `RCM_MAX_CONNECTIONS` | 512 | 16 à 65 536 ; connexions TCP simultanées, WebSocket compris |
| `max_connections_per_ip` | `RCM_MAX_CONNECTIONS_PER_IP` | 64 | 1 à 65 536 ; par adresse (mandataires de confiance exemptés) |
| `audit_retention_days` | `RCM_AUDIT_RETENTION_DAYS` | 90 | 1 à 3 650 ; lignes d'audit plus anciennes purgées chaque heure |
| `max_servers` | `RCM_MAX_SERVERS` | 32 | 1 à 1 000 ; nombre de serveurs |
| `max_memory_mb` | `RCM_MAX_MEMORY_MB` | 0 (pas de borne) | 0 à 1 048 576 ; mémoire de tous les serveurs ensemble (Mio) |
| `max_installs` | `RCM_MAX_INSTALLS` | 2 | 1 à 16 ; installations simultanées |
| `upload_max_mb` | `RCM_UPLOAD_MAX_MB` | 1 024 | 1 à 65 536 ; taille d'un envoi de fichier (Mio) |
| `public_url` | `RCM_PUBLIC_URL` | — | `https://<nom>[:port]` (http seulement pour `localhost`) : origine et domaine des passkeys ; sans elle, passkeys désactivées |
| — | `RCM_CONTAINER` | `false` (`true` dans l'image) | la clé de chiffrement doit alors être fournie |
| — | `RCM_ENCRYPTION_KEY` ou `RCM_ENCRYPTION_KEY_FILE` | — | 32 octets en base64 ou 64 chiffres hexadécimaux (voir [Secrets](#secrets)) |
| — | `RCM_LOG` | `info` | `error`, `warn`, `info`, `debug` |
| `dns_zone` | `RCM_DNS_ZONE` | — | zone des noms publics (`example.com`) : un nom hors zone est refusé |
| — | `RCM_CLOUDFLARE_TOKEN_FILE` | — | jeton d'API Cloudflare (fichier **seulement** ; `RCM_CLOUDFLARE_TOKEN` en clair est refusé) ; exige la zone et son identifiant |
| `cloudflare_zone_id` | `RCM_CLOUDFLARE_ZONE_ID` | — | identifiant de la zone (32 chiffres hexadécimaux) |
| `public_ipv4`, `public_ipv6` | `RCM_PUBLIC_IPV4`, `RCM_PUBLIC_IPV6` | détectées | IP publiques fixées (adresse publique de la bonne famille, sinon refus) |
| `public_ip_detect` | `RCM_PUBLIC_IP_DETECT` | `true` | demander les IP non fixées à `1.1.1.1/cdn-cgi/trace` (au démarrage puis toutes les 15 min) |
| `router_port` | `RCM_ROUTER_PORT` | 0 (coupé) | aiguilleur : 1 024 à 65 535, ni le port de l'interface ni celui d'un serveur |
| `router_listen` | `RCM_ROUTER_LISTEN` | `0.0.0.0` | adresse d'écoute de l'aiguilleur |
| `router_max_connections` | `RCM_ROUTER_MAX_CONNECTIONS` | 1 024 | 16 à 65 536 |
| `router_max_per_ip` | `RCM_ROUTER_MAX_PER_IP` | 8 | 1 à 1 024 ; IPv6 par /64 |

Délais fixes : en-têtes 10 s (borne aussi l'attente entre deux requêtes d'une connexion gardée),
requête d'API complète 30 s (408), WebSocket fermé après 90 s sans rien recevoir (ping toutes les
30 s), attente d'une place de hachage 5 s (503).

### Secrets

Un secret se donne par fichier (`RCM_<NOM>_FILE`, secret Docker) ou par variable (`RCM_<NOM>`) ;
les deux à la fois, un fichier illisible ou vide : refus de démarrer. La clé de chiffrement
protège les secrets TOTP, l'historique des fichiers de configuration, et l'adresse et le
`User-Agent` du journal d'audit (AES-256-GCM, liste complète dans [SECURITY.md](SECURITY.md)).
Hors conteneur, sans clé fournie, elle est créée au premier lancement dans
`<données>/manager.key` (0600) : **sauvegardez-la à part de la base**. Dans l'image, elle doit
être fournie (`openssl rand -base64 32`). Une base ouverte avec une autre clé est refusée au
démarrage.

### Derrière un mandataire inverse (Traefik, Caddy, nginx)

Le binaire ne fait pas de TLS : exposé sur Internet, il se place derrière un mandataire HTTPS
déclaré dans `trusted_proxies`. Avec Traefik dans Docker, le plus sûr est de le désigner par son
nom de conteneur :

```toml
listen = "0.0.0.0"
# Jamais tout un sous-réseau Docker (172.16.0.0/12) : n'importe quel conteneur de l'hôte pourrait
# alors dicter X-Forwarded-For.
trusted_proxies = ["traefik"]
```

Un nom ne donne que des adresses **privées** (boucle locale, RFC 1918, IPv6 locale), résolues
toutes les 5 s, et rien tant qu'il ne se résout pas. Réservez au mandataire et au gestionnaire un
réseau Docker dédié : un autre conteneur de ce réseau qui récupérerait l'adresse du mandataire
serait cru quelques secondes. À défaut de nom, l'IP exacte du mandataire. Il doit transmettre
`X-Forwarded-Proto: https` : `Origin` est comparé schéma compris. Le port 8580 ne se publie alors
plus : le mandataire le joint par le réseau Docker.

### Adresse publique des serveurs

Onglet « Adresse » de chaque serveur : un nom public (`survie.example.com`) et un mode.

- **Enregistrement direct** : A (et AAAA si l'IPv6 est connue) vers l'IP publique, plus
  `_minecraft._tcp.<nom>` en SRV si le port du serveur n'est pas 25565. Le port du serveur se
  publie (Docker, box).
- **Aiguilleur** : un seul port public partagé (`RCM_ROUTER_PORT`, 25565 conseillé) ; le
  gestionnaire lit le nom dans la poignée de main du joueur et relaie vers le serveur local. Les
  ports des serveurs ne se publient plus. Limite : les bannissements par adresse ne voient que
  l'aiguilleur.

Sans jeton Cloudflare, l'onglet donne les enregistrements exacts à créer à la main. Avec le jeton,
le gestionnaire les tient lui-même : aperçu avant d'appliquer (administrateurs), puis suivi du
changement de port, du renommage, de la suppression du serveur et de l'IP publique, et
resynchronisation au démarrage. Ses enregistrements sont en **nuage gris** (le jeu ne passe pas
par le proxy de Cloudflare) et portent le commentaire `rustcraft-manager <empreinte>` ; ce qui a
été créé ou retouché à la main n'est jamais modifié ni supprimé, seulement signalé. Un joker
proxifié (`*.example.com` orange) ne suffit pas : chaque nom de jeu a son enregistrement gris.
« Tester » résout le nom, ouvre le port et interroge le statut du jeu (la box doit accepter de
boucler sur sa propre IP publique).

Mise en place avec Cloudflare :

1. **Profil > Jetons d'API > Créer un jeton > Modifier la zone DNS** : autorisation
   `Zone / DNS / Modifier`, ressource `Inclure / Zone spécifique / example.com`, rien d'autre.
2. Le jeton dans un fichier lisible par l'uid du conteneur seulement (`chmod 600`), monté en
   secret Docker : `RCM_CLOUDFLARE_TOKEN_FILE=/run/secrets/cf_token`,
   `RCM_CLOUDFLARE_ZONE_ID=<identifiant de la zone>`, `RCM_DNS_ZONE=example.com`.
3. Aiguilleur : `RCM_ROUTER_PORT=25565`, port 25565/TCP publié par Docker et redirigé par la box
   vers l'hôte.

## Logiciels serveur

| Logiciel | Source officielle | Vérification |
|---|---|---|
| Officiel (vanilla) | manifeste Mojang (`piston-meta`, `piston-data`) | SHA-1 et taille du manifeste de version |
| Paper, Folia | API PaperMC fill v3 | SHA-256 et taille |
| Purpur | API Purpur v2 | MD5 (seule somme publiée ; l'authenticité vient du HTTPS) |
| Fabric, Quilt | serveur Mojang + profil `meta` + bibliothèques Maven | sommes du profil, sinon `.sha256` (ou `.sha1`) du dépôt |
| Java | API Adoptium (JRE Temurin), archives sur GitHub | SHA-256 et taille |

- **Téléchargements** en HTTPS seulement, vers une liste fermée d'hôtes (vérifiée à chaque
  redirection), délais (connexion 15 s, inactivité 60 s), taille bornée, écrits à côté puis
  renommés : jamais de fichier à moitié. Rien de Mojang n'est livré avec le gestionnaire.
- **Java** : `javaVersion` du manifeste Mojang (25 pour 26.x, 21 pour 1.20.5 à 1.21.x, 17 pour
  1.18 à 1.20.4, 16 → 17 car Adoptium n'a pas de JRE 16, 8 avant), installé dans
  `<données>/java/<version>`.
- **Processus** lancés sans shell, arguments un par un, environnement vidé puis liste blanche
  (jamais une variable `RCM_*`), `-Xmx` selon la mémoire réglée. Sous Windows, un objet Job
  « tuer à la fermeture » par serveur ; sous Linux hors Docker (systemd), garder
  `KillMode=control-group` (le défaut) pour que les processus Java meurent avec le gestionnaire.
- **Une opération à la fois** par serveur (installation, démarrage, arrêt, redémarrage,
  suppression), poussée en direct à l'interface. Arrêt : `stop`, 90 s d'attente, puis arrêt
  forcé. « En ligne » = le port de jeu répond ; un serveur vivant dont le port reste fermé 5 min
  est signalé. Plantage : redémarrage automatique optionnel, abandonné (alerte) après 3 plantages
  en 10 min. À l'arrêt du gestionnaire, chaque serveur reçoit `save-all` puis `stop`.
- **Mesures** : tant que quelqu'un regarde la page du serveur, processeur et mémoire toutes les
  2 s ; toutes les 10 s, `list` et `tick query` (vanilla 1.20.3+) ou `mspt`/`tps` (Paper) sur
  l'entrée standard, réponses retirées de la console. RCON reste coupé (le jeu l'ouvrirait sur
  toutes les interfaces).
- **Console** : 2 000 lignes en mémoire, 4 Mio sur disque (`<serveur>/.rcm/console.jsonl`),
  relues au démarrage.
- **Dossiers** : `<données>/servers/<id>` (identifiant entier validé), corbeille
  `<données>/trash/<id>-<instant>` gardée 30 jours.

## Sécurité

Rustcraft Manager pilote des processus : il est traité comme un outil d'administration. Modèle
de menace, constats corrigés et limites assumées : [SECURITY.md](SECURITY.md). Pour signaler une
faille, utilisez le [signalement privé de GitHub](https://github.com/neotoxicfr/rustcraft-manager/security/advisories/new),
jamais une issue publique.

- **Exposition** : écoute sur `127.0.0.1` par défaut ; `X-Forwarded-For`, `X-Forwarded-Proto` et
  `X-Forwarded-Host` ne sont lus que d'un mandataire de confiance.
- **Mots de passe** Argon2id (19 Mio, 2 passes), 10 à 256 caractères ; hachages simultanés bornés ;
  un compte inconnu coûte le même temps.
- **Limites réservées avant Argon2** (pardonnées au succès) par (réseau, compte) et par réseau
  (IPv6 par /64, /56 et /48), échéancier par compte toutes adresses confondues, pas de
  verrouillage par le mot de passe.
- **Double authentification** TOTP (RFC 6238) sans rejeu, 10 codes de secours, plafond de codes
  faux par compte ; **passkeys** (vérification de l'utilisateur et clé résidente exigées, défi à
  usage unique gardé côté serveur, compteur qui recule refusé).
- **Ré-authentification** pour changer le mot de passe ou le TOTP (les autres sessions sont alors
  fermées) et pour ajouter ou supprimer une passkey.
- **Sessions** : jeton de 256 bits en cookie `HttpOnly; SameSite=Strict` (`__Host-` et `Secure`
  en HTTPS), empreinte seule en base ; **CSRF** par en-tête et `Origin` comparé exactement,
  WebSocket compris.
- **En-têtes** : CSP stricte (scripts par empreinte, `wasm-unsafe-eval`), `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `nosniff`, COOP et CORP, `Permissions-Policy`, HSTS en HTTPS,
  `no-store` sur l'API.
- **Données** : dossier 0700, base et clé 0600, secrets chiffrés par champ (AES-256-GCM), copie
  `VACUUM INTO` avant toute migration, journal d'audit sans secret.

> [!WARNING]
> **Un serveur Minecraft n'est pas isolé du gestionnaire** : ses processus Java tournent avec le
> même utilisateur système. Un plugin ou un mod malveillant peut compromettre le gestionnaire.
> N'installez que des plugins et des mods de confiance.

## Architecture

```text
navigateur ──HTTPS──▶ mandataire ──HTTP, WebSocket──▶ rustcraft-manager ──stdin/stdout──▶ java (serveurs)
                                                      axum + tokio, SQLite,
                                                      interface wasm embarquée
joueurs ──TCP──▶ serveurs, ou aiguilleur intégré (un port partagé) ──▶ serveurs
```

| Dossier | Paquet | Rôle |
|---|---|---|
| `.` (racine) | `rc-manager` (binaire `rustcraft-manager`) | axum + tokio, SQLite, API, WebSocket, pilotage des serveurs, interface embarquée |
| `shared` | `rc-manager-shared` | types de l'API et calcul du thème, communs au binaire et à l'interface |
| `web` | `rc-manager-web` | interface Leptos (rendu client, WebAssembly), construite par `trunk`, hors du workspace natif |

Le binaire embarque `web/dist` à la compilation (fichiers compressés une fois pour toutes, ETag,
empreintes CSP de l'amorce). Sans `dist`, il compile quand même et sert une page qui explique
comment construire l'interface (l'API reste utilisable).

## Développement

Outils (une fois) : la chaîne Rust de [`rust-toolchain.toml`](rust-toolchain.toml),
`rustup target add wasm32-unknown-unknown`, `cargo install --locked trunk --version 0.21.14`,
`cargo install --locked wasm-bindgen-cli --version 0.2.129`, `cargo install --locked cargo-deny
cargo-audit`, et `wasm-opt` de [binaryen version_133](https://github.com/WebAssembly/binaryen/releases/tag/version_133)
dans le `PATH`.

```sh
(cd web && trunk build --release --offline)   # → web/dist
cargo build --release -p rc-manager            # embarque web/dist dans le binaire
./target/release/rustcraft-manager             # http://127.0.0.1:8580
```

L'ordre compte : le binaire embarque `web/dist` à la compilation. `RC_MANAGER_WEB_DIST` désigne un
autre dossier. `trunk serve` ne relaie pas l'API : le plus simple est de reconstruire
(`trunk build`, environ 1 s en incrémental) puis de relancer le binaire.

**Vérification complète** : [`scripts/check.sh`](scripts/check.sh) enchaîne format, clippy
`-D warnings` (natif et wasm), construction de l'interface, tests, `cargo deny` et `cargo audit`.
C'est la même commande dans le hook `pre-push` (`git config core.hooksPath .githooks`) et dans la
[CI](.github/workflows/ci.yml).

**Tests** : unitaires (TOTP contre les vecteurs RFC, chiffrement, limiteurs, configuration,
migrations), API sur le routeur en mémoire (`tests/api.rs`), bout en bout sur un vrai port
(`tests/e2e.rs` : délais, plafond de connexions, WebSocket), pilotage sans réseau avec un faux
`java` (`tests/servers.rs`), aller-retour sans perte sur de vrais fichiers de configuration
(`tests/configs.rs`), traductions (`tests/i18n.rs`) et garde-fous de l'appli installée
(`tests/pwa.rs`). Bancs et chiffres : [`docs/perf.md`](docs/perf.md).

**Image** :

```sh
docker buildx build -t rustcraft-manager:dev --platform linux/amd64 \
  --build-arg RCM_GIT_COMMIT=$(git rev-parse HEAD) --load .
```

Le Dockerfile compile en croisé (plateforme de l'hôte vers `amd64` ou `arm64`) : pas d'émulation
QEMU, et l'interface wasm n'est construite qu'une fois pour les deux architectures.

**Releases** : un tag `vX.Y.Z` (égal à la version de `Cargo.toml`) publie l'image
`ghcr.io/neotoxicfr/rustcraft-manager:X.Y.Z` (multi-architecture) et crée la release GitHub.

## Contribuer

Les contributions sont bienvenues : lisez [CONTRIBUTING.md](CONTRIBUTING.md) (règles, style,
vérification) et le [code de conduite](CODE_OF_CONDUCT.md).

## Licence

Au choix, sous [licence MIT](LICENSE-MIT) ou [licence Apache 2.0](LICENSE-APACHE).
Polices Inter Tight et JetBrains Mono sous licence SIL OFL 1.1 (`web/public/fonts`).

Minecraft est une marque de Mojang AB. Rustcraft Manager n'est ni affilié à Mojang ni approuvé
par Mojang ou Microsoft.
