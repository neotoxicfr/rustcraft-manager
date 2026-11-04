# Sécurité

## Signaler une faille

N'ouvre pas d'issue publique. Utilise le signalement privé de GitHub : onglet **Security**, puis
**Report a vulnerability**. Décris la faille, son impact et comment la reproduire. Tu recevras une
réponse dès que possible, et le correctif sera publié avec ton accord sur la mention de ton nom.

Seule la dernière version de la branche `main` est suivie.

## Modèle de sécurité

Rustcraft Manager pilote des serveurs Minecraft : qui le contrôle peut lancer des processus, lire
et écrire leurs fichiers. Il est donc traité comme un outil d'administration.

- **Exposition** : écoute sur `127.0.0.1` par défaut. Exposé sur Internet, il doit l'être derrière
  un mandataire inverse en HTTPS (Traefik, Caddy, nginx) déclaré dans `trusted_proxies`, idéalement
  avec une authentification en amont (Authelia). L'aiguilleur (`RCM_ROUTER_PORT`, coupé par
  défaut) est le seul autre écouteur : public par nature, il ne parle que la poignée de main du
  jeu (voir plus bas).
- **Comptes** : mots de passe Argon2id, double authentification TOTP sans rejeu, codes de secours
  à usage unique, sessions opaques dont seule l'empreinte est en base, cookies `HttpOnly`,
  `Secure`, `SameSite=Strict`, protection CSRF, limites de tentatives, journal d'audit.
- **Secrets** : fournis par fichier (`RCM_<NOM>_FILE`, secrets Docker) ; les secrets stockés en base
  sont chiffrés ; aucun secret n'est écrit dans les journaux.
- **Serveurs pilotés** : processus lancés sans shell, arguments passés directement, environnement
  vidé ; téléchargements vérifiés par somme de contrôle ; EULA de Mojang jamais acceptée à la
  place de l'utilisateur ; RCON coupé. (Gestionnaire de fichiers confiné au dossier de chaque
  serveur : phase 3.)
- **Limite assumée : un serveur Minecraft n'est PAS isolé du gestionnaire.** Ses processus Java
  tournent avec le même utilisateur système : un plugin ou un mod malveillant peut lire et écrire
  le dossier de données (base, `manager.key` hors conteneur, autres serveurs), donc compromettre
  le gestionnaire. N'installer que des plugins et mods de confiance. Parade prévue : un
  utilisateur système ou un conteneur par serveur.

Une faille dans l'un de ces domaines est traitée en priorité.

### Menaces retenues (phase 1)

| Attaquant | Peut | Parade |
|---|---|---|
| Anonyme sur Internet | deviner des mots de passe en masse, en parallèle, depuis beaucoup d'adresses | réservation avant Argon2, limites par réseau (/64, /56, /48) et par (réseau, compte), requêtes en cours bornées, échéancier par compte (les essais passent un par un, espacés de 250 ms à 8 s, refus au-delà de 30 s d'attente : le débit est réellement borné), plafond DUR de 10 codes faux par compte et fenêtre pour le second facteur et la ré-authentification, sémaphore Argon2 à délai dont la place est gardée jusqu'à la fin du calcul, Authelia en amont |
| Anonyme | épuiser le serveur (slowloris, corps lents, connexions, WebSocket) | délais d'en-têtes, de requête et d'inactivité, plafond de connexions, trames de 64 Kio, 4 WebSocket par session |
| Voleur d'une session (onglet ouvert, cookie) | changer le mot de passe ou le TOTP, ajouter une passkey pour garder la main | ré-authentification (mot de passe + code), autres sessions fermées au changement de TOTP |
| Anonyme | remplir les tables (défis de passkey, connexions, sessions) | tables séparées, refus plutôt qu'éviction, limites par réseau, connexions par adresse (64) et sessions par compte (10) bornées |
| Voleur d'une sauvegarde de la base | lire les secrets TOTP | AES-256-GCM par champ, clé hors de la base (secret Docker ou `manager.key` séparé) |
| Autre conteneur de l'hôte | se faire passer pour Traefik (`X-Forwarded-For`) | mandataire désigné par nom ou IP exacte, refus par défaut |
| Sous-domaine du même site | poser un cookie de session | cookie `__Host-` en HTTPS |
| Site tiers (hameçonnage) | relayer un défi de passkey | origine et domaine fixés par `RCM_PUBLIC_URL`, vérifiés par WebAuthn |
| Clé matérielle clonée | rejouer une passkey | compteur qui recule refusé, défi à usage unique |

### Menaces retenues (phase 2 : serveurs pilotés)

| Attaquant | Peut | Parade |
|---|---|---|
| Réseau ou source compromise entre le gestionnaire et un éditeur | servir un jar ou un JRE piégé | HTTPS seulement, hôtes d'une liste fermée vérifiée à chaque redirection, somme de contrôle de la source (SHA-1/SHA-256 Mojang, PaperMC, Adoptium, Maven ; MD5 pour Purpur, seule publiée), taille annoncée vérifiée, fichier écrit à côté puis renommé |
| Source qui répond démesurément ou lentement | remplir le disque, bloquer une installation | taille bornée (512 Mio, 16 Mio pour un JSON), délais de connexion, d'inactivité et total |
| Archive hostile (JRE) | écrire hors du dossier (`../`) | entrées confinées (`enclosed_name`, `unpack_in`), refus et nettoyage |
| Utilisateur connecté (session volée) | supprimer un serveur | nom recopié vérifié d'abord, puis ré-authentification (mot de passe + code) ; dossier en corbeille, pas effacé |
| Utilisateur connecté | injecter une commande ou une clé (`\n`) | commande d'une ligne, sans caractère de contrôle, 4 096 octets au plus ; valeurs de `server.properties` sans contrôle |
| Saisie dans une adresse | sortir du dossier des serveurs (`../`, `%2e%2e`, `CON`) | identifiant entier validé (404 sinon), versions et coordonnées Maven validées avant tout chemin |
| Processus Java (mod, plugin malveillant) | lire la base, la clé (`manager.key` hors conteneur), les autres serveurs : **compromettre le gestionnaire** | NON couvert aujourd'hui (même utilisateur système). Réduit seulement : environnement vidé (aucun secret transmis), clé retirée de l'environnement du gestionnaire, clé en secret Docker dans l'image. Parade prévue : utilisateur ou conteneur par serveur |
| Plantage du gestionnaire | laisser des serveurs orphelins | objet Job « tuer à la fermeture » par serveur sous Windows ; `kill_on_drop` ; dans Docker, conteneur et `init: true` |
| Quiconque | accepter l'EULA de Mojang à la place de l'utilisateur | case cochée par l'utilisateur, acceptation enregistrée (compte, instant) puis seulement `eula.txt` ; un test refuse tout autre endroit du code qui l'écrirait |
| Réseau local | piloter un serveur par RCON | RCON coupé (`enable-rcon=false`, mot de passe vidé) : le jeu l'ouvrirait sur `server-ip`, toutes les interfaces par défaut, sans réglage séparé (lu dans `RconThread` de la 26.3) ; mesures par l'entrée standard |

### Menaces retenues (phase 3 : fichiers de configuration)

| Attaquant | Peut | Parade |
|---|---|---|
| Utilisateur connecté (session volée) ou chemin forgé | lire ou écrire hors des fichiers de configuration (`../`, `%2e%2e`, `CON`, chemin absolu, lien ou jonction vers le monde ou hors du dossier) | liste blanche par logiciel (`server.properties`, Bukkit, Spigot, Paper, Purpur, `config/` des mods aux extensions connues), chaque segment contrôlé (ni `..`, ni `%`, ni `:`, ni nom réservé, ni point ou espace final), aucun lien sur le trajet (`symlink_metadata` segment par segment), forme canonique sous le dossier canonique du serveur ; 404 sinon, testé par les routes |
| Utilisateur connecté | rouvrir RCON, changer le port tenu par le gestionnaire | `server-port`, `enable-rcon`, `rcon.*`, `query.port` comparés au disque : refus à la vérification et à l'écriture (texte comme visuel), et réécrits au lancement |
| Utilisateur connecté | casser un serveur par un fichier illisible | analyseur du format avant toute écriture (propriétés Java, YAML 1.2, JSON, JSON5, TOML) ; historique chiffré de l'état réel du disque avant chaque écriture, restaurable |
| Écriture concurrente (serveur qui démarre ou s'arrête, autre onglet, éditeur externe) | écraser un fichier modifié entre-temps | empreinte SHA-256 du fichier ouvert comparée au disque (409), refus pendant un démarrage, un arrêt ou une installation, un enregistrement à la fois ; écriture atomique (temporaire, fsync, renommage, fsync du dossier) |
| Édition visuelle défectueuse | perdre un commentaire, une clé inconnue ou changer une autre valeur | éditions ciblées (seule la valeur touchée est réécrite) puis relecture : l'arbre obtenu doit être l'arbre d'avant avec ce seul changement, sinon refus ; aller-retour octet pour octet sur des fichiers réels de chaque logiciel |
| Corps démesuré | saturer la mémoire | fichier de 1 Mio au plus, corps de 3 Mio sur les deux routes qui portent un fichier (64 Kio ailleurs), 64 éditions par requête ; arbre du mode visuel borné (64 niveaux, 20 000 entrées, 8 Mio portés : chaque entrée recopie son chemin), deux analyses à la fois (503 au-delà de 10 s d'attente) |
| Utilisateur connecté | ouvrir le pilotage du serveur au réseau par le serveur de gestion JSON-RPC du jeu (26.x) | `management-server-*` tenues par le gestionnaire (refus à la vérification et à l'écriture), `management-server-enabled=false` réécrit à chaque lancement |
| Utilisateur connecté non administrateur | lancer un programme (`settings.restart-script` de Spigot, exécuté par `Runtime.exec` dans `RestartCommand` de Paper 26.3), couper l'authentification (`online-mode`, `bungeecord`, mandataires Paper), ouvrir un service ou contacter une adresse (`server-ip`, `enable-query`, JMX, `text-filtering-config`, clés de mods dont un mot est `port`, `host`, `bind`, `url`, `webhook`, `script`, `command`, `secret`, `token`…) | réglages réservés aux administrateurs (`admin_only`, partagé avec l'interface qui les signale), comparés au disque, toutes occurrences comprises : refus nommé à la vérification, 403 et audit `config_refused` à l'écriture ; changement par un administrateur tracé dans l'audit ; arbre que l'analyseur complet ne représente pas par des chemins (plusieurs documents, étiquette de section, clé complexe, alias dans sa propre ancre, fusion d'une valeur, bombe d'alias) : modification réservée aux administrateurs, l'interface nomme la construction en cause et quoi changer |
| Utilisateur connecté (même administrateur) | faire lire ou lancer un fichier hors du dossier (`level-name=../x`, script absolu, `a.bat & calc`) | `level-name` et `restart-script` : chemin relatif sans `..`, lecteur ni nom réservé ; script en `[A-Za-z0-9._/-]` (Paper concatène la valeur à `cmd /c start ` ou `sh `) ; lancement refusé si le fichier a été modifié à la main ; `server.properties` ou `spigot.yml` non représentable (rien de vérifiable) : refusé pour tous, administrateurs compris, et lancement refusé, l'interface disant pourquoi |
| Fichier à clé en double | faire viser au mode visuel une autre occurrence que celle lue par le jeu (la dernière) | chemin en double : visuel refusé avec la clé nommée, éditions refusées, texte toujours éditable |

### Menaces retenues (phase 3 : joueurs et gestionnaire de fichiers)

| Attaquant | Peut | Parade |
|---|---|---|
| Utilisateur connecté | glisser une commande de console par un pseudo, une adresse ou une raison (`Bob op Eve`, `1.2.3.4; stop`, retour à la ligne) | pseudo `[A-Za-z0-9_]{1,16}`, adresse analysée puis réécrite, raison d'une ligne (200 caractères), niveau 1-4, expiration future, vérifiés avant la console comme avant le fichier |
| Utilisateur connecté | effacer une liste d'accès illisible en y ajoutant un joueur | fichier illisible signalé, jamais réécrit (422) ; mode JSON : liste d'objets exigée |
| Utilisateur connecté (session volée) ou chemin forgé | lire, écrire, renommer ou supprimer hors du dossier du serveur (`..`, `%2e%2e`, chemin absolu, lecteur, `CON`, `COM¹`, espace ou point final, lien symbolique, jonction ou autre point d'analyse, même vers l'intérieur) | forme du chemin contrôlée segment par segment avant le disque (422) ; puis, AU MOMENT de l'opération et dans le même fil : chaque composant lu sans suivre (`symlink_metadata`, attribut `REPARSE_POINT` sous Windows), forme canonique du parent sous la racine, ouverture sans suivre (`FILE_FLAG_OPEN_REPARSE_POINT` / `O_NOFOLLOW`) et nature de ce qui est ouvert vérifiée ; chemin revérifié après une écriture ; liens listés, jamais suivis (ni par le zip) |
| Utilisateur connecté | toucher au dossier interne `.rcm` (console, temporaires, corbeille) | premier segment `.rcm` refusé quelle que soit la casse ; absent des listes et des zip |
| Processus du serveur (greffon malveillant) | faire écrire ou lire le gestionnaire ailleurs : `.rcm` remplacé par un lien ou une jonction, lien posé à la place de `server.properties`, `whitelist.json`, `usercache.json` ou de l'historique de la console | `.rcm` et ses sous-dossiers vérifiés vrais dossiers avant chaque usage (temporaires d'envoi et de lancement, corbeille, historique de la console), sinon rien n'y est écrit ni lu ; lectures du gestionnaire sans suivre de lien sur le dernier composant, sans attendre (une FIFO posée à la place d'un fichier est refusée au lieu de bloquer, Unix) et bornées même si le fichier grandit : un lien n'est ni lu, ni recopié dans `server.properties` ou l'historique des réglages ; rotation de l'historique de la console seulement si `.rcm` est encore un vrai dossier |
| Utilisateur connecté | faire bloquer l'adresse du gestionnaire par Mojang en cherchant des pseudos sans fin | 30 demandes par minute à `api.mojang.com` pour tout le gestionnaire (réponses en cache gratuites), un 429 de Mojang suspend les demandes une minute ; au-delà, 429 avec `Retry-After` |
| Utilisateur connecté | contourner l'écran de l'EULA ou les gardes des réglages par le gestionnaire de fichiers | `eula.txt` refusé ; tout contenu de format connu (éditeur, envoi, renommage vers ce nom) passe l'analyseur et les gardes des réglages (clés gérées, chemins, réglages réservés aux administrateurs) |
| Utilisateur connecté non administrateur | lancer du code (greffon `.jar`, script `.sh`, `.bat`…) | programmes et code créés, envoyés, remplacés ou renommés (vers ou depuis) par les administrateurs seulement (403) ; supprimer reste permis (corbeille) |
| Utilisateur connecté non administrateur | contourner les réglages réservés par un fichier sans analyseur (`.conf`, `.ini`, `.txt` d'un greffon), une suppression (réglages remis à leur valeur par défaut), un déplacement ou une restauration | fichier sans analyseur dans `plugins/`, `mods/`, `config/` ou à la racine : règle par ligne du format texte (ligne qui porte un mot réservé), contenu illisible comme texte dans ces dossiers réservé aux administrateurs ; supprimer ou déplacer = écrire vide, restaurer = créer : chaque fichier concerné (dossiers parcourus sans suivre de lien ; seuls les fichiers soumis à une règle sont lus : 10 000 entrées et 32 Mio lus au plus, sinon refus avec un code dédié, « dossier trop grand pour être vérifié ») qui porte un réglage réservé, à l'ancien comme au nouveau chemin, réservé aux administrateurs (403) |
| Serveur en marche ou qui démarre | corrompre le monde ou une liste tenue en mémoire | règles vérifiées sous le verrou des enregistrements, que le lancement prend avant Java (une modification admise finit avant tout lancement) ; ce verrou est tenu par le fil qui fait le travail, jusqu'à sa fin, même si la requête est abandonnée (délai global de 30 s) ; aucune modification pendant un démarrage, un arrêt ou une installation ; le monde (`level-name`, ses dimensions et leurs parents) et les listes d'accès refusés serveur en marche |
| Envoi démesuré ou lent | remplir le disque, tenir une connexion | taille bornée (`upload_max_mb`, 1 Gio par défaut) comptée au fil de l'eau, 60 s sans rien recevoir = abandon, débit moyen d'au moins 32 Kio/s après une minute (envois et téléchargements : un client au compte-gouttes ne garde pas sa place) ; 4 envois et 8 téléchargements simultanés (2 par compte, toutes ses sessions comprises, 503 au-delà) ; taille annoncée et place libre du disque vérifiées avant, puis tous les 64 Mio (256 Mio gardés libres, 507 sinon) ; temporaire dans `.rcm/tmp` effacé quoi qu'il arrive (`Drop`), restes d'un plantage effacés au démarrage puis après 24 h (au démarrage aussi : temporaires d'écriture atomique `.rcm-XXXXXXXX.tmp` du dossier du serveur, emplacements de corbeille sans élément) ; corps `application/octet-stream` exigé, jeton anti-CSRF et `Origin` comme partout |
| Fausse manœuvre | perdre un dossier, ou un fichier écrasé par un envoi | suppression vers la corbeille (`.rcm/trash`, 30 jours), restauration sans jamais écraser ce qui a pris la place (de même qu'un déplacement) ; dossier : nom recopié vérifié par le serveur ; envoi qui écrase : ancien fichier à la corbeille d'abord (et sa version dans l'historique s'il s'agit de réglages), nouveau posé sans remplacer, ancien rendu si la pose échoue |
| Utilisateur connecté (session volée, compte ordinaire) | effacer définitivement la corbeille (détruire un monde supprimé) | effacement définitif (corbeille, ou élément trop gros pour elle) réservé aux administrateurs (vérifié avant tout code), puis ré-authentification (mot de passe, + code TOTP s'il est actif), audits `file_purged` et `file_erased` ; un compte ordinaire n'efface jamais rien, même par éviction : corbeille pleine = refus (507) |
| Utilisateur connecté | remplir le disque par la corbeille | corbeille de 200 éléments et 16 Gio par serveur : élément plus gros refusé (jamais rangé pour être effacé aussitôt, ni la corbeille vidée pour lui) ; pleine, les plus anciens partent pour un administrateur (prévenu dans la fenêtre de suppression), refus sinon ; expirés (30 jours) effacés au démarrage puis toutes les heures sous le verrou des enregistrements, jamais par la liste (simple lecture), liste plafonnée |
| Lecture de secrets | lire un mot de passe ou un jeton sans trace | lecture d'un fichier sensible (`server.properties`, `paper-global.yml`, clés, `*secret*`, `*token*`…) et tout téléchargement tracés dans l'audit |

### Menaces retenues (adresses publiques, DNS et aiguilleur)

Nouvelle surface : l'**aiguilleur** (`RCM_ROUTER_PORT`, coupé par défaut) est un écouteur TCP
public, sans authentification par nature (c'est le port du jeu). Il ne parle que la poignée de main
du protocole Minecraft, puis relaie des octets vers un serveur local en mode aiguilleur.

| Attaquant | Peut | Parade |
|---|---|---|
| Anonyme sur Internet | épuiser l'aiguilleur (connexions muettes, lentes, en masse) | poignée de main lue en 5 s au plus ; plafond global (`RCM_ROUTER_MAX_CONNECTIONS`, 1 024) et par adresse (`RCM_ROUTER_MAX_PER_IP`, 8 ; IPv6 par /64) pris AVANT toute lecture, refus par fermeture immédiate ; relais coupé après 2 min sans aucun octet dans un sens ; tampons fixes de 16 Kio par sens |
| Anonyme | faire planter ou gonfler l'analyse (VarInt sans fin, longueur démesurée, chaîne non UTF-8, champs en trop, ping hérité `0xFE`) | poignée de main de 1 Kio au plus, VarInt de 5 octets au plus, identifiant 0 et état 1 à 3 exigés, champs en trop refusés, adresse de 255 caractères (+ suffixe FML) au plus ; tout le reste fermé sans relais |
| Anonyme | joindre un serveur qui n'est pas en mode aiguilleur, ou un service local, par un nom forgé | routage par nom EXACT (point final et suffixe FML retirés, casse ignorée) parmi les seuls serveurs en mode aiguilleur, vers leur port local ; nom inconnu : réponse de statut ou refus de connexion lisible, puis fermeture ; aucune adresse de destination ne vient du client |
| Anonyme | énumérer les serveurs par le statut | nom inconnu et serveur arrêté répondent le même statut neutre du gestionnaire (aucune liste) |
| Joueur malveillant derrière l'aiguilleur | échapper à un bannissement par adresse | **limite assumée** : le serveur voit l'aiguilleur (boucle locale), pas l'adresse du joueur (pas de protocole PROXY) ; les bannissements par pseudo marchent, ceux par adresse non. Le mode « enregistrement direct » garde l'adresse réelle |
| Voleur du jeton Cloudflare | modifier toute la zone DNS (détourner le domaine) | jeton LIMITÉ conseillé (Zone:DNS:Edit sur la seule zone) ; fourni seulement par fichier (`RCM_CLOUDFLARE_TOKEN_FILE`, secret Docker) : variable en clair refusée au démarrage, jamais en base, jamais saisi dans l'interface, jamais journalisé (`Debug` masqué, erreurs réseau sans adresse, messages de Cloudflare bornés), retiré de l'environnement après lecture ; aucune redirection suivie (l'en-tête ne part nulle part ailleurs) |
| Utilisateur connecté non administrateur | écrire dans la zone DNS | aperçu et test pour tous ; application réservée aux administrateurs (403), session, CSRF, audit `address_changed` |
| Utilisateur connecté (même administrateur) | écraser un enregistrement posé à la main (MX, site, joker) | seuls les enregistrements du gestionnaire intacts sont modifiés ou supprimés : commentaire `rustcraft-manager <empreinte>` exact, empreinte égale au contenu actuel, nuage gris ; tout autre enregistrement au même nom (créé ou retouché à la main, CNAME) est un conflit montré et laissé tel quel ; noms limités à la zone (`RCM_DNS_ZONE`), FQDN validé, unique par serveur |
| Fausse manœuvre ou course entre deux onglets | appliquer autre chose que l'aperçu montré | empreinte de l'aperçu renvoyée à l'application, plan recalculé sous verrou : différent = 409 `preview_outdated` ; une synchronisation à la fois |
| Panne de détection d'IP ou de Cloudflare | retirer les enregistrements, ou les pointer ailleurs | IP inconnue : nos A/AAAA d'un nom encore attendu sont gardés ; IP détectée non publique (privée, CGNAT, documentation) écartée ; IP fixable (`RCM_PUBLIC_IPV4/6`) ; échec de Cloudflare audité (`dns_sync_failed`), repris au tour suivant |
| Joker proxifié (orange) | faire passer le jeu par le proxy HTTP de Cloudflare (injoignable) | enregistrement gris explicite par nom ; le test de joignabilité signale une résolution qui ne donne pas l'IP publique |
| Utilisateur connecté | faire sonder des adresses par le test de joignabilité | seul le nom public enregistré du serveur est testé (FQDN de la zone), sur son port de jeu, 5 s par étape, deux tests à la fois (503 au-delà) |

### Chiffré, haché, en clair

Chiffré = AES-256-GCM, format `v1:`, données associées `<table>:<colonne>:<id>` (recopié sur une
autre ligne ou colonne, il ne se déchiffre plus), déchiffrement fermé, clé dérivée (HKDF) de la
clé maîtresse hors base. Haché = empreinte seule, la valeur n'est jamais stockée.

| Table.colonne | Stockage | Raison |
|---|---|---|
| `users.totp_secret_enc`, `users.totp_pending_enc` | chiffré | secret partagé du TOTP |
| `users.password_hash` | haché (Argon2id) | mot de passe |
| `users.username` | en clair | identifiant de connexion, cherché à chaque connexion ; pas un secret |
| `users.webauthn_id` | en clair | 16 octets aléatoires remis au navigateur à chaque passkey ; jamais l'id SQL |
| `users.totp_last_step`, `is_admin`, `created_at` | en clair | numéro de pas (anti-rejeu), rôle, date : sans valeur pour un attaquant |
| `recovery_codes.code_hash` | haché (HMAC-SHA256, clé dérivée ; codes de la version 1 : SHA-256 salée, gardés valides) | code de secours |
| `sessions.token_hash` | haché (SHA-256 ; 256 bits aléatoires, pas besoin de hachage lent) | jeton de session |
| `sessions.csrf` | en clair | renvoyé à l'interface, inutile sans le cookie |
| `sessions.ip` | supprimée (migration 5) | n'était jamais relue |
| `audit_log.ip`, `audit_log.user_agent` | chiffré (jamais en clair : aucun repli) | donnée personnelle |
| `audit_log.username` | en clair, seulement s'il a la forme d'un nom | lecture de l'audit ; un mot de passe tapé dans le mauvais champ n'y entre pas |
| `audit_log.action`, `detail`, `ts`, `count` | en clair | nature de l'événement (jamais de secret), nom donné à une passkey |
| `passkeys.data`, `cred_id`, `counter`, `transports` | en clair | clé PUBLIQUE et compteur : ni secrets, ni personnels |
| `passkeys.name`, `created_at`, `last_used_at` | en clair | nom choisi par l'utilisateur, dates |
| `settings.key_check` | chiffré | témoin : une autre clé est refusée au démarrage |
| `servers.rcon_password_enc` | chiffré | mot de passe RCON tiré à la création, inutilisé tant que RCON est coupé (jamais écrit dans `server.properties`) |
| `servers.*` (nom, logiciel, version, ports, mémoire, Java, état voulu, EULA acceptée par et quand) | en clair | configuration, sans secret |
| `server_favorites`, `users.theme` | en clair | commandes favorites et thème choisis par le compte |
| `server_addresses` (nom public, mode, date, auteur) | en clair | configuration publique par nature (le nom est dans le DNS) |
| Jeton Cloudflare | hors base | secret Docker `RCM_CLOUDFLARE_TOKEN_FILE` seulement, retiré de l'environnement après lecture |
| `server_config_history.content_enc` | chiffré (données associées : serveur et chemin du fichier) | version précédente d'un fichier de configuration : peut porter un secret (`management-server-secret`, secret Velocity) |
| `server_config_history.path`, `ts`, `size`, `user_id` | en clair | fichier, date, taille, auteur de l'enregistrement |
| `<serveur>/.rcm/console.jsonl` | en clair (dossier du serveur) | historique de la console, comme `logs/latest.log` du serveur ; jamais de secret écrit par le gestionnaire |
| Clé maîtresse | hors base | secret Docker ou `manager.key` (0600), à sauvegarder à part ; retirée de l'environnement du processus après lecture ; en conteneur, un `manager.key` du volume est refusé |
| Copie d'avant migration (`manager.db.vN.bak`) | supprimée après une migration réussie | elle contenait les valeurs encore en clair ; la base est ensuite réécrite (VACUUM, `secure_delete`, journal WAL vidé) |
| Défis WebAuthn, compteurs des limiteurs | en mémoire seulement | perdus au redémarrage, sans conséquence |

## Audits

Revue contradictoire du 20/10/2026, avant la mise en ligne. Chaque constat a un test qui échoue
sans le correctif (vérifié en sabotant le correctif).

| Id | Constat | Correctif | Tests |
|---|---|---|---|
| B1 | Limite contrôlée avant Argon2 mais comptée après : N requêtes simultanées passaient toutes | réservation atomique avant le travail, pardon au succès ; requêtes en cours par réseau ; sémaphore Argon2 à délai ; même chose pour `/api/auth/totp`, session provisoire brûlée après 5 codes | `limite_tenue_sous_requetes_simultanees`, `requetes_en_cours_bornees_par_adresse`, `reservation_avant_le_travail`, `semaphore_avec_delai`, `session_provisoire_brulee` |
| B2 | Compteur par adresse exacte, table non bornée, audit d'un échec = une ligne | IPv6 par /64, IPv4 vue en IPv6 ramenée, clé de compte `#invalid`, tables bornées, échéancier par compte, échecs agrégés et rétention | `ipv6_par_64_et_audit_agrege`, `tables_bornees`, `echeancier_par_compte_borne_le_debit`, `echecs_agreges_et_bornes`, `purge_et_retention` |
| I1 | TOTP activable avec une session volée seule ; sessions gardées | ré-authentification unique `Reauthed` (limiteur propre), autres sessions fermées | `reauthentification_des_actions_sensibles`, `desactivation_ferme_les_autres_sessions` |
| I2 | Cookie non `Secure` derrière un mandataire non déclaré | `RCM_COOKIE_SECURE=always` dans l'image, avertissements au démarrage et sur `X-Forwarded-For` d'un pair non déclaré | `attributs_du_cookie`, `x_forwarded_for_non_fiable_ignore` |
| I3 | Exemple `172.16.0.0/12` trop large | mandataire par nom résolu, refus par défaut ; exemple corrigé | `mandataire_par_nom`, `noms_resolus_refus_par_defaut`, `limite_par_client_derriere_un_mandataire_de_confiance` |
| I4 | Aucun délai (axum::serve) | hyper + minuterie : en-têtes, requête, inactivité, plafond de connexions | `delais_et_plafond_de_connexions`, `corps_trop_lent_coupe` |
| I5 | Droits du dossier et de la base par défaut | 0700/0600 explicites, sonde d'écriture avec uid et `chown` | `sonde_d_ecriture`, `droits_unix` (Unix) |
| M1 | Cookie sans préfixe en HTTPS | `__Host-rcm_session` | `attributs_du_cookie`, `cookie_dans_l_en_tete` |
| M2 | Trames WebSocket de 16 Mio, canaux illimités | trames de 64 Kio, 4 canaux par session, client muet coupé | `websocket_trames_et_plafond_par_session` |
| M3 | Version annoncée à tous | seulement en local ou connecté | `version_seulement_en_local_ou_connecte` |
| M4 | Nom tenté invalide écrit dans l'audit | écrit seulement s'il a la forme d'un nom | `ipv6_par_64_et_audit_agrege` |
| M5 | `Origin` comparé sans le schéma | comparaison exacte, schéma compris | `origine_schema_compris`, `origine_comparee_schema_compris_derriere_le_mandataire` |
| M6 | Images de base non épinglées | `@sha256` dans le Dockerfile | — (relecture) |
| S1 | Secrets TOTP en clair en base | AES-256-GCM par champ, migration des valeurs existantes, témoin de clé | `chiffrement_par_champ_ferme`, `chaine_depuis_la_version_1`, `cle_fournie_lue_creee_ou_refusee` |
| S2 | Secrets et configuration lus sans contrôle | `_FILE` prioritaire et fermé, bornes, booléens stricts | `secret_par_fichier_prioritaire_et_ferme`, `echec_ferme_et_variable_nommee` |
| S3 | Transactions différées | `BEGIN IMMEDIATE` partout | `transactions_d_ecriture_immediates`, `aucune_transaction_differee_dans_les_sources` |
| S4 | Adresse et `User-Agent` de l'audit en clair, adresse des sessions gardée sans usage | chiffrés (migration des lignes existantes), colonne des sessions supprimée | `adresse_et_user_agent_chiffres`, `chaine_depuis_la_version_1` |
| P1 | Passkeys (ajout) | WebAuthn : défi côté serveur, usage unique, 5 min, lié à la session ; ré-authentification ; clé résidente et vérification de l'utilisateur exigées | `ajout_connexion_compteur_et_suppression`, `defi_a_usage_unique_et_origine_verifiee`, `defi_expire`, `defis_bornes` |
| P2 | Passkeys (connexion) | origine fixe, compteur qui recule refusé, limiteur de connexion, échecs audités | mêmes tests |
| B-A | Requête coupée pendant Argon2 : place du sémaphore rendue alors que le calcul continue (512 fils bloquants, ≈ 9,7 Gio) | place possédée et déplacée dans le fil bloquant ; `max_blocking_threads` = 32 | `coupures_pendant_le_hachage_bornees` |
| B-B | Aucune borne dure du second facteur par compte (un /48 ≈ 328 000 codes / 15 min) ; ralentissement = attentes parallèles ; `login_totp` sans attente | plafond dur de 10 échecs par compte et fenêtre (second facteur, ré-auth ; audit `second_factor_locked`), échéancier qui sérialise les essais d'un compte (mot de passe compris), agrégation /56 et /48 | `plafond_dur_par_compte`, `plafond_dur_du_second_facteur_toutes_adresses`, `echeancier_par_compte_borne_le_debit`, `ipv6_par_56_et_48` |
| I-A | Copie d'avant migration et pages libérées gardant les secrets en clair | `secure_delete`, `temp_store=MEMORY`, VACUUM + checkpoint après migration, copie supprimée après succès | `chaine_depuis_la_version_1` (aucun fichier du dossier ne contient la valeur) |
| I-B | Défis de passkey évincés par une rafale anonyme | tables séparées, refus (503) plutôt qu'éviction, 4 défis par session, 30 défis de connexion par réseau | `defi_d_enregistrement_survit_a_une_rafale` |
| I-C | Place de connexion rendue à l'upgrade WebSocket ; sessions par compte illimitées | place gardée par le canal, canaux fermés à l'arrêt ; 10 sessions par compte | `websocket_garde_sa_place_de_connexion`, `sessions_par_compte_bornees` |
| m1 | Code TOTP ou de secours consommé par une requête sensible au corps invalide | corps validé avant la ré-authentification | `corps_valide_avant_la_reauthentification` |
| m2 | En conteneur, `manager.key` du volume accepté | refusé : secret exigé | `cle_fournie_lue_creee_ou_refusee` |
| m3 | Mandataire par nom : adresse publique possible, fenêtre de 15 s | adresses privées seulement, résolution toutes les 5 s ; réseau Docker dédié à Traefik (README) | `noms_vers_adresses_privees_seulement` |
| m4 | Mandataire local non déclaré vu comme « local » (version affichée) | local = boucle locale ET aucun en-tête de relais | `version_seulement_en_local_ou_connecte` |
| m5 | Clé dans l'environnement du processus | retirée après lecture ; les serveurs Java sont lancés avec `env_clear` et une liste blanche (phase 2) | `chaque_secret_retire_de_l_environnement`, `cycle_de_vie_avec_un_faux_java` |
| m6 | Pas de plafond de connexions par adresse | 64 par adresse (`RCM_MAX_CONNECTIONS_PER_IP`), mandataires de confiance exemptés | `plafond_de_connexions_par_adresse` |
| m7 | Compteur de passkey mis à jour sans condition | `UPDATE … WHERE counter < ?` | `compteur_atomique_sous_concurrence` |
| m9 | Codes de secours de la version 1 (SHA-256) sans incitation à les changer | signalés dans le compte, régénération derrière la ré-authentification | `codes_de_secours_anciens_regeneres` |
| m11 | Tests incomplets | drapeau « utilisateur vérifié » absent refusé, code `passkey_rejected` vérifié | `verification_utilisateur_exigee_cote_serveur` |
| T1 | Anglais incomplet | langue du navigateur par défaut, pages d'avant l'interface bilingues | `chaque_cle_dans_chaque_langue`, `aucun_texte_visible_en_dur`, `pages_avant_l_interface_dans_les_deux_langues` |

Gardes de la phase 2 (20/10/2026). Chacune a été retirée une à une (script de sabotage) : un test
au moins a échoué à chaque fois (31 sur 31 ; la garde `..` des coordonnées Maven, doublée par
d'autres, a reçu un cas de test qui ne passe que par elle).

| Id | Garde | Tests |
|---|---|---|
| G1 | Environnement des processus vidé (liste blanche) | `cycle_de_vie_avec_un_faux_java`, `environnement_minimal_sans_secret` |
| G2 | Hôtes de téléchargement en liste fermée (HTTPS, port, identifiants, IP refusés) | `hotes_hostiles_refuses` |
| G3 | Somme et taille vérifiées, rien ne reste après un échec | `somme_taille_et_aucun_reste` |
| G4 | Identifiants de serveur, versions, coordonnées Maven validés avant tout chemin | `identifiants_hostiles_refuses`, `versions_hostiles_refusees`, `coordonnees_maven_hostiles_refusees`, `identifiants_hostiles` |
| G5 | Archive zip confinée | `zip_hostile_refuse` |
| G6 | Commande d'une seule ligne, bornée | `commandes_acceptees`, `eula_commande_theme_favoris` |
| G7 | Suppression : nom recopié vérifié avant la ré-authentification, puis ré-authentification | `suppression_nom_puis_reauthentification` |
| G8 | EULA jamais acceptée à la place de l'utilisateur (un seul endroit du code, démarrage refusé sans) | `eula_jamais_acceptee_automatiquement`, `eula_jamais_acceptee_a_la_place_de_l_utilisateur`, `eula_commande_theme_favoris` |
| G9 | `server.properties` sans injection de clé | `injection_refusee`, `mise_a_jour_sans_perte` |
| G10 | Thème validé (`#rrggbb`) | `eula_commande_theme_favoris`, `reglage_valide` |
| G11 | Lignes de sortie, historique en mémoire bornés | `lecture_bornee_des_lignes`, `historique_borne_et_persistant` |
| G12 | Une opération à la fois, port libre vérifié | `port_deja_pris_et_operation_unique` |
| G13 | Redémarrage automatique borné (3 plantages en 10 min) | `plantage_et_redemarrage_borne` |
| G14 | « En ligne » seulement port ouvert ; panne silencieuse signalée | `panne_silencieuse_et_arret_force` |
| G15 | CSRF et session sur toutes les routes qui modifient | `csrf_et_session_exiges` |
| G17 | Arrêter ou supprimer un serveur planté annule sa relance automatique (rien recréé) | `arret_ou_suppression_annule_la_relance` |
| G18 | RCON coupé, mesures par l'entrée standard (réponses retirées de la console) | `cycle_de_vie_avec_un_faux_java`, `mesures_par_l_entree_standard`, `reponses_aux_mesures` |
| G19 | Antislash final refusé (propriétés, noms) ; création tout ou rien ; bornes (serveurs, mémoire, installations) ; réglages refusés pendant une opération ; nettoyage au démarrage ; échec de langue mémorisé | `injection_refusee`, `bornes_creation_atomique_et_reglages`, `nettoyage_au_demarrage`, `echec_memorise_par_version` |
| G16 | Aucun orphelin si le gestionnaire est tué (objet Job, Windows) | essai réel : gestionnaire tué, `java.exe` disparu (non automatisé : il faut un vrai JRE) |

## Avant de partager un journal

Les journaux ne contiennent ni mot de passe ni jeton, sauf le lien de création du premier compte
affiché au tout premier lancement : retire-le avant de partager.

## Choix assumés

- **Changer le mot de passe ne touche pas aux passkeys** : ce sont des facteurs indépendants, chacun
  supprimable dans le compte (derrière la ré-authentification). Le changement ferme les autres
  sessions.
- **Ajouter une passkey ne ferme pas les autres sessions** : l'ajout est déjà derrière la
  ré-authentification (mot de passe + code) et l'audit le note (`passkey_added`) ; fermer les
  sessions de ses autres appareils à chaque ajout serait plus gênant qu'utile. Activer ou
  désactiver le TOTP, changer le mot de passe : autres sessions fermées.
- **Plafond dur du second facteur** : après 10 codes faux en 15 min (toutes adresses), le compte
  ne peut plus passer le second facteur jusqu'à la fin de la fenêtre ; c'est un verrouillage
  volontaire de CE facteur (le mot de passe ne suffit pas à le déclencher : il faut l'avoir), la
  passkey reste une issue. Le mot de passe n'a pas de plafond dur.
- **`secure_delete` en plus du VACUUM** : le VACUUM d'après migration suffit pour la migration
  (vérifié en retirant l'un puis l'autre) ; `secure_delete` couvre les effacements courants
  (sessions, codes de secours, passkeys supprimées).
