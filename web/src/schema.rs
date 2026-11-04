//! Schéma de `server.properties` (clés et défauts lus dans le serveur 26.3, plus les clés des
//! versions plus anciennes) et libellés des principales options de Bukkit, Spigot, Paper et
//! Purpur. Données d'affichage seulement : le serveur valide et écrit.

use crate::i18n::Lang;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Group {
    Game,
    World,
    Players,
    Network,
    Security,
    Performance,
    Advanced,
}

pub const GROUPS: [Group; 7] =
    [Group::Game, Group::World, Group::Players, Group::Network, Group::Security, Group::Performance, Group::Advanced];

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Bool,
    Int {
        min: i64,
        max: i64,
    },
    /// Liste fermée.
    Choice(&'static [&'static str]),
    /// Texte avec suggestions à la frappe.
    Suggest(&'static [&'static str]),
    Text,
    /// Secret : masqué.
    Secret,
}

/// Raison d'une clé tenue par le gestionnaire (lecture seule).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Managed {
    /// Port réglé dans les paramètres du serveur.
    Port,
    /// RCON coupé par le gestionnaire.
    Rcon,
    /// Suit le port du jeu.
    Query,
    /// Serveur de gestion JSON-RPC : coupé par le gestionnaire.
    Management,
}

#[derive(Clone, Copy, Debug)]
pub struct Prop {
    pub key: &'static str,
    pub group: Group,
    pub kind: Kind,
    pub default: &'static str,
    pub fr: (&'static str, &'static str),
    pub en: (&'static str, &'static str),
    /// Première et dernière version qui lisent la clé (`None` : toujours, ou encore lue).
    pub since: Option<&'static str>,
    pub until: Option<&'static str>,
    pub managed: Option<Managed>,
}

impl Prop {
    pub fn label(&self, l: Lang) -> &'static str {
        if l == Lang::Fr { self.fr.0 } else { self.en.0 }
    }
    pub fn help(&self, l: Lang) -> &'static str {
        if l == Lang::Fr { self.fr.1 } else { self.en.1 }
    }
}

const fn p(
    key: &'static str,
    group: Group,
    kind: Kind,
    default: &'static str,
    fr: (&'static str, &'static str),
    en: (&'static str, &'static str),
) -> Prop {
    Prop { key, group, kind, default, fr, en, since: None, until: None, managed: None }
}

const fn since(mut x: Prop, v: &'static str) -> Prop {
    x.since = Some(v);
    x
}
const fn until(mut x: Prop, v: &'static str) -> Prop {
    x.until = Some(v);
    x
}
const fn managed(mut x: Prop, m: Managed) -> Prop {
    x.managed = Some(m);
    x
}

const B: Kind = Kind::Bool;
const T: Kind = Kind::Text;
const fn n(min: i64, max: i64) -> Kind {
    Kind::Int { min, max }
}
const MAXI: i64 = i32::MAX as i64;

use Group::*;

pub const PROPS: &[Prop] = &[
    // Jeu
    p(
        "motd",
        Game,
        T,
        "A Minecraft Server",
        ("Message d'accueil", "Affiché dans la liste des serveurs du jeu."),
        ("Message of the day", "Shown in the game's server list."),
    ),
    p(
        "gamemode",
        Game,
        Kind::Choice(&["survival", "creative", "adventure", "spectator"]),
        "survival",
        ("Mode de jeu", "Mode des nouveaux joueurs."),
        ("Game mode", "Mode given to new players."),
    ),
    p(
        "force-gamemode",
        Game,
        B,
        "false",
        ("Imposer le mode de jeu", "Remet le mode par défaut à chaque connexion."),
        ("Force game mode", "Resets players to the default mode on each join."),
    ),
    p(
        "difficulty",
        Game,
        Kind::Choice(&["peaceful", "easy", "normal", "hard"]),
        "easy",
        ("Difficulté", "Dégâts, faim, apparition des monstres."),
        ("Difficulty", "Damage, hunger, monster spawning."),
    ),
    p(
        "hardcore",
        Game,
        B,
        "false",
        ("Extrême", "Difficulté maximale, spectateur après la mort."),
        ("Hardcore", "Hardest difficulty, spectator after death."),
    ),
    p(
        "allow-flight",
        Game,
        B,
        "false",
        ("Autoriser le vol", "Ne pas expulser les joueurs qui volent (mods, plugins)."),
        ("Allow flight", "Do not kick flying players (mods, plugins)."),
    ),
    p(
        "spawn-protection",
        Game,
        n(0, MAXI),
        "16",
        ("Protection du point d'apparition", "Rayon où seuls les opérateurs construisent ; 0 pour aucun."),
        ("Spawn protection", "Radius where only operators can build; 0 for none."),
    ),
    until(
        p(
            "pvp",
            Game,
            B,
            "true",
            ("Combat entre joueurs", "Les joueurs peuvent se blesser."),
            ("PvP", "Players can hurt each other."),
        ),
        "1.21.8",
    ),
    until(
        p(
            "allow-nether",
            Game,
            B,
            "true",
            ("Nether", "Les portails mènent au Nether."),
            ("Nether", "Portals lead to the Nether."),
        ),
        "1.21.8",
    ),
    until(
        p("spawn-animals", Game, B, "true", ("Animaux", "Apparition des animaux."), ("Animals", "Animals spawn.")),
        "1.21.8",
    ),
    until(
        p("spawn-monsters", Game, B, "true", ("Monstres", "Apparition des monstres."), ("Monsters", "Monsters spawn.")),
        "1.21.8",
    ),
    until(
        p(
            "spawn-npcs",
            Game,
            B,
            "true",
            ("Villageois", "Apparition des villageois."),
            ("Villagers", "Villagers spawn."),
        ),
        "1.21.8",
    ),
    until(
        p(
            "enable-command-block",
            Game,
            B,
            "false",
            ("Blocs de commande", "Les blocs de commande s'exécutent."),
            ("Command blocks", "Command blocks run."),
        ),
        "1.21.8",
    ),
    // Monde
    p(
        "level-name",
        World,
        T,
        "world",
        ("Dossier du monde", "Créé s'il n'existe pas."),
        ("World folder", "Created if missing."),
    ),
    p(
        "level-seed",
        World,
        T,
        "",
        ("Graine", "Vide : graine au hasard (nouveau monde seulement)."),
        ("Seed", "Empty: random seed (new world only)."),
    ),
    p(
        "level-type",
        World,
        Kind::Suggest(&[
            "minecraft:normal",
            "minecraft:flat",
            "minecraft:large_biomes",
            "minecraft:amplified",
            "minecraft:single_biome_surface",
            "default",
            "flat",
            "largeBiomes",
            "amplified",
            "buffet",
        ]),
        "minecraft:normal",
        ("Type de monde", "Préréglage de génération (nouveau monde seulement)."),
        ("World type", "Generation preset (new world only)."),
    ),
    p(
        "generator-settings",
        World,
        T,
        "{}",
        ("Réglages du générateur", "JSON du monde plat ou personnalisé."),
        ("Generator settings", "JSON for flat or custom worlds."),
    ),
    p(
        "generate-structures",
        World,
        B,
        "true",
        ("Structures", "Villages, temples, forteresses…"),
        ("Structures", "Villages, temples, strongholds…"),
    ),
    p(
        "max-world-size",
        World,
        n(1, 29_999_984),
        "29999984",
        ("Rayon du monde", "Bordure maximale, en blocs."),
        ("World radius", "Maximum border, in blocks."),
    ),
    until(
        p(
            "max-build-height",
            World,
            n(64, 256),
            "256",
            ("Hauteur de construction", "Hauteur maximale."),
            ("Build height", "Maximum height."),
        ),
        "1.16.5",
    ),
    p(
        "initial-enabled-packs",
        World,
        T,
        "vanilla",
        ("Packs activés", "Packs de données à la création du monde."),
        ("Enabled packs", "Data packs when the world is created."),
    ),
    p(
        "initial-disabled-packs",
        World,
        T,
        "",
        ("Packs désactivés", "Packs exclus à la création du monde."),
        ("Disabled packs", "Packs excluded when the world is created."),
    ),
    // Joueurs
    p(
        "max-players",
        Players,
        n(0, MAXI),
        "20",
        ("Joueurs au plus", "Places simultanées."),
        ("Max players", "Simultaneous slots."),
    ),
    p(
        "white-list",
        Players,
        B,
        "true",
        ("Liste blanche", "Seuls les joueurs listés entrent."),
        ("Whitelist", "Only listed players can join."),
    ),
    p(
        "enforce-whitelist",
        Players,
        B,
        "false",
        ("Liste blanche appliquée", "Expulse les connectés absents de la liste quand elle change."),
        ("Enforce whitelist", "Kicks online players missing from the list when it changes."),
    ),
    p(
        "op-permission-level",
        Players,
        n(0, 4),
        "4",
        ("Niveau des opérateurs", "0 à 4 : commandes permises aux opérateurs."),
        ("Operator level", "0 to 4: commands allowed to operators."),
    ),
    p(
        "player-idle-timeout",
        Players,
        n(0, MAXI),
        "0",
        ("Expulsion des absents", "Minutes d'inactivité ; 0 pour jamais."),
        ("Idle kick", "Idle minutes; 0 for never."),
    ),
    p(
        "hide-online-players",
        Players,
        B,
        "false",
        ("Cacher les joueurs", "La liste des serveurs n'affiche pas les connectés."),
        ("Hide players", "The server list hides who is online."),
    ),
    p(
        "broadcast-console-to-ops",
        Players,
        B,
        "true",
        ("Console vers les opérateurs", "Les commandes de la console leur sont montrées."),
        ("Console to operators", "Console commands are shown to them."),
    ),
    p(
        "broadcast-rcon-to-ops",
        Players,
        B,
        "true",
        ("RCON vers les opérateurs", "Les commandes RCON leur sont montrées."),
        ("RCON to operators", "RCON commands are shown to them."),
    ),
    since(
        p(
            "enable-code-of-conduct",
            Players,
            B,
            "false",
            ("Code de conduite", "Affiche les fichiers du dossier codeofconduct."),
            ("Code of conduct", "Shows the files of the codeofconduct folder."),
        ),
        "1.21.9",
    ),
    since(
        p(
            "bug-report-link",
            Players,
            T,
            "",
            ("Lien de signalement", "Adresse proposée aux joueurs pour signaler un bogue."),
            ("Bug report link", "Address offered to players to report a bug."),
        ),
        "1.21.6",
    ),
    since(
        p(
            "chat-spam-threshold-seconds",
            Players,
            n(0, MAXI),
            "10",
            ("Seuil anti-spam du tchat", "Secondes de la fenêtre de comptage."),
            ("Chat spam threshold", "Seconds of the counting window."),
        ),
        "26.1",
    ),
    since(
        p(
            "command-spam-threshold-seconds",
            Players,
            n(0, MAXI),
            "10",
            ("Seuil anti-spam des commandes", "Secondes de la fenêtre de comptage."),
            ("Command spam threshold", "Seconds of the counting window."),
        ),
        "26.1",
    ),
    p(
        "require-resource-pack",
        Players,
        B,
        "false",
        ("Pack de ressources exigé", "Refusé : déconnexion."),
        ("Require resource pack", "Declined: disconnected."),
    ),
    p(
        "resource-pack",
        Players,
        T,
        "",
        ("Pack de ressources", "Adresse de téléchargement."),
        ("Resource pack", "Download address."),
    ),
    p(
        "resource-pack-sha1",
        Players,
        T,
        "",
        ("Empreinte SHA-1 du pack", "Vérifiée par le jeu."),
        ("Pack SHA-1", "Checked by the game."),
    ),
    p("resource-pack-id", Players, T, "", ("Identifiant du pack", "UUID du pack."), ("Pack ID", "UUID of the pack.")),
    p(
        "resource-pack-prompt",
        Players,
        T,
        "",
        ("Message du pack", "Texte JSON montré avec la demande."),
        ("Pack prompt", "JSON text shown with the request."),
    ),
    // Réseau
    p(
        "server-ip",
        Network,
        T,
        "",
        ("Adresse d'écoute", "Vide : toutes les interfaces."),
        ("Bind address", "Empty: every interface."),
    ),
    managed(p("server-port", Network, n(1, 65535), "25565", ("Port du jeu", ""), ("Game port", "")), Managed::Port),
    p(
        "enable-status",
        Network,
        B,
        "true",
        ("Visible dans la liste", "Répond aux demandes d'état des clients."),
        ("Listed", "Answers status requests."),
    ),
    p(
        "enable-query",
        Network,
        B,
        "false",
        ("Protocole GameSpy4", "Informations du serveur en UDP."),
        ("GameSpy4 query", "Server info over UDP."),
    ),
    managed(
        p("query.port", Network, n(1, 65535), "25565", ("Port de requête", ""), ("Query port", "")),
        Managed::Query,
    ),
    since(
        p(
            "accepts-transfers",
            Network,
            B,
            "false",
            ("Transferts entrants", "Accepte les joueurs envoyés par un autre serveur."),
            ("Incoming transfers", "Accepts players sent by another server."),
        ),
        "1.20.5",
    ),
    p(
        "network-compression-threshold",
        Network,
        n(-1, MAXI),
        "256",
        ("Seuil de compression", "Octets ; -1 pour ne pas compresser."),
        ("Compression threshold", "Bytes; -1 for no compression."),
    ),
    p(
        "rate-limit",
        Network,
        n(0, MAXI),
        "0",
        ("Paquets par seconde", "Au-delà, expulsion ; 0 pour sans limite."),
        ("Packets per second", "Above it, kicked; 0 for no limit."),
    ),
    p(
        "use-native-transport",
        Network,
        B,
        "true",
        ("Transport natif", "Epoll sous Linux."),
        ("Native transport", "Epoll on Linux."),
    ),
    p(
        "prevent-proxy-connections",
        Network,
        B,
        "false",
        ("Refuser les mandataires", "Compare l'adresse à celle vue par Mojang."),
        ("Block proxies", "Compares the address with the one seen by Mojang."),
    ),
    since(
        p(
            "status-heartbeat-interval",
            Network,
            n(0, MAXI),
            "0",
            ("Rappel d'état", "Secondes entre deux états poussés aux clients ; 0 pour jamais."),
            ("Status heartbeat", "Seconds between status pushes to clients; 0 for never."),
        ),
        "1.21.9",
    ),
    // Sécurité
    p(
        "online-mode",
        Security,
        B,
        "true",
        ("Comptes vérifiés", "Vérifie chaque compte auprès de Mojang."),
        ("Online mode", "Checks every account with Mojang."),
    ),
    p(
        "enforce-secure-profile",
        Security,
        B,
        "true",
        ("Tchat signé exigé", "Clés de profil Mojang obligatoires."),
        ("Secure profile", "Mojang profile keys required."),
    ),
    p(
        "log-ips",
        Security,
        B,
        "true",
        ("Adresses dans le journal", "Note l'adresse IP des joueurs."),
        ("Log IPs", "Logs players' IP addresses."),
    ),
    managed(p("enable-rcon", Security, B, "false", ("RCON", ""), ("RCON", "")), Managed::Rcon),
    managed(p("rcon.port", Security, n(1, 65535), "25575", ("Port RCON", ""), ("RCON port", "")), Managed::Rcon),
    managed(
        p("rcon.password", Security, Kind::Secret, "", ("Mot de passe RCON", ""), ("RCON password", "")),
        Managed::Rcon,
    ),
    managed(
        since(
            p(
                "management-server-enabled",
                Security,
                B,
                "false",
                ("Serveur de gestion", "Interface JSON-RPC du jeu, pilotage à distance."),
                ("Management server", "The game's JSON-RPC interface, remote control."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-host",
                Security,
                T,
                "localhost",
                ("Adresse de gestion", "Interface d'écoute."),
                ("Management host", "Listening interface."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-port",
                Security,
                n(0, 65535),
                "0",
                ("Port de gestion", "0 : choisi au hasard."),
                ("Management port", "0: picked at random."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-secret",
                Security,
                Kind::Secret,
                "",
                ("Secret de gestion", "Jeton exigé des clients."),
                ("Management secret", "Token required from clients."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-tls-enabled",
                Security,
                B,
                "true",
                ("TLS de gestion", "Chiffre l'interface de gestion."),
                ("Management TLS", "Encrypts the management interface."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-tls-keystore",
                Security,
                T,
                "",
                ("Magasin de clés TLS", "Fichier PKCS12."),
                ("TLS keystore", "PKCS12 file."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-tls-keystore-password",
                Security,
                Kind::Secret,
                "",
                ("Mot de passe du magasin", "Mot de passe du fichier PKCS12."),
                ("Keystore password", "Password of the PKCS12 file."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    managed(
        since(
            p(
                "management-server-allowed-origins",
                Security,
                T,
                "",
                ("Origines permises", "Pages web autorisées, séparées par des virgules."),
                ("Allowed origins", "Allowed web pages, comma separated."),
            ),
            "1.21.9",
        ),
        Managed::Management,
    ),
    p(
        "text-filtering-config",
        Security,
        T,
        "",
        ("Filtre de texte", "Configuration du filtre externe."),
        ("Text filtering", "External filter configuration."),
    ),
    since(
        p(
            "text-filtering-version",
            Security,
            n(0, 1),
            "0",
            ("Version du filtre", "Protocole du filtre externe."),
            ("Filter version", "External filter protocol."),
        ),
        "1.21.2",
    ),
    // Performances
    p(
        "view-distance",
        Performance,
        n(3, 32),
        "10",
        ("Distance de vue", "Tronçons envoyés autour de chaque joueur."),
        ("View distance", "Chunks sent around each player."),
    ),
    p(
        "simulation-distance",
        Performance,
        n(3, 32),
        "10",
        ("Distance de simulation", "Tronçons où le monde avance."),
        ("Simulation distance", "Chunks where the world ticks."),
    ),
    p(
        "entity-broadcast-range-percentage",
        Performance,
        n(10, 1000),
        "100",
        ("Portée des entités", "Pourcentage de la distance d'envoi des entités."),
        ("Entity range", "Percentage of the entity send distance."),
    ),
    since(
        p(
            "pause-when-empty-seconds",
            Performance,
            n(-1, MAXI),
            "60",
            ("Pause sans joueur", "Secondes avant la pause ; 0 ou moins pour jamais."),
            ("Pause when empty", "Seconds before pausing; 0 or less for never."),
        ),
        "1.21.2",
    ),
    p(
        "max-tick-time",
        Performance,
        n(-1, i64::MAX),
        "60000",
        ("Garde-fou d'un tick", "Millisecondes avant l'arrêt forcé ; -1 pour jamais."),
        ("Watchdog", "Milliseconds before a forced stop; -1 for never."),
    ),
    p(
        "max-chained-neighbor-updates",
        Performance,
        n(-1, MAXI),
        "1000000",
        ("Mises à jour en chaîne", "Plafond des mises à jour de blocs voisins."),
        ("Chained updates", "Limit of chained neighbour block updates."),
    ),
    p(
        "sync-chunk-writes",
        Performance,
        B,
        "true",
        ("Écritures synchrones", "Tronçons écrits sans tampon (plus sûr, plus lent)."),
        ("Synchronous writes", "Chunks written unbuffered (safer, slower)."),
    ),
    since(
        p(
            "region-file-compression",
            Performance,
            Kind::Choice(&["deflate", "lz4", "none"]),
            "deflate",
            ("Compression des régions", "Format des fichiers de région."),
            ("Region compression", "Region file format."),
        ),
        "1.20.5",
    ),
    // Avancé
    p(
        "function-permission-level",
        Advanced,
        n(1, 4),
        "2",
        ("Niveau des fonctions", "Permissions des fonctions des packs."),
        ("Function level", "Permissions of pack functions."),
    ),
    p(
        "enable-jmx-monitoring",
        Advanced,
        B,
        "false",
        ("Surveillance JMX", "Expose les temps de tick à JMX."),
        ("JMX monitoring", "Exposes tick times to JMX."),
    ),
    until(
        p(
            "snooper-enabled",
            Advanced,
            B,
            "true",
            ("Statistiques Mojang", "Envoi de données d'usage."),
            ("Snooper", "Sends usage data."),
        ),
        "1.17.1",
    ),
    p(
        "debug",
        Advanced,
        B,
        "false",
        ("Débogage", "Journal plus bavard (Paper et anciennes versions)."),
        ("Debug", "Chattier log (Paper and old versions)."),
    ),
];

pub fn prop(key: &str) -> Option<&'static Prop> {
    PROPS.iter().find(|p| p.key == key)
}

/// Version du jeu en nombres (`1.20.4` → [1, 20, 4] ; `26.4-snapshot-4` → [26, 4]).
fn nums(v: &str) -> Vec<u32> {
    v.split(['-', ' ']).next().unwrap_or("").split('.').map_while(|x| x.parse().ok()).collect()
}

/// La clé existe dans cette version du jeu.
pub fn in_version(p: &Prop, version: &str) -> bool {
    let v = nums(version);
    if v.is_empty() {
        return true;
    }
    p.since.is_none_or(|s| v >= nums(s)) && p.until.is_none_or(|u| v <= nums(u))
}

/// Libellé et aide d'une option YAML connue (chemin en points, fichier).
pub struct Known {
    pub file: &'static str,
    pub path: &'static str,
    pub fr: (&'static str, &'static str),
    pub en: (&'static str, &'static str),
}

const fn k(
    file: &'static str,
    path: &'static str,
    fr: (&'static str, &'static str),
    en: (&'static str, &'static str),
) -> Known {
    Known { file, path, fr, en }
}

pub const KNOWN: &[Known] = &[
    // bukkit.yml
    k("bukkit.yml", "settings.allow-end", ("End", "Le portail de l'End fonctionne."), ("End", "The End portal works.")),
    k(
        "bukkit.yml",
        "settings.warn-on-overload",
        ("Alerte de surcharge", "Écrit « Can't keep up » dans le journal."),
        ("Overload warning", "Logs “Can't keep up”."),
    ),
    k(
        "bukkit.yml",
        "settings.connection-throttle",
        ("Délai entre connexions", "Millisecondes entre deux connexions d'une même adresse."),
        ("Connection throttle", "Milliseconds between two joins from one address."),
    ),
    k(
        "bukkit.yml",
        "settings.shutdown-message",
        ("Message d'arrêt", "Montré aux joueurs à l'arrêt."),
        ("Shutdown message", "Shown to players on shutdown."),
    ),
    k(
        "bukkit.yml",
        "spawn-limits",
        ("Plafonds d'apparition", "Créatures par joueur, par catégorie."),
        ("Spawn limits", "Mobs per player, per category."),
    ),
    k(
        "bukkit.yml",
        "ticks-per",
        ("Ticks entre apparitions", "Fréquence des apparitions par catégorie."),
        ("Ticks per spawn", "Spawn frequency per category."),
    ),
    k(
        "bukkit.yml",
        "ticks-per.autosave",
        ("Sauvegarde automatique", "Ticks entre deux sauvegardes ; 0 : celle du jeu."),
        ("Autosave", "Ticks between saves; 0: the game's."),
    ),
    // spigot.yml
    k(
        "spigot.yml",
        "settings.bungeecord",
        ("BungeeCord", "Derrière un mandataire BungeeCord."),
        ("BungeeCord", "Behind a BungeeCord proxy."),
    ),
    k(
        "spigot.yml",
        "settings.restart-on-crash",
        ("Relance après plantage", "Lance le script de redémarrage."),
        ("Restart on crash", "Runs the restart script."),
    ),
    k(
        "spigot.yml",
        "settings.timeout-time",
        ("Délai du garde-fou", "Secondes de blocage avant le vidage des fils."),
        ("Watchdog timeout", "Seconds stuck before dumping threads."),
    ),
    k(
        "spigot.yml",
        "settings.save-user-cache-on-stop-only",
        ("Cache des joueurs à l'arrêt", "Écrit usercache.json seulement à l'arrêt."),
        ("User cache on stop", "Writes usercache.json on stop only."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.view-distance",
        ("Distance de vue", "« default » : celle de server.properties."),
        ("View distance", "“default”: the one from server.properties."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.simulation-distance",
        ("Distance de simulation", "« default » : celle de server.properties."),
        ("Simulation distance", "“default”: the one from server.properties."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.mob-spawn-range",
        ("Portée d'apparition", "Tronçons autour du joueur."),
        ("Mob spawn range", "Chunks around the player."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.item-despawn-rate",
        ("Disparition des objets", "Ticks avant qu'un objet au sol disparaisse."),
        ("Item despawn", "Ticks before a dropped item vanishes."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.merge-radius",
        ("Regroupement", "Rayon de fusion des objets et de l'expérience."),
        ("Merge radius", "Merge radius of items and experience."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.entity-activation-range",
        ("Activation des entités", "Distance où les entités agissent pleinement."),
        ("Entity activation", "Distance where entities fully tick."),
    ),
    k(
        "spigot.yml",
        "world-settings.default.entity-tracking-range",
        ("Suivi des entités", "Distance d'envoi des entités aux joueurs."),
        ("Entity tracking", "Distance entities are sent to players."),
    ),
    // config/paper-global.yml
    k(
        "config/paper-global.yml",
        "proxies.velocity.enabled",
        ("Velocity", "Derrière un mandataire Velocity."),
        ("Velocity", "Behind a Velocity proxy."),
    ),
    k(
        "config/paper-global.yml",
        "proxies.velocity.secret",
        ("Secret Velocity", "Clé partagée avec le mandataire."),
        ("Velocity secret", "Key shared with the proxy."),
    ),
    k(
        "config/paper-global.yml",
        "chunk-loading-basic.player-max-chunk-load-rate",
        ("Chargement par joueur", "Tronçons chargés par seconde, au plus."),
        ("Load rate per player", "Chunks loaded per second, at most."),
    ),
    k(
        "config/paper-global.yml",
        "chunk-system.worker-threads",
        ("Fils des tronçons", "-1 : choisi par Paper."),
        ("Chunk threads", "-1: picked by Paper."),
    ),
    k(
        "config/paper-global.yml",
        "console.enable-brigadier-highlighting",
        ("Couleurs de la console", "Coloration des commandes."),
        ("Console colours", "Command highlighting."),
    ),
    k(
        "config/paper-global.yml",
        "misc.max-joins-per-tick",
        ("Connexions par tick", "Joueurs acceptés par tick, au plus."),
        ("Joins per tick", "Players accepted per tick, at most."),
    ),
    k(
        "config/paper-global.yml",
        "watchdog.early-warning-delay",
        ("Alerte précoce", "Millisecondes avant le premier avertissement."),
        ("Early warning", "Milliseconds before the first warning."),
    ),
    k(
        "config/paper-global.yml",
        "anticheat.anti-xray.enabled",
        ("Anti-xray", "Cache les minerais."),
        ("Anti-xray", "Hides ores."),
    ),
    // config/paper-world-defaults.yml
    k(
        "config/paper-world-defaults.yml",
        "anticheat.anti-xray.enabled",
        ("Anti-xray", "Cache les minerais aux tricheurs."),
        ("Anti-xray", "Hides ores from cheaters."),
    ),
    k(
        "config/paper-world-defaults.yml",
        "chunks.auto-save-interval",
        ("Sauvegarde des tronçons", "Ticks entre deux sauvegardes ; « default » : celle du jeu."),
        ("Chunk autosave", "Ticks between saves; “default”: the game's."),
    ),
    k(
        "config/paper-world-defaults.yml",
        "chunks.max-auto-save-chunks-per-tick",
        ("Tronçons sauvés par tick", "Au plus."),
        ("Chunks saved per tick", "At most."),
    ),
    k(
        "config/paper-world-defaults.yml",
        "entities.spawning.per-player-mob-spawns",
        ("Apparitions par joueur", "Plafond réparti entre les joueurs."),
        ("Per-player spawns", "Cap shared between players."),
    ),
    k(
        "config/paper-world-defaults.yml",
        "environment.optimize-explosions",
        ("Explosions optimisées", "Calcul plus rapide des explosions."),
        ("Optimised explosions", "Faster explosion maths."),
    ),
    k(
        "config/paper-world-defaults.yml",
        "tick-rates",
        ("Fréquences", "Ticks entre deux mises à jour, par mécanique."),
        ("Tick rates", "Ticks between updates, per mechanic."),
    ),
    k(
        "config/paper-world-defaults.yml",
        "collisions.max-entity-collisions",
        ("Collisions par entité", "Au plus."),
        ("Collisions per entity", "At most."),
    ),
    // purpur.yml
    k(
        "purpur.yml",
        "settings.use-alternate-keepalive",
        ("Keepalive alternatif", "Tolère mieux les connexions instables."),
        ("Alternate keepalive", "Copes better with unstable links."),
    ),
    k(
        "purpur.yml",
        "settings.messages",
        ("Messages", "Textes affichés aux joueurs."),
        ("Messages", "Texts shown to players."),
    ),
    k(
        "purpur.yml",
        "settings.command",
        ("Commandes", "Réglages des commandes de Purpur."),
        ("Commands", "Purpur command settings."),
    ),
    k(
        "purpur.yml",
        "world-settings.default.gameplay-mechanics",
        ("Mécaniques", "Règles de jeu modifiables par Purpur."),
        ("Mechanics", "Game rules tunable by Purpur."),
    ),
    k(
        "purpur.yml",
        "world-settings.default.mobs",
        ("Créatures", "Réglages par créature."),
        ("Mobs", "Per-mob settings."),
    ),
    k(
        "purpur.yml",
        "world-settings.default.blocks",
        ("Blocs", "Réglages par bloc."),
        ("Blocks", "Per-block settings."),
    ),
];

/// Option connue de ce fichier (chemin en points).
pub fn known(file: &str, path: &str) -> Option<&'static Known> {
    // Folia et Purpur lisent les mêmes fichiers que Paper.
    KNOWN.iter().find(|k| k.file == file && k.path == path)
}
