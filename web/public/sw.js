// Service worker minimal de Rustcraft Manager.
// - Fichiers dont le nom porte l'empreinte (wasm, js, css de trunk) : cache d'abord (immuables).
// - Navigation : réseau d'abord, coquille en cache si hors ligne.
// - /api et /version : jamais mis en cache.
// Cache nommé par l'empreinte de l'interface (remplacée par build.rs à la construction du
// binaire) : une nouvelle interface = un nouveau service worker, l'ancien cache est purgé.
const CACHE = "rcm-__RCM_UI_VERSION__";

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.add("/")).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Notifications push (phase 5 : abonnement Web Push côté serveur à venir). Charge utile JSON
// { title, body, tag, url } ; un clic ouvre ou ramène l'onglet du gestionnaire, jamais une autre
// origine.
self.addEventListener("push", (e) => {
  let msg = {};
  try {
    msg = e.data ? e.data.json() : {};
  } catch {
    /* charge utile qui n'est pas de nous */
  }
  e.waitUntil(
    self.registration.showNotification(msg.title || "Rustcraft Manager", {
      body: msg.body || "",
      tag: msg.tag,
      icon: "/icon-192.png",
      badge: "/icon-192.png",
      data: { url: msg.url || "/" },
    })
  );
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "/", self.location.origin);
  if (url.origin !== self.location.origin) return;
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      const open = list.find((c) => new URL(c.url).origin === url.origin);
      return open ? open.focus().then((c) => c.navigate(url.href)) : self.clients.openWindow(url.href);
    })
  );
});

// Seule la coquille elle-même entre dans le cache sous "/" : réponse réussie, même origine, non
// redirigée, en HTML. Une page de connexion de mandataire (Authelia), une redirection ou une page
// d'erreur ne doit jamais l'écraser (sinon le mode hors ligne servirait cette page).
function estCoquille(res) {
  return (
    res.ok &&
    !res.redirected &&
    res.type === "basic" &&
    (res.headers.get("content-type") || "").toLowerCase().startsWith("text/html")
  );
}

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (
    req.method !== "GET" ||
    url.origin !== self.location.origin ||
    url.pathname.startsWith("/api/") ||
    url.pathname === "/version"
  ) {
    return;
  }
  if (req.mode === "navigate") {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (estCoquille(res)) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put("/", copy));
          }
          return res;
        })
        .catch(() => caches.match("/"))
    );
    return;
  }
  if (/-[0-9a-f]{12,}(_bg)?\.(wasm|js|css)$/.test(url.pathname)) {
    e.respondWith(
      caches.match(req).then(
        (hit) =>
          hit ||
          fetch(req).then((res) => {
            if (res.ok) {
              const copy = res.clone();
              caches.open(CACHE).then((c) => c.put(req, copy));
            }
            return res;
          })
      )
    );
  }
});
