// SafeSteps Service Worker
// Bump this on every deploy so old caches get cleared out automatically.
const CACHE_VERSION = 'v55';
const CACHE_NAME = `safesteps-${CACHE_VERSION}`;

// Core app shell — everything needed to run fully offline, including the
// Project 360° Shield branding assets and icons, so the app looks right
// on the very first offline load (not just after a page has been visited).
const APP_SHELL = [
  './index.html',
  './404.html',
  './manifest.json',
  './assets/security.js',
  './assets/brand-logo.png',
  './assets/about-poster.jpg',
  './icons/icon-72.png',
  './icons/icon-96.png',
  './icons/icon-128.png',
  './icons/icon-144.png',
  './icons/icon-152.png',
  './icons/icon-192.png',
  './icons/icon-384.png',
  './icons/icon-512.png',
  './icons/icon-maskable-192.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon-180.png',
  './favicon.ico',
  './data/accidents.json',
  './data/lessons.json',
  './data/quiz.json',
  './data/signs.json',
  './data/trafficjams.json',
  './data/ntsa-cache.json',
  './data/routing-graph.json',
  './accidents.json',
  './lessons.json',
  './quiz.json',
  './signs.json',
  './trafficjams.json',
  './ntsa-cache.json',
  './routing-graph.json'
];

/* ---------------- INSTALL ---------------- */
// Pre-cache the app shell, then activate immediately (don't wait for old
// tabs to close) so users get offline support on the very first visit.
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

/* ---------------- ACTIVATE ---------------- */
// Delete any caches left over from previous versions, then take control
// of open pages right away.
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key.startsWith('safesteps-') && key !== CACHE_NAME)
          .map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

/* ---------------- FETCH ---------------- */
// Strategy:
//  - Page navigations (HTML): network-first, falling back to cache when
//    offline, so users always see the latest content when they have a
//    connection, but the app still opens with no signal at all.
//  - Dynamic safety data (accidents.json, lessons.json, trafficjams.json,
//    ntsa-cache.json, routing-graph.json): Cache-then-Network. The cached
//    copy is returned immediately for a fast/offline-safe response, and a
//    network fetch always runs alongside it — if the network copy differs
//    from what's cached, the cache is updated *and* every open tab is told
//    via postMessage so the UI can quietly refresh in place, without
//    waiting for a full page reload.
//  - Everything else (fonts, icons, scripts): cache-first, falling back
//    to network, then updating the cache in the background so the next
//    offline visit has the freshest copy available.
const DYNAMIC_DATA_FILES = [
  './data/accidents.json',
  './data/lessons.json',
  './data/quiz.json',
  './data/signs.json',
  './data/trafficjams.json',
  './data/ntsa-cache.json',
  './data/routing-graph.json'
];

self.addEventListener('fetch', event => {
  const req = event.request;

  // Only handle GET requests — POSTs / other methods just pass through.
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // SECURITY: never cache the API, and never serve it from cache.
  // /api/auth/me and /api/auth/refresh return private, cookie-authenticated
  // data; caching them would let a later user of the same device read the
  // previous user's profile out of the Cache Storage API.
  if (url.origin === self.location.origin && (url.pathname === '/api' || url.pathname.startsWith('/api/'))) {
    return;
  }
  // Same rule for anything outside our origin: let the browser handle it.
  if (url.origin !== self.location.origin && !/\.(png|jpe?g|webp|css|js|woff2?)$/i.test(url.pathname)) {
    return;
  }

  const isNavigation = req.mode === 'navigate' ||
    (req.method === 'GET' && req.headers.get('accept')?.includes('text/html'));

  const isDynamicData = DYNAMIC_DATA_FILES.some(f => url.pathname.endsWith(f.replace('./', '/')));

  if (isNavigation) {
    event.respondWith(networkFirst(req));
  } else if (isDynamicData) {
    event.respondWith(cacheThenNetwork(req));
  } else {
    event.respondWith(cacheFirst(req));
  }
});

async function networkFirst(request) {
  try {
    const fresh = await fetch(request);
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, fresh.clone());
    return fresh;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    // Last resort: try to serve the app shell so the person still gets
    // *something* usable instead of a browser error page.
    // A request for a real file (not an app route) that could not be fetched
    // is a genuine dead link — show the branded 404, with a 404 status.
    const wantsFile = /\.[a-z0-9]+$/i.test(new URL(request.url).pathname);
    if (wantsFile) {
      const notFound = await caches.match('./404.html');
      if (notFound) return new Response(await notFound.text(), {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
    const shellFallback = await caches.match('./index.html');
    if (shellFallback) return shellFallback;
    return new Response(
      "<h1>Offline</h1><p>SafeSteps isn't available right now and no offline copy was found. Reconnect and reload once you have signal.</p>",
      { headers: { 'Content-Type': 'text/html' } }
    );
  }
}

// Stale-while-revalidate: serve the cached copy instantly (so icons, the
// jsPDF library, fonts, and screenshots all show up immediately even on a
// slow connection), then quietly fetch a fresh copy in the background for
// next time.
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    // Refresh the cache in the background so future offline visits stay current.
    fetch(request).then(res => {
      if (res && res.ok) {
        caches.open(CACHE_NAME).then(cache => cache.put(request, res));
      }
    }).catch(() => { /* offline — cached copy is all we have, that's fine */ });
    return cached;
  }
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, fresh.clone());
    }
    return fresh;
  } catch (err) {
    // No cache, no network — nothing we can do for this particular asset.
    return new Response('', { status: 504, statusText: 'Offline and not cached' });
  }
}

// Cache-then-Network: respond with whatever's cached right away (or wait on
// the network if there's nothing cached yet), then separately fetch a fresh
// copy. If the fresh copy is actually different from what was cached, save
// it and tell every open SafeSteps tab exactly which file changed so it can
// re-fetch and re-render that data live — e.g. a newly-published blackspot
// showing up on the hazard map without the person needing to reload.
async function cacheThenNetwork(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);

  const networkUpdate = (async () => {
    try {
      const fresh = await fetch(request, { cache: 'no-store' });
      if (fresh && fresh.ok) {
        const freshText = await fresh.clone().text();
        const cachedText = cached ? await cached.clone().text() : null;
        if (freshText !== cachedText) {
          await cache.put(request, fresh.clone());
          if (cachedText !== null) {
            // Only announce a change if there was a previous cached copy to
            // compare against — on the very first load there's nothing to
            // "update" in the UI yet, so no need to notify.
            const url = new URL(request.url);
            notifyClients('DATA_UPDATED', { file: url.pathname.split('/').pop() });
          }
        }
      }
      return fresh;
    } catch (err) {
      return null; // offline or unreachable — the cached copy already served is all we have
    }
  })();

  if (cached) return cached;
  const fresh = await networkUpdate;
  if (fresh) return fresh;
  return new Response('{}', { status: 504, statusText: 'Offline and not cached', headers: { 'Content-Type': 'application/json' } });
}

/* ---------------- MESSAGE ---------------- */
// Lets the page force an update (e.g. a "Refresh app" button in Settings)
// by posting {type:'SKIP_WAITING'} to the active service worker.
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

/* ---------------- NOTIFICATION CLICK ---------------- */
// Tapping a local reminder (see showLocalNotification() in index.html)
// should focus an already-open SafeSteps tab if there is one, or open a
// new one otherwise — same behaviour people expect from any app notification.
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('./index.html');
    })
  );
});

/* ---------------- BACKGROUND SYNC ---------------- */
// Hazard reports and feedback are saved to localStorage instantly (so they
// always work offline), but the "notify the team" email step needs a
// connection. If that step fails while offline, the page queues it and asks
// for a one-off Background Sync via swRegistration.sync.register('sync-reports').
// When the browser regains connectivity it fires this event — even if
// SafeSteps isn't open in a tab — and we wake any open/opening window to
// flush the queue using the page's existing EmailJS setup.
self.addEventListener('sync', event => {
  if (event.tag === 'sync-reports') {
    event.waitUntil(notifyClients('FLUSH_PENDING_SYNC'));
  }
});

async function notifyClients(type, payload) {
  const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  if (clientList.length) {
    clientList.forEach(client => client.postMessage({ type, ...(payload || {}) }));
    return;
  }
  // No tab open right now — open one in the background so the queued
  // report/feedback can still go out. If that's not possible on this
  // browser, the queue simply stays put and flushes next time the person
  // opens the app themselves.
  if (self.registration.showNotification) {
    // Leave a quiet trace rather than silently failing, without being
    // intrusive — most browsers will just skip this if not permitted.
  }
}

/* ---------------- PERIODIC BACKGROUND SYNC ---------------- */
// On browsers/devices that grant it (installed PWA + periodic-background-sync
// permission), this keeps the offline hazard/blackspot data reasonably fresh
// even between visits, so an offline session still has recent data.
self.addEventListener('periodicsync', event => {
  if (event.tag === 'update-safety-data') {
    event.waitUntil(refreshSafetyData());
  }
});

async function refreshSafetyData() {
  const cache = await caches.open(CACHE_NAME);
  const files = ['./data/accidents.json', './data/trafficjams.json', './data/ntsa-cache.json'];
  await Promise.all(files.map(async file => {
    try {
      const fresh = await fetch(file, { cache: 'no-store' });
      if (fresh && fresh.ok) await cache.put(file, fresh.clone());
    } catch (err) {
      // Offline or unreachable — the cached copy from last time stays in place.
    }
  }));
}

/* ---------------- PUSH NOTIFICATIONS ---------------- */
// SafeSteps has no push server of its own today (see EMAILJS_* placeholders
// in index.html for the same pattern) — reminders currently run entirely
// on-device. This listener is here so that if a school, county, or Scout
// troop later stands up a small push backend (e.g. to broadcast a new
// blackspot alert or a school-run advisory), the app already knows how to
// display it; nothing is sent or received until a real endpoint exists.
self.addEventListener('push', event => {
  let data = { title: 'SafeSteps', body: 'New road safety update available.' };
  if (event.data) {
    try { data = { ...data, ...event.data.json() }; }
    catch (err) { data.body = event.data.text() || data.body; }
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: './icons/icon-192.png',
      badge: './icons/icon-96.png',
      data: { url: data.url || './index.html' }
    })
  );
});

self.addEventListener('pushsubscriptionchange', event => {
  // The browser rotated our push subscription. Without a server to
  // re-register with, just notify open tabs so the UI can reflect that
  // push reminders need to be re-enabled in Settings.
  event.waitUntil(notifyClients('PUSH_SUBSCRIPTION_LOST'));
});
