// Bumped to v3: the old caches held stale copies of pages/forms served by the
// previous cache-first strategy below. Renaming purges them on activate.
const CACHE_STATIC = 'bfg-main-static-v3';
const CACHE_PAGES  = 'bfg-main-pages-v3';
const ALL_CACHES   = [CACHE_STATIC, CACHE_PAGES];

const APP_SHELL = ['/', '/index.html', '/manifest.json', '/icon-192.png', '/assets/Logo.JPG'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_STATIC).then(c => c.addAll(APP_SHELL)).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => !ALL_CACHES.includes(k)).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Never intercept these: agents fill out and print the forms, and the portal
  // and admin are login-gated — serving any of them from cache risks showing a
  // stale version. Let the browser fetch them normally so an update always lands.
  if (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/admin') ||
      url.pathname.startsWith('/portal') ||
      url.pathname.startsWith('/forms/') ||
      url.origin !== self.location.origin) return;

  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then(res => { caches.open(CACHE_PAGES).then(c => c.put(e.request, res.clone())); return res; })
        .catch(() => caches.match(e.request).then(h => h || caches.match('/')))
    );
    return;
  }

  // Network-first, falling back to cache only when offline. The previous
  // cache-first version returned the stored copy and merely refreshed the cache
  // for next time, so an updated form could stay stale indefinitely.
  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res.ok && e.request.method === 'GET') {
          const copy = res.clone();
          caches.open(CACHE_STATIC).then(c => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
