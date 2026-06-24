const CACHE_STATIC = 'bfg-main-static-v2';
const CACHE_PAGES  = 'bfg-main-pages-v2';
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
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/admin') || url.origin !== self.location.origin) return;

  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then(res => { caches.open(CACHE_PAGES).then(c => c.put(e.request, res.clone())); return res; })
        .catch(() => caches.match(e.request).then(h => h || caches.match('/')))
    );
    return;
  }

  e.respondWith(
    caches.match(e.request).then(cached => {
      const network = fetch(e.request).then(res => {
        if (res.ok && e.request.method === 'GET')
          caches.open(CACHE_STATIC).then(c => c.put(e.request, res.clone()));
        return res;
      });
      return cached || network;
    })
  );
});
