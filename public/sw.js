const CACHE_NAME = 'digdeep-shell-v4';
const CORE_SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './favicon.svg',
  './favicon.ico',
  './apple-touch-icon.png',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(CORE_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k.startsWith('digdeep-shell-') && k !== CACHE_NAME)
            .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  const data = event.data;
  if (data && data.type === 'CACHE_URLS' && Array.isArray(data.urls)) {
    event.waitUntil(
      caches.open(CACHE_NAME).then((cache) =>
        Promise.all(
          data.urls.map((url) =>
            fetch(url)
              .then((resp) => {
                if (resp.ok) return cache.put(url, resp);
              })
              .catch(() => undefined)
          )
        )
      )
    );
  }
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  const accept = request.headers.get('accept') || '';

  // Never intercept or cache DNS-over-HTTPS wire queries (even if self-hosted on same origin)
  if (accept.includes('application/dns-message') || url.searchParams.has('dns')) {
    return;
  }

  // Never intercept or cache cross-origin APIs (except Google Fonts stylesheets/glyphs)
  if (url.origin !== self.location.origin) {
    if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
      event.respondWith(
        caches.match(request).then(
          (cached) =>
            cached ||
            fetch(request).then((resp) => {
              if (resp.ok) {
                const clone = resp.clone();
                caches.open(CACHE_NAME).then((c) => c.put(request, clone));
              }
              return resp;
            })
        )
      );
    }
    return;
  }

  // Immutable hashed Vite bundle assets: Cache-First
  if (url.pathname.includes('/assets/')) {
    event.respondWith(
      caches.match(request).then(
        (cached) =>
          cached ||
          fetch(request).then((resp) => {
            if (resp.ok) {
              const clone = resp.clone();
              caches.open(CACHE_NAME).then((c) => c.put(request, clone));
            }
            return resp;
          })
      )
    );
    return;
  }

  // Navigation & shell files: Network-First with offline cache fallback
  event.respondWith(
    fetch(request)
      .then((resp) => {
        if (resp.ok) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then((c) => c.put(request, clone));
        }
        return resp;
      })
      .catch(async () => {
        const cached = await caches.match(request);
        if (cached) return cached;
        if (request.mode === 'navigate') {
          return (await caches.match('./index.html')) || (await caches.match('./'));
        }
        throw new Error('Offline and not in cache');
      })
  );
});
