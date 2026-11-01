/* Build replaces these placeholders with the public static export inventory. */
const CACHE_NAME = '__PICHU_CACHE_NAME__';
const PRECACHE_URLS = __PICHU_PRECACHE_URLS__;
const PAYLOAD_ALIASES = __PICHU_PAYLOAD_ALIASES__;
const APP_PATHS = new Set(__PICHU_APP_PATHS__);
const PRECACHE_PATHS = new Set(
  [
    ...PRECACHE_URLS,
    ...Object.keys(PAYLOAD_ALIASES),
  ].map((path) => new URL(path, self.location.origin).pathname),
);
const OFFLINE_PATH = '/offline/';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      await cache.addAll(PRECACHE_URLS);
      await Promise.all(
        Object.entries(PAYLOAD_ALIASES).map(async ([alias, target]) => {
          const response = await cache.match(target);
          if (!response) throw new Error(`No se pudo precargar el payload de ruta ${target}.`);
          await cache.put(alias, response);
        }),
      );
    }),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => name.startsWith('pichu-shell-') && name !== CACHE_NAME)
            .map((name) => caches.delete(name)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  if (request.method !== 'GET' || url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    if (!APP_PATHS.has(url.pathname)) {
      event.respondWith(
        fetch(request).catch(async () => {
          const cache = await caches.open(CACHE_NAME);
          return cache.match(OFFLINE_PATH);
        }),
      );
      return;
    }

    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok && url.search === '') {
            const canonicalRequest = new Request(`${url.origin}${url.pathname}`);
            void caches.open(CACHE_NAME).then((cache) => cache.put(canonicalRequest, response.clone()));
          }
          return response;
        })
        .catch(async () => {
          const cache = await caches.open(CACHE_NAME);
          const cachedPage = await cache.match(`${url.origin}${url.pathname}`);
          return cachedPage ?? (await cache.match(OFFLINE_PATH));
        }),
    );
    return;
  }

  if (!PRECACHE_PATHS.has(url.pathname)) return;

  event.respondWith(
    caches.open(CACHE_NAME).then(async (cache) => {
      const cachedResponse = await cache.match(request, { ignoreSearch: true });
      if (cachedResponse) return cachedResponse;
      const response = await fetch(request);
      if (response.ok && url.search === '') await cache.put(request, response.clone());
      return response;
    }),
  );
});
