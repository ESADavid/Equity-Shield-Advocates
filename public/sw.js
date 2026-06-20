// public/sw.js - Service Worker stub for tests
// Required by tests/service_worker.test.js

// Register event listeners (mocked in tests)
globalThis.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('oscar-broome-v1').then((cache) => {
      return cache.addAll([
        '/',
        '/index.html',
        '/static/js/bundle.js'
      ]);
    })
  );
});

globalThis.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});

globalThis.addEventListener('push', (event) => {
  const data = event.data?.json() || {};
  const options = {
    body: data.body || 'New notification',
    icon: '/icon.png',
    badge: '/badge.png'
  };
  event.waitUntil(
    globalThis.registration.showNotification(data.title || 'OSCAR BROOME', options)
  );
});

globalThis.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(globalThis.clients.openWindow('/'));
});
