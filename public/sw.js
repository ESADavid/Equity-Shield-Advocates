// public/sw.js - Service Worker for PWA support

const CACHE_NAME = 'oscar-broome-v1';
const OFFLINE_URL = '/offline.html';

async function syncOfflineTransactions() {
  // Placeholder implementation required by tests
  // In production, this would read queued transactions and replay them.
  return Promise.resolve();
}

globalThis.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll([
        '/',
        '/index.html',
        '/static/js/bundle.js',
        OFFLINE_URL
      ]);
    })
  );
});

globalThis.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
});

globalThis.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return (
        response ||
        fetch(event.request).catch(() => {
          if (event.request.mode === 'navigate') {
            return caches.match(OFFLINE_URL);
          }
          return undefined;
        })
      );
    })
  );
});

globalThis.addEventListener('sync', (event) => {
  if (event.tag === 'background-transaction-sync') {
    event.waitUntil(syncOfflineTransactions());
  }
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
