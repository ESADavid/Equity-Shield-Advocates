// public/sw.js - Service Worker for PWA with offline support
// Required by tests/pwa-basic.test.js

const CACHE_NAME = 'oscar-broome-v1';
const OFFLINE_URL = '/offline.html';

// Register install event
globalThis.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll([
        '/',
        '/index.html',
        '/static/js/bundle.js',
        '/offline.html'
      ]);
    })
  );
  // Skip waiting to activate immediately
  globalThis.skipWaiting();
});

// Register activate event
globalThis.addEventListener('activate', (event) => {
  // Claim clients immediately
  event.waitUntil(
    globalThis.clients.claim().then(() => {
      // Clean up old caches
      return caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => caches.delete(name))
        );
      });
    })
  );
});

// Background sync for offline transactions
function syncOfflineTransactions() {
  return globalThis.registration.sync.register('background-transaction-sync').then(() => {
    console.log('Background sync registered');
  });
}

// Register fetch event
globalThis.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      if (response) {
        return response;
      }
      return fetch(event.request).catch(() => {
        // Return offline page for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match(OFFLINE_URL);
        }
        return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
      });
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
