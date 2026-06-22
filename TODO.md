# PWA Test Fix TODO

- [x] Update `public/sw.js` to include `activate` event and background sync (`syncOfflineTransactions`, `background-transaction-sync`)
- [x] Create `public/manifest.json` with required PWA properties
- [x] Create `public/offline.html` with offline fallback content
- [x] Update homepage HTML to register service worker (`navigator.serviceWorker.register('/sw.js')`)
- [ ] Run tests and verify `tests/pwa-basic.test.js` passes
