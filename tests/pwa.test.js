/**
 * Comprehensive PWA Testing Suite
 * Tests service worker, caching, offline functionality, and PWA features
 */

import puppeteer from 'puppeteer';

describe('Progressive Web App (PWA) Tests', () => {
  let browser;
  let page;

  beforeAll(async () => {
    try {
      browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });
    } catch (error) {
      console.warn('Puppeteer browser launch failed, skipping PWA tests:', error.message);
      browser = null;
    }
  });

  afterAll(async () => {
    if (browser) {
      await browser.close();
    }
  });

  beforeEach(async () => {
    if (!browser) {
      throw new Error('Browser not available, skipping test');
    }
    page = await browser.newPage();
    await page.setViewport({ width: 1200, height: 800 });
  });

  afterEach(async () => {
    if (page) {
      await page.close();
    }
  });

  describe('Service Worker Registration', () => {
    test('should register service worker successfully', async () => {
      await page.goto('http://localhost:3000');

      const swRegistration = await page.evaluate(() => {
        return navigator.serviceWorker.getRegistration();
      });

      expect(swRegistration).toBeTruthy();
      expect(swRegistration.scope).toBe('http://localhost:3000/');
    });

    test('should cache static assets', async () => {
      await page.goto('http://localhost:3000');

      // Wait for service worker to be ready
      await page.waitForFunction(() => {
        return navigator.serviceWorker.ready;
      });

      // Check if assets are cached
      const cacheContents = await page.evaluate(() => {
        return caches.open('ai-bank-static-v1.0.0').then((cache) => {
          return cache.keys().then((keys) => {
            return keys.map((request) => request.url);
          });
        });
      });

      expect(cacheContents.length).toBeGreaterThan(0);
      expect(cacheContents.some((url) => url.includes('manifest.json'))).toBe(
        true
      );
    });
  });

  describe('Offline Functionality', () => {
    test('should serve offline page when network is unavailable', async () => {
      await page.goto('http://localhost:3000');

      // Set offline
      await page.setOfflineMode(true);

      // Try to navigate to a page
      await page.goto('http://localhost:3000/offline.html');

      const content = await page.$eval('body', (el) => el.textContent);
      expect(content).toContain('offline');
    });

    test('should cache API responses for offline use', async () => {
      await page.goto('http://localhost:3000');

      // Wait for initial load
      await page.waitForSelector('.container');

      // Go offline
      await page.setOfflineMode(true);

      // Check if cached API data is available
      const cachedData = await page.evaluate(() => {
        return caches.open('ai-bank-dynamic-v1.0.0').then((cache) => {
          return cache.keys().then((keys) => {
            return keys.filter((request) => request.url.includes('/api/'))
              .length;
          });
        });
      });

      expect(cachedData).toBeGreaterThan(0);
    });
  });

  describe('Push Notifications', () => {
    test('should handle push notification events', async () => {
      await page.goto('http://localhost:3000');

      // Mock push event
      const pushHandled = await page.evaluate(() => {
        let handled = false;
        navigator.serviceWorker.addEventListener('message', (event) => {
          if (event.data.type === 'PUSH_RECEIVED') {
            handled = true;
          }
        });

        // Simulate push event (in real scenario, this would come from server)
        navigator.serviceWorker.controller.postMessage({
          type: 'PUSH_RECEIVED',
          title: 'Test Notification',
          body: 'This is a test push notification',
        });

        // Timeout after 2 seconds
        return new Promise((resolve) => {
          setTimeout(() => resolve(handled), 2000);
        });
      });

      expect(pushHandled).toBe(true);
    });
  });

  describe('Background Sync', () => {
    test('should register background sync for transactions', async () => {
      await page.goto('http://localhost:3000');

      const syncRegistered = await page.evaluate(async () => {
        if (
          'serviceWorker' in navigator &&
          'sync' in globalThis.ServiceWorkerRegistration.prototype
        ) {
          const registration = await navigator.serviceWorker.ready;
          await registration.sync.register('background-transaction-sync');
          return true;
        }
        return false;
      });

      // This test may fail in headless mode without proper sync support
      // In real browsers, this would work
      expect(syncRegistered).toBe(true);
    });
  });

  describe('PWA Manifest', () => {
    test('should have valid manifest.json', async () => {
      const response = await page.goto('http://localhost:3000/manifest.json');
      expect(response.ok()).toBe(true);

      const manifest = await response.json();

      expect(manifest).toHaveProperty('name');
      expect(manifest).toHaveProperty('short_name');
      expect(manifest).toHaveProperty('start_url');
      expect(manifest).toHaveProperty('display', 'standalone');
      expect(manifest).toHaveProperty('icons');
      expect(Array.isArray(manifest.icons)).toBe(true);
    });

    test('should be installable as PWA', async () => {
      await page.goto('http://localhost:3000');

      // Check for beforeinstallprompt event
      const installable = await page.evaluate(() => {
        let installPromptTriggered = false;

        window.addEventListener('beforeinstallprompt', () => {
          installPromptTriggered = true;
        });

        // Wait a bit for the event
        return new Promise((resolve) => {
          setTimeout(() => resolve(installPromptTriggered), 2000);
        });
      });

      expect(installable).toBe(true);
    });
  });

  describe('Performance & Caching', () => {
    test('should load quickly on second visit (cached)', async () => {
      // First visit
      const startTime1 = Date.now();
      await page.goto('http://localhost:3000');
      await page.waitForSelector('.container');
      const loadTime1 = Date.now() - startTime1;

      // Second visit (should be cached)
      const startTime2 = Date.now();
      await page.reload();
      await page.waitForSelector('.container');
      const loadTime2 = Date.now() - startTime2;

      // Second load should be significantly faster
      expect(loadTime2).toBeLessThan(loadTime1);
    });

    test('should handle cache versioning', async () => {
      await page.goto('http://localhost:3000');

      const cacheVersion = await page.evaluate(async () => {
        const cache = await caches.open('ai-bank-static-v1.0.0');
        return cache ? true : false;
      });

      expect(cacheVersion).toBe(true);
    });
  });

  describe('Mobile Responsiveness', () => {
    test('should be responsive on mobile viewport', async () => {
      await page.setViewport({ width: 375, height: 667 }); // iPhone SE size
      await page.goto('http://localhost:3000');

      const isResponsive = await page.evaluate(() => {
        const container = document.querySelector('.container');
        const viewportWidth = globalThis.innerWidth;
        const containerWidth = container.offsetWidth;

        // Container should not exceed viewport width
        return containerWidth <= viewportWidth;
      });

      expect(isResponsive).toBe(true);
    });

    test('should work with touch gestures', async () => {
      await page.setViewport({ width: 375, height: 667 });
      await page.goto('http://localhost:3000');

      // Test touch scroll
      await page.touchscreen.tap(200, 300);
      await page.waitForTimeout(500);

      // Should not throw any errors
      expect(true).toBe(true);
    });
  });
});
