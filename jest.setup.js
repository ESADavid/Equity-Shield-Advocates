// jest.setup.js - Global test environment setup
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'warn'; // Reduce logger noise

/* eslint-disable no-console */
// Mock console methods to reduce noise
/** @type {Record<'log'|'info'|'warn'|'error', typeof console.log>} */
const originalConsoleMethods = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
};

/** @type {Array<'log'|'info'>} */
const suppressedMethods = ['log', 'info'];
/** @type {Record<string, Function>} */
const consoleMethods = {};

suppressedMethods.forEach(/** @type {function(string): void} */ ((method) => {
  consoleMethods[method] = jest.fn();
}));

Object.keys(originalConsoleMethods).forEach(/** @type {function(string): void} */ ((method) => {
  if (!consoleMethods[method]) {
    consoleMethods[method] = originalConsoleMethods[/** @type {'log'|'info'|'warn'|'error'} */ (method)];
  }
}));

Object.assign(console, consoleMethods);

// Properly typed fetch mock - returns a complete Response-like object
/** @type {() => Promise<Response>} */
const createMockResponse = () => Promise.resolve(/** @type {Response} */ ({
  ok: true,
  json: () => Promise.resolve({}),
  headers: new Headers(),
  redirected: false,
  status: 200,
  statusText: 'OK',
  type: 'default',
  url: '',
  body: null,
  bodyUsed: false,
  clone: function () { return this; },
  text: () => Promise.resolve(''),
  blob: () => Promise.resolve(new Blob()),
  formData: () => Promise.resolve(new FormData()),
  arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
  bytes: () => Promise.resolve(new Uint8Array(0)),
}));

globalThis.fetch = jest.fn(/** @type {typeof createMockResponse} */ (createMockResponse));

// Use built-in Node.js TextEncoder/TextDecoder
globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;

// Service Worker mocks for browser tests (CacheStorage)
/** @type {CacheStorage} */
const mockCacheStorage = {
  open: jest.fn(),
  match: jest.fn(),
  delete: jest.fn(),
  keys: jest.fn(),
  has: jest.fn(),
};
if (typeof globalThis !== 'undefined') {
  globalThis.caches = mockCacheStorage;
}

// Fix for jsdom ResizeObserver
globalThis.ResizeObserver = class ResizeObserver {
  observe() {
    return;
  } // intentional no-op for jsdom test mock
  unobserve() {
    return;
  } // intentional no-op for jsdom test mock
  disconnect() {
    return;
  } // intentional no-op for jsdom test mock
};

// Polyfill setImmediate for node test environment
/** @type {(fn: () => void) => void} */
const setImmediatePolyfill = (fn) => setTimeout(fn, 0);
globalThis.setImmediate = globalThis.setImmediate || setImmediatePolyfill;
