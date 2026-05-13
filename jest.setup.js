// jest.setup.js - Global test environment setup
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'warn'; // Reduce logger noise

/* eslint-disable no-console */

/** @type {Array<'log'|'info'>} */
const suppressedMethods = ['log', 'info'];

/** @type {Record<string, Function>} */
const consoleMethods = {};

// Suppress log and info console methods
suppressedMethods.forEach(function (/** @type {'log'|'info'} */ method) {
  consoleMethods[method] = jest.fn();
});

// Restore warn and error methods
const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
};

Object.keys(originalConsole).forEach(function (/** @type {string} */ method) {
  if (!consoleMethods[method]) {
    consoleMethods[method] = originalConsole[/** @type {'log'|'info'|'warn'|'error'} */ (method)];
  }
});

Object.assign(console, consoleMethods);

/** @type {() => Promise<Response>} */
const createMockResponse = function () {
  return Promise.resolve({
    ok: true,
    json: function () { return Promise.resolve({}); },
    headers: new Headers(),
    redirected: false,
    status: 200,
    statusText: 'OK',
    type: 'default',
    url: '',
    body: null,
    bodyUsed: false,
    clone: function () { return this; },
    text: function () { return Promise.resolve(''); },
    blob: function () { return Promise.resolve(new Blob()); },
    formData: function () { return Promise.resolve(new FormData()); },
    arrayBuffer: function () { return Promise.resolve(new ArrayBuffer(0)); },
    bytes: function () { return Promise.resolve(new Uint8Array(0)); },
  });
};

globalThis.fetch = jest.fn(createMockResponse);

// Use built-in Node.js TextEncoder/TextDecoder for browser test environments
if (typeof TextEncoder !== 'undefined') {
  globalThis.TextEncoder = TextEncoder;
}
if (typeof TextDecoder !== 'undefined') {
  globalThis.TextDecoder = TextDecoder;
}

/** @type {CacheStorage['open']} */
const mockCacheOpen = function () {
  return Promise.resolve({
    match: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    keys: jest.fn(),
    add: jest.fn(),
    addAll: jest.fn(),
    matchAll: jest.fn(),
  });
};

/** @type {CacheStorage} */
const mockCacheStorage = {
  open: mockCacheOpen,
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
  observe() { return; }
  unobserve() { return; }
  disconnect() { return; }
};

/** @type {(fn: Function) => void} */
const setImmediatePolyfill = function (fn) {
  setTimeout(fn, 0);
};

// Only set if not already defined
if (!globalThis.setImmediate) {
  // @ts-ignore - polyfill for test environment
  globalThis.setImmediate = setImmediatePolyfill;
}
