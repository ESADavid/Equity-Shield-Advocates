// jest.setup.js - Global test environment setup
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'warn'; // Reduce logger noise

/* eslint-disable no-console */
// Mock console methods to reduce noise
const originalConsoleMethods = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
};

const suppressedMethods = ['log', 'info'];
const consoleMethods = {};

suppressedMethods.forEach((method) => {
  consoleMethods[method] = jest.fn();
});

Object.keys(originalConsoleMethods).forEach((method) => {
  if (!consoleMethods[method]) {
    consoleMethods[method] = originalConsoleMethods[method];
  }
});

Object.assign(console, consoleMethods);

globalThis.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({}),
  })
);

globalThis.TextEncoder = require('node:util').TextEncoder;
globalThis.TextDecoder = require('node:util').TextDecoder;

// Service Worker mocks for browser tests
if (typeof globalThis !== 'undefined') {
  globalThis.caches = {
    open: jest.fn(),
    match: jest.fn(),
    add: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    keys: jest.fn(),
  };
}

// Fix for jsdom
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
global.setImmediate = global.setImmediate || ((fn, ...args) => setTimeout(() => fn(...args), 0));
