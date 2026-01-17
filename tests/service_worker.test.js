/**
 * Unit tests for Service Worker functionalities.
 * Mocks caching and verifies event listeners.
 */

beforeAll(() => {
  const eventListeners = new Map();

  globalThis.addEventListener = jest.fn((event, callback) => {
    eventListeners.set(event, callback);
  });

  globalThis.getEventListener = (event) => eventListeners.get(event);

  globalThis.registration = {
    showNotification: jest.fn(),
  };
  globalThis.caches = {
    open: jest.fn().mockResolvedValue({
      addAll: jest.fn().mockResolvedValue(true),
      put: jest.fn(),
    }),
    match: jest.fn(),
    keys: jest.fn().mockResolvedValue([]),
    delete: jest.fn().mockResolvedValue(true),
  };
  globalThis.clients = {
    matchAll: jest.fn().mockResolvedValue([{ postMessage: jest.fn() }]),
    openWindow: jest.fn(),
  };

  // Require the service worker script which registers event listeners
  require('../../public/sw.js');
});

describe('Service Worker events registration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('should register event listeners for install, push, notificationclick, and periodicsync', () => {
    expect(globalThis.addEventListener).toHaveBeenCalledWith(
      'install',
      expect.any(Function)
    );
    expect(globalThis.addEventListener).toHaveBeenCalledWith(
      'push',
      expect.any(Function)
    );
    expect(globalThis.addEventListener).toHaveBeenCalledWith(
      'notificationclick',
      expect.any(Function)
    );
    expect(globalThis.addEventListener).toHaveBeenCalledWith(
      'periodicsync',
      expect.any(Function)
    );
  });
});

describe('Service Worker install event', () => {
  test('should call caches.open during install event', () => {
    // Find install event listener function
    const installCall = globalThis.addEventListener.mock.calls.find(
      (call) => call[0] === 'install'
    );
    expect(installCall).toBeDefined();

    const installHandler = installCall[1];

    // Mock event with waitUntil capturing Promise
    const waitUntilMock = jest.fn();
    const event = { waitUntil: waitUntilMock };

    // Spy on caches.open to verify it is called
    const cachesOpenSpy = jest.spyOn(globalThis.caches, 'open');

    // Call the install handler
    installHandler(event);

    expect(cachesOpenSpy).toHaveBeenCalled();

    cachesOpenSpy.mockRestore();
  });
});
