// @ts-nocheck
// Mock for server-enhanced.js - used in integration tests
// This avoids ESM transformation issues with __dirname

/**
 * @typedef {Object} MockRequest
 * @property {string} [body]
 * @property {Object} [params]
 * @property {Object} [query]
 */

/**
 * @typedef {Object} MockResponse
 * @property {Function} json
 * @property {Function} status
 * @property {number} statusCode
 */

/**
 * @typedef {Object} RouteHandlers
 * @property {Function} [get]
 * @property {Function} [post]
 * @property {Function} [put]
 * @property {Function} [del]
 */

/**
 * @typedef {Object} MockExpress
 * @property {Function} get
 * @property {Function} post
 * @property {Function} put
 * @property {Function} del
 * @property {Function} use
 * @property {Function} listen
 * @property {Object} routes
 */

/**
 * Routes storage
 * @type {Object.<string, RouteHandlers>}
 */
const routes = {};

/**
 * Get route handler
 * @param {string} path
 * @param {Function} handler
 */
function get(path, handler) {
  routes[path] = routes[path] || {};
  routes[path].get = handler;
}

/**
 * Post route handler
 * @param {string} path
 * @param {Function} handler
 */
function post(path, handler) {
  routes[path] = routes[path] || {};
  routes[path].post = handler;
}

/**
 * Put route handler
 * @param {string} path
 * @param {Function} handler
 */
function put(path, handler) {
  routes[path] = routes[path] || {};
  routes[path].put = handler;
}

/**
 * Delete route handler
 * @param {string} path
 * @param {Function} handler
 */
function del(path, handler) {
  routes[path] = routes[path] || {};
  routes[path].del = handler;
}

/**
 * Middleware handler
 * @param {Function} _handler
 */
function use(_handler) {
  // Middleware - ignore in mock
}

/**
 * Listen handler
 * @param {number} _port
 * @param {Function} callback
 * @returns {Object}
 */
function listen(_port, callback) {
  if (callback) callback();
  return {
    close: () => {}
  };
}

/** @type {MockExpress} */
const mockApp = { get, post, put, del, use, listen, routes };

// Setup test routes
/**
 * @param {MockRequest} _req
 * @param {MockResponse} res
 */
mockApp.get('/health', (_req, res) => {
  res.json({ status: 'healthy' });
});

// Blackbox Multi-Agent test routes
/**
 * @param {MockRequest} _req
 * @param {MockResponse} res
 */
mockApp.post('/api/multi-agent/create', (_req, res) => {
  res.json({
    success: true,
    taskId: 'test-task-123',
    taskUrl: 'https://blackbox.com/task/test-task-123'
  });
});

/**
 * @param {MockRequest} _req
 * @param {MockResponse} res
 */
mockApp.post('/api/multi-agent/optimize', (_req, res) => {
  res.json({
    success: true,
    message: 'Optimization started'
  });
});

/**
 * @param {MockRequest} _req
 * @param {MockResponse} res
 */
mockApp.get('/api/multi-agent/status/:taskId', (_req, res) => {
  res.status(500).json({
    success: false,
    error: 'Task not found'
  });
});

// Default export
export default mockApp;
