// Mock for server-enhanced.js - used in integration tests
// This avoids ESM transformation issues with __dirname

/**
 * @typedef {Object} MockExpress
 * @property {Function} get
 * @property {Function} post
 * @property {Function} put
 * @property {Function} delete
 * @property {Function} use
 * @property {Function} listen
 */

/**
 * Creates mock Express app for testing
 * @returns {MockExpress}
 */
function createMockApp() {
  /** @type {Object} */
  const routes = {};
  
  /**
   * @param {string} path
   * @param {Function} handler
   */
  function get(path, handler) {
    routes[path] = routes[path] || {};
    routes[path].get = handler;
  }
  
  /**
   * @param {string} path
   * @param {Function} handler
   */
  function post(path, handler) {
    routes[path] = routes[path] || {};
    routes[path].post = handler;
  }
  
  /**
   * @param {string} path
   * @param {Function} handler
   */
  function put(path, handler) {
    routes[path] = routes[path] || {};
    routes[path].put = handler;
  }
  
/**
   * @param {string} path
   * @param {Function} handler
   */
  function del(path, handler) {
    routes[path] = routes[path] || {};
    routes[path].del = handler;
  }
  
  /**
   * @param {Function} handler
   */
  function use(handler) {
    // Middleware - ignore in mock
  }
  
  /**
   * @param {number} port
   * @param {Function} callback
   * @returns {Object}
   */
  function listen(port, callback) {
    if (callback) callback();
    return {
      close: () => {}
    };
  }
  
  return { get, post, put, delete, use, listen, routes };
}

/** @type {MockExpress} */
const mockApp = createMockApp();

// Setup test routes
mockApp.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Blackbox Multi-Agent test routes
mockApp.post('/api/multi-agent/create', (req, res) => {
  res.json({
    success: true,
    taskId: 'test-task-123',
    taskUrl: 'https://blackbox.com/task/test-task-123'
  });
});

mockApp.post('/api/multi-agent/optimize', (req, res) => {
  res.json({
    success: true,
    message: 'Optimization started'
  });
});

mockApp.get('/api/multi-agent/status/:taskId', (req, res) => {
  res.status(500).json({
    success: false,
    error: 'Task not found'
  });
});

// Default export
export default mockApp;
