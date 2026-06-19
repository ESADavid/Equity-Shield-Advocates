/**
 * Mock for puppeteer library
 * Used by PWA tests that need browser automation
 */

// Mock Browser launch
export const launch = async (options = {}) => ({
  // Browser options
  options,
  
  // Create new page
  newPage: async () => ({
    // Page navigation
    /**
     * @param {string} url
     * @param {object} [options]
     * @returns {Promise<{ url: string, options: object, status: number }>}
     */
    goto: async (url, options = {}) => ({
      url,
      options,
      status: 200,
    }),
    
    // Wait for selector
    /**
     * @param {string} _selector
     * @returns {Promise<true>}
     */
    waitForSelector: async (_selector) => true,
    
    // Click element
    /**
     * @param {string} _selector
     * @returns {Promise<void>}
     */
    click: async (_selector) => {},
    
    // Type in input
    /**
     * @param {string} _selector
     * @param {string} _text
     * @returns {Promise<void>}
     */
    type: async (_selector, _text) => {},
    
    // Evaluate JavaScript
    /**
     * @param {Function} fn
     * @returns {Promise<unknown>}
     */
    evaluate: async (fn) => {
      if (typeof fn === 'function') {
        return fn();
      }
      return {};
    },
    
    // Get content
    content: async () => '<html><body>Mock Page</body></html>',
    
    // Get title
    title: async () => 'Mock Page Title',
    
    // Close page
    close: async () => {},
    
    // Set viewport
    /**
     * @param {object} _options
     * @returns {Promise<void>}
     */
    setViewport: async (_options) => {},
    
    // screenshot
    /**
     * @returns {Promise<Buffer>}
     */
    screenshot: async () => Buffer.from(''),
    
    // Query selectors
    /**
     * @param {string} _selector
     * @returns {Promise<null>}
     */
    $: async (_selector) => null,
    
    /**
     * @param {string} _selector
     * @returns {Promise<Array<unknown>>}
     */
    $$: async (_selector) => [],
  }),
  
  // Close browser
  close: async () => {},
  
  // Create browser context
  createIncognitoBrowserContext: async () => ({
    newPage: async () => ({}),
    close: async () => {},
  }),
  
  // Target management
  targets: () => [],
  version: () => '1.0.0',
});

// Launcher create
export default { launch };
