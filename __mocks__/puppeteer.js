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
    goto: async (url, options = {}) => ({
      url,
      options,
      status: 200,
    }),
    
    // Wait for selector
    waitForSelector: async (selector) => true,
    
    // Click element
    click: async (selector) => {},
    
    // Type in input
    type: async (selector, text) => {},
    
    // Evaluate JavaScript
    evaluate: async (fn) => {
      if (typeof fn === 'function') {
        return fn();
      }
      return {};
    }),
    
    // Get content
    content: async () => '<html><body>Mock Page</body></html>',
    
    // Get title
    title: async () => 'Mock Page Title',
    
    // Close page
    close: async () => {},
    
    // Set viewport
    setViewport: async (options) => {},
    
    // screenshot
    screenshot: async () => Buffer.from(''),
    
    // Query selectors
    $: async (selector) => null,
    $$: async (selector) => [],
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
