const { defineConfig } = require('cypress');

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:4000',
    specPattern: 'cypress/e2e/**/*.cy.js',
    supportFile: false,
    defaultCommandTimeout: 10000,
    pageLoadTimeout: 20000,
  },
});
