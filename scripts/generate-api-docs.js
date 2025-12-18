#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const options = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'OSCAR BROOME REVENUE API',
      description: 'Comprehensive financial management platform API',
      version: '2.0.0',
      contact: {
        name: 'OSCAR BROOME Development Team',
        email: 'support@oscarbroome.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server'
      },
      {
        url: 'https://api.oscarbroome.com',
        description: 'Production server'
      }
    ],
    security: [
      {
        bearerAuth: []
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  },
  apis: [
    './routes/*.js',
    './models/*.js',
    './services/*.js',
    './controllers/*.js',
    './server-enhanced.js'
  ]
};

const specs = swaggerJsdoc(options);

// Write the OpenAPI spec to file
const outputPath = path.join(__dirname, '..', 'docs', 'openapi.json');
fs.writeFileSync(outputPath, JSON.stringify(specs, null, 2));

logger.info(`✅ API documentation generated: ${outputPath}`);

// Generate HTML documentation
const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>OSCAR BROOME REVENUE API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.7.2/swagger-ui.css" />
    <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5.7.2/favicon-32x32.png" sizes="32x32" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.7.2/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.7.2/swagger-ui-standalone-preset.js"></script>
    <script>
    window.onload = function() {
      const ui = SwaggerUIBundle({
        url: './openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>
`;

const htmlPath = path.join(__dirname, '..', 'docs', 'index.html');
fs.writeFileSync(htmlPath, htmlTemplate);

logger.info(`✅ HTML documentation generated: ${htmlPath}`);

// Generate Postman collection
const postmanCollection = {
  info: {
    name: 'OSCAR BROOME REVENUE API',
    description: 'Comprehensive financial management platform API',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
  },
  item: [],
  variable: [
    {
      key: 'baseUrl',
      value: 'http://localhost:3000',
      type: 'string'
    },
    {
      key: 'token',
      value: '',
      type: 'string'
    }
  ]
};

// Add authentication endpoints
postmanCollection.item.push({
  name: 'Authentication',
  item: [
    {
      name: 'Login',
      request: {
        method: 'POST',
        header: [
          {
            key: 'Content-Type',
            value: 'application/json'
          }
        ],
        body: {
          mode: 'raw',
          raw: JSON.stringify({
            username: '{{username}}',
            password: '{{password}}'
          }, null, 2)
        },
        url: {
          raw: '{{baseUrl}}/api/auth/login',
          host: ['{{baseUrl}}'],
          path: ['api', 'auth', 'login']
        }
      }
    },
    {
      name: 'Get Profile',
      request: {
        method: 'GET',
        header: [
          {
            key: 'Authorization',
            value: 'Bearer {{token}}'
          }
        ],
        url: {
          raw: '{{baseUrl}}/api/auth/profile',
          host: ['{{baseUrl}}'],
          path: ['api', 'auth', 'profile']
        }
      }
    }
  ]
});

// Add system endpoints
postmanCollection.item.push({
  name: 'System',
  item: [
    {
      name: 'Health Check',
      request: {
        method: 'GET',
        header: [],
        url: {
          raw: '{{baseUrl}}/health',
          host: ['{{baseUrl}}'],
          path: ['health']
        }
      }
    },
    {
      name: 'API Status',
      request: {
        method: 'GET',
        header: [],
        url: {
          raw: '{{baseUrl}}/api/status',
          host: ['{{baseUrl}}'],
          path: ['api', 'status']
        }
      }
    }
  ]
});

const postmanPath = path.join(__dirname, '..', 'docs', 'postman-collection.json');
fs.writeFileSync(postmanPath, JSON.stringify(postmanCollection, null, 2));

logger.info(`✅ Postman collection generated: ${postmanPath}`);
logger.info('\n📚 API Documentation Summary:');
logger.info(`   - OpenAPI 3.0 spec: docs/openapi.json`);
logger.info(`   - HTML documentation: docs/index.html`);
logger.info(`   - Postman collection: docs/postman-collection.json`);
logger.info('\n🚀 To view documentation:');
logger.info('   1. Start the server: npm start');
logger.info('   2. Open: http://localhost:3000/api-docs');
logger.info('   3. Or open docs/index.html in browser');
