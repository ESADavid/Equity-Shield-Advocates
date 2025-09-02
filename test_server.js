#!/usr/bin/env node

/**
 * Test Server for JPMorgan Payment Integration
 *
 * This server is used for testing the JPMorgan payment endpoints
 * and integration functionality.
 */

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Import JPMorgan payment routes
const jpmorganRoutes = require('./earnings_dashboard/jpmorgan_payment');

// Mount JPMorgan routes under /jpmorgan
app.use('/jpmorgan', jpmorganRoutes);

// Basic health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'JPMorgan Payment Integration Test Server',
    timestamp: new Date().toISOString(),
    endpoints: [
      'GET /health',
      'POST /jpmorgan/create-payment',
      'GET /jpmorgan/payment-status/:paymentId',
      'POST /jpmorgan/refund',
      'POST /jpmorgan/capture',
      'POST /jpmorgan/void',
      'GET /jpmorgan/transactions',
      'POST /jpmorgan/webhook',
      'GET /jpmorgan/health',
      'POST /jpmorgan/sync-quickbooks'
    ]
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /health',
      'POST /jpmorgan/create-payment',
      'GET /jpmorgan/payment-status/:paymentId',
      'POST /jpmorgan/refund',
      'POST /jpmorgan/capture',
      'POST /jpmorgan/void',
      'GET /jpmorgan/transactions',
      'POST /jpmorgan/webhook',
      'GET /jpmorgan/health',
      'POST /jpmorgan/sync-quickbooks'
    ]
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 JPMorgan Payment Integration Test Server running at http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`💳 JPMorgan endpoints available at http://localhost:${PORT}/jpmorgan/*`);
  console.log('='.repeat(60));
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down test server...');
  server.close(() => {
    console.log('✅ Test server stopped');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down test server...');
  server.close(() => {
    console.log('✅ Test server stopped');
    process.exit(0);
  });
});

module.exports = app;
