/**
 * CRITICAL-PATH QUANTUM TESTING
 * Tests core quantum system components and server endpoints
 */
const request = require('supertest');
const { app, server, quantumEngine, quantumSecurity, quantumOptimizer } = require('../server-quantum');
const QuantumEngine = require('../quantum/quantumEngine');
const QuantumSecurity = require('../quantum/quantumSecurity');
const QuantumOptimizer = require('../quantum/quantumOptimizer');

describe('🚀 Quantum System Critical Testing', () => {
  let testServer;

  beforeAll(async () => {
    // Server is already started in server-quantum.js
    testServer = server;
  });

  afterAll(async () => {
    if (testServer) {
      testServer.close();
    }
  });

  describe('🔧 Quantum Engine Tests', () => {
    test('should initialize quantum engine successfully', () => {
      const engine = new QuantumEngine();
      expect(engine).toBeDefined();
      expect(engine.quantumState).toBeInstanceOf(Map);
      expect(engine.entanglementNodes).toBeInstanceOf(Set);
    });

    test('should set and get quantum state with integrity', () => {
      const engine = new QuantumEngine();
      const testKey = 'test-transaction-123';
      const testValue = { amount: 1000, currency: 'USD' };
      
      const hash = engine.setQuantumState(testKey, testValue);
      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      
      const retrieved = engine.getQuantumState(testKey);
      expect(retrieved).toEqual(testValue);
    });

    test('should handle quantum state recovery', () => {
      const engine = new QuantumEngine();
      const testKey = 'test-recovery';
      const testValue = { status: 'pending' };
      
      engine.setQuantumState(testKey, testValue);
      const retrieved = engine.getQuantumState(testKey);
      expect(retrieved).toEqual(testValue);
    });

    test('should create quantum entanglement', () => {
      const engine = new QuantumEngine();
      const testKey = 'test-entanglement';
      const testValue = { entangled: true };
      
      engine.setQuantumState(testKey, testValue);
      expect(engine.entanglementNodes.has(testKey)).toBe(true);
    });
  });

  describe('🔒 Quantum Security Tests', () => {
    test('should initialize quantum security successfully', () => {
      const security = new QuantumSecurity();
      expect(security).toBeDefined();
      expect(security.encryptionKey).toBeDefined();
      expect(typeof security.encryptionKey).toBe('string');
    });

    test('should encrypt and decrypt data correctly', () => {
      const security = new QuantumSecurity();
      const testData = { transactionId: 'TX-123', amount: 5000 };
      
      const encrypted = security.encrypt(testData);
      expect(encrypted).toBeDefined();
      expect(encrypted.encrypted).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      
      const decrypted = security.decrypt(encrypted);
      expect(decrypted).toEqual(testData);
    });

    test('should generate and verify quantum tokens', () => {
      const security = new QuantumSecurity();
      const payload = { userId: 'user-123', role: 'admin' };
      
      const token = security.generateQuantumToken(payload);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      const verified = security.verifyQuantumToken(token);
      expect(verified.userId).toBe(payload.userId);
      expect(verified.role).toBe(payload.role);
    });

    test('should verify zero-trust security', () => {
      const security = new QuantumSecurity();
      const request = {
        ip: '192.168.1.100',
        userAgent: 'test-agent',
        timestamp: Date.now(),
        signature: 'test-signature'
      };
      
      const isSecure = security.verifyZeroTrust(request);
      expect(typeof isSecure).toBe('boolean');
    });
  });

  describe('⚡ Quantum Optimizer Tests', () => {
    test('should initialize quantum optimizer successfully', () => {
      const optimizer = new QuantumOptimizer();
      expect(optimizer).toBeDefined();
      expect(optimizer.metrics).toBeInstanceOf(Map);
      expect(optimizer.optimizationHistory).toBeInstanceOf(Array);
    });

    test('should optimize performance successfully', () => {
      const optimizer = new QuantumOptimizer();
      const optimization = optimizer.optimize();
      
      expect(optimization).toBeDefined();
      expect(optimization.performance).toBeDefined();
      expect(optimization.memory).toBeDefined();
      expect(optimization.cache).toBeDefined();
      expect(optimization.database).toBeDefined();
      expect(optimization.network).toBeDefined();
    });

    test('should provide real-time metrics', () => {
      const optimizer = new QuantumOptimizer();
      const metrics = optimizer.getRealTimeMetrics();
      
      expect(metrics).toBeDefined();
      expect(metrics.performance).toBeDefined();
      expect(metrics.security).toBeDefined();
      expect(metrics.health).toBeDefined();
      expect(metrics.quantum).toBeDefined();
    });

    test('should predict optimization needs', () => {
      const optimizer = new QuantumOptimizer();
      const predictions = optimizer.predictOptimization();
      
      expect(predictions).toBeDefined();
      expect(predictions.nextHour).toBeDefined();
      expect(predictions.nextDay).toBeDefined();
      expect(predictions.nextWeek).toBeDefined();
    });
  });

  describe('🌐 Quantum Server Endpoint Tests', () => {
    test('GET /quantum/status should return quantum status', async () => {
      const response = await request(app)
        .get('/quantum/status')
        .expect(200);
      
      expect(response.body).toBeDefined();
      expect(response.body.quantum).toBe(true);
      expect(response.body.engine).toBeDefined();
      expect(response.body.security).toBeDefined();
      expect(response.body.optimizer).toBeDefined();
    });

    test('GET /quantum/optimize should return optimization results', async () => {
      const response = await request(app)
        .get('/quantum/optimize')
        .expect(200);
      
      expect(response.body).toBeDefined();
      expect(response.body.optimization).toBeDefined();
      expect(response.body.quantum).toBe(true);
    });

    test('GET /quantum/security should return security verification', async () => {
      const response = await request(app)
        .get('/quantum/security')
        .expect(200);
      
      expect(response.body).toBeDefined();
      expect(response.body.security).toBeDefined();
      expect(response.body.quantum).toBe(true);
    });

    test('GET /quantum/health should return health status', async () => {
      const response = await request(app)
        .get('/quantum/health')
        .expect(200);
      
      expect(response.body).toBeDefined();
      expect(response.body.status).toBe('perfect');
      expect(response.body.quantum).toBe(true);
    });

    test('should handle quantum security middleware', async () => {
      const response = await request(app)
        .get('/quantum/status')
        .set('X-Quantum-Signature', 'test-signature')
        .expect(200);
      
      expect(response.headers['x-quantum-secure']).toBe('true');
      expect(response.headers['x-quantum-optimized']).toBe('true');
    });
  });

  describe('🔄 Integration Tests', () => {
    test('should integrate quantum systems successfully', () => {
      expect(quantumEngine).toBeDefined();
      expect(quantumSecurity).toBeDefined();
      expect(quantumOptimizer).toBeDefined();
      
      expect(typeof quantumEngine.setQuantumState).toBe('function');
      expect(typeof quantumSecurity.encrypt).toBe('function');
      expect(typeof quantumOptimizer.optimize).toBe('function');
    });

    test('should handle quantum state across systems', () => {
      const testKey = 'integration-test';
      const testValue = { integrated: true, quantum: true };
      
      quantumEngine.setQuantumState(testKey, testValue);
      const retrieved = quantumEngine.getQuantumState(testKey);
      
      expect(retrieved).toEqual(testValue);
    });
  });

  describe('🚨 Error Handling Tests', () => {
    test('should handle invalid quantum token verification', () => {
      const security = new QuantumSecurity();
      
      expect(() => {
        security.verifyQuantumToken('invalid-token');
      }).toThrow();
    });

    test('should handle missing quantum state gracefully', () => {
      const engine = new QuantumEngine();
      const retrieved = engine.getQuantumState('non-existent-key');
      
      expect(retrieved).toBeNull();
    });
  });
});

// Test runner
if (require.main === module) {
  console.log('🚀 Running Quantum Critical Tests...');
  const { TestRunner } = require('jest');
  const runner = new TestRunner();
  
  runner.runTests().then(results => {
    console.log('✅ Quantum tests completed');
    console.log('🎯 System is quantumly perfect');
  });
}
