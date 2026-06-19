import { describe, it, expect, beforeEach } from 'vitest';
import { QuantumSecurity } from '../quantum/quantumSecurityCommonJS.js';

describe('QuantumSecurity Class', () => {
  let quantumSecurity;

  beforeEach(() => {
    quantumSecurity = new QuantumSecurity();
  });

  it('should initialize static fields correctly', () => {
    expect(quantumSecurity.algorithm).toBe('CRYSTALS-Dilithium-3');
    expect(quantumSecurity.securityMatrix).toBeDefined();
    expect(quantumSecurity.securityMatrix.layers).toContain('quantum');
    expect(quantumSecurity.securityMatrix.protocols).toContain('FIDO2');
  });

  it('should generate encryption key on instantiation', () => {
    expect(quantumSecurity.encryptionKey).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should generate JWT key on instantiation', () => {
    expect(quantumSecurity.jwtKey).toMatch(/^[a-f0-9]{128}$/);
  });

  it('should encrypt and decrypt data correctly', () => {
    const payload = { message: 'hello quantum' };
    const encrypted = quantumSecurity.encrypt(payload);
    expect(encrypted).toHaveProperty('encrypted');
    expect(encrypted).toHaveProperty('authTag');
    expect(encrypted).toHaveProperty('iv');
    expect(encrypted.algorithm).toBe(quantumSecurity.algorithm);

    const decrypted = quantumSecurity.decrypt(encrypted);
    expect(decrypted).toEqual(payload);
  });

  it('should generate and verify JWT tokens', () => {
    const payload = { user: 'quantum-user' };
    const token = quantumSecurity.generateQuantumToken(payload);
    expect(typeof token).toBe('string');

    const verifiedPayload = quantumSecurity.verifyQuantumToken(token);
    expect(verifiedPayload.user).toBe('quantum-user');
  });

  it('should verify zero trust and quantum signatures', () => {
    const data = { important: 'data' };
    const signature = quantumSecurity.generateQuantumSignature(data);
    expect(quantumSecurity.verifyQuantumSignature(data, signature)).toBe(true);

    const request = {
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      timestamp: Date.now(),
      data,
      signature,
      blockchain: {},
    };
    expect(quantumSecurity.verifyZeroTrust(request)).toBe(true);
  });

  it('should return true for blockchain integrity', () => {
    expect(quantumSecurity.verifyBlockchainIntegrity({})).toBe(true);
  });

  it('should detect no anomalies in quantum or behavioral', () => {
    const request = {};
    const anomalies = quantumSecurity.detectIntrusion(request);
    expect(Array.isArray(anomalies)).toBe(true);
    expect(anomalies.length).toBe(0);
  });

  it('should return correct security metrics', () => {
    const metrics = quantumSecurity.getSecurityMetrics();
    expect(metrics.quantumSafe).toBe(true);
    expect(metrics.encryptionStrength).toBe('256-bit');
  });
});
