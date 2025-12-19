/**
 * COMPLIANCE MONITORING INTEGRATION TEST
 * Tests compliance monitoring system integration
 */

import ComplianceMonitoringService from '../../services/complianceMonitoringService.js';

describe('Compliance Monitoring Integration', () => {
  let complianceService;

  beforeAll(() => {
    complianceService = new ComplianceMonitoringService();
  });

  test('should perform GDPR compliance check', async () => {
    const result = await complianceService.checkGDPRCompliance({
      dataProcessing: true,
      userConsent: true,
      dataRetention: true,
      rightToErasure: true
    });

    expect(result.success).toBe(true);
    expect(result.compliant).toBe(true);
  });

  test('should perform PCI-DSS compliance check', async () => {
    const result = await complianceService.checkPCIDSSCompliance({
      encryption: true,
      accessControl: true,
      monitoring: true,
      testing: true
    });

    expect(result.success).toBe(true);
  });

  test('should generate compliance report', async () => {
    const result = await complianceService.generateComplianceReport('monthly');
    expect(result.success).toBe(true);
    expect(result.report).toBeDefined();
  });

  test('should calculate risk level', () => {
    const result = complianceService.calculateRiskLevel({
      gdprCompliant: true,
      pciCompliant: true,
      iso27001Compliant: true,
      recentViolations: 0
    });

    expect(result.success).toBe(true);
    expect(result.riskLevel).toBe('low');
  });
});
