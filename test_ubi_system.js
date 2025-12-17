/**
 * UNIVERSAL BASIC INCOME SYSTEM TEST
 * Comprehensive testing for UBI citizen registration and payment processing
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import UniversalBasicIncomeService from './services/universalBasicIncomeService.js';

const ubiService = new UniversalBasicIncomeService();

// Test data
const testCitizens = [
  {
    personalInfo: {
      firstName: 'Jean',
      lastName: 'Baptiste',
      middleName: 'Pierre',
      dateOfBirth: new Date('1985-03-15'),
      gender: 'male',
      nationalId: 'HT-1985-001234',
      biometricHash: 'bio_hash_001234567890abcdef',
      photograph: 'data:image/jpeg;base64,/9j/4AAQSkZJRg...'
    },
    contactInfo: {
      address: {
        street: '123 Rue de la Liberté',
        city: 'Port-au-Prince',
        department: 'Ouest',
        postalCode: 'HT6110',
        country: 'Haiti',
        coordinates: {
          latitude: 18.5944,
          longitude: -72.3074
        }
      },
      phone: '+509-1234-5678',
      email: 'jean.baptiste@example.ht',
      emergencyContact: {
        name: 'Marie Baptiste',
        relationship: 'spouse',
        phone: '+509-1234-5679'
      }
    },
    bankingInfo: {
      accountNumber: '1234567890',
      routingNumber: '021000021',
      bankName: 'Banque Nationale de Crédit',
      accountType: 'checking'
    }
  },
  {
    personalInfo: {
      firstName: 'Marie',
      lastName: 'Dupont',
      dateOfBirth: new Date('1990-07-22'),
      gender: 'female',
      nationalId: 'HT-1990-005678',
      biometricHash: 'bio_hash_005678901234abcdef'
    },
    contactInfo: {
      address: {
        street: '456 Avenue Jean-Jacques Dessalines',
        city: 'Cap-Haïtien',
        department: 'Nord',
        postalCode: 'HT1110',
        country: 'Haiti'
      },
      phone: '+509-2345-6789',
      email: 'marie.dupont@example.ht'
    },
    bankingInfo: {
      accountNumber: '0987654321',
      routingNumber: '021000021',
      bankName: 'Unibank',
      accountType: 'savings'
    }
  },
  {
    personalInfo: {
      firstName: 'Pierre',
      lastName: 'Louis',
      dateOfBirth: new Date('1978-11-30'),
      gender: 'male',
      nationalId: 'HT-1978-009012',
      biometricHash: 'bio_hash_009012345678abcdef'
    },
    contactInfo: {
      address: {
        street: '789 Rue Capois',
        city: 'Gonaïves',
        department: 'Artibonite',
        postalCode: 'HT4110',
        country: 'Haiti'
      },
      phone: '+509-3456-7890',
      email: 'pierre.louis@example.ht'
    },
    bankingInfo: {
      accountNumber: '1122334455',
      routingNumber: '021000021',
      bankName: 'Sogebank',
      accountType: 'checking'
    }
  }
];

/**
 * Run comprehensive UBI system tests
 */
async function runUBITests() {
  console.log('\n' + '='.repeat(80));
  console.log('UNIVERSAL BASIC INCOME SYSTEM - COMPREHENSIVE TEST');
  console.log('OWLBAN GROUP - Heaven on Earth Initiative');
  console.log('='.repeat(80) + '\n');

  const results = {
    totalTests: 0,
    passed: 0,
    failed: 0,
    tests: []
  };

  // Test 1: Service Health Check
  await runTest(results, 'Service Health Check', async () => {
    const health = ubiService.getHealthStatus();
    
    if (health.status !== 'operational') {
      throw new Error('Service is not operational');
    }
    
    return {
      status: health.status,
      amounts: health.amounts
    };
  });

  // Test 2: Register First Citizen
  let citizen1Id;
  await runTest(results, 'Register First Citizen (Jean Baptiste)', async () => {
    const result = await ubiService.registerCitizen(testCitizens[0], 'test-admin-001');
    
    if (!result.success) {
      throw new Error(result.error || 'Registration failed');
    }
    
    citizen1Id = result.citizen.citizenId;
    
    return {
      citizenId: citizen1Id,
      fullName: result.citizen.fullName,
      nationalId: result.citizen.nationalId,
      ubiAmount: result.citizen.ubiStatus.annualAmount
    };
  });

  // Test 3: Register Second Citizen
  let citizen2Id;
  await runTest(results, 'Register Second Citizen (Marie Dupont)', async () => {
    const result = await ubiService.registerCitizen(testCitizens[1], 'test-admin-001');
    
    if (!result.success) {
      throw new Error(result.error || 'Registration failed');
    }
    
    citizen2Id = result.citizen.citizenId;
    
    return {
      citizenId: citizen2Id,
      fullName: result.citizen.fullName,
      ubiAmount: result.citizen.ubiStatus.annualAmount
    };
  });

  // Test 4: Register Third Citizen
  let citizen3Id;
  await runTest(results, 'Register Third Citizen (Pierre Louis)', async () => {
    const result = await ubiService.registerCitizen(testCitizens[2], 'test-admin-001');
    
    if (!result.success) {
      throw new Error(result.error || 'Registration failed');
    }
    
    citizen3Id = result.citizen.citizenId;
    
    return {
      citizenId: citizen3Id,
      fullName: result.citizen.fullName
    };
  });

  // Test 5: Prevent Duplicate Registration
  await runTest(results, 'Prevent Duplicate Registration', async () => {
    const result = await ubiService.registerCitizen(testCitizens[0], 'test-admin-001');
    
    if (result.success) {
      throw new Error('Duplicate registration should have been prevented');
    }
    
    return {
      prevented: true,
      error: result.error
    };
  });

  // Test 6: Get Citizen UBI Status
  await runTest(results, 'Get Citizen UBI Status', async () => {
    if (!citizen1Id) throw new Error('Citizen 1 not registered');
    
    const result = await ubiService.getCitizenUBIStatus(citizen1Id);
    
    if (!result.success) {
      throw new Error(result.error || 'Failed to get UBI status');
    }
    
    return {
      citizenId: result.citizen.citizenId,
      eligible: result.eligibility.eligible,
      monthlyAmount: result.ubiStatus.monthlyAmount,
      annualAmount: result.ubiStatus.annualAmount,
      educationProgress: result.educationStatus.overallProgress
    };
  });

  // Test 7: Check UBI Eligibility
  await runTest(results, 'Check UBI Eligibility', async () => {
    if (!citizen1Id) throw new Error('Citizen 1 not registered');
    
    const result = await ubiService.getCitizenUBIStatus(citizen1Id);
    
    if (!result.success) {
      throw new Error('Failed to check eligibility');
    }
    
    return {
      eligible: result.eligibility.eligible,
      reason: result.eligibility.reason,
      complianceStatus: result.educationStatus.complianceStatus
    };
  });

  // Test 8: Suspend UBI Payments
  await runTest(results, 'Suspend UBI Payments', async () => {
    if (!citizen2Id) throw new Error('Citizen 2 not registered');
    
    const result = await ubiService.suspendUBI(
      citizen2Id,
      'Test suspension - education non-compliance',
      'test-admin-001'
    );
    
    if (!result.success) {
      throw new Error(result.error || 'Suspension failed');
    }
    
    return {
      citizenId: result.citizenId,
      suspended: true,
      reason: result.suspensionReason,
      gracePeriodEnd: result.gracePeriodEnd
    };
  });

  // Test 9: Verify Suspension
  await runTest(results, 'Verify Suspension', async () => {
    if (!citizen2Id) throw new Error('Citizen 2 not registered');
    
    const result = await ubiService.getCitizenUBIStatus(citizen2Id);
    
    if (!result.success) {
      throw new Error('Failed to get status');
    }
    
    if (!result.ubiStatus.suspended) {
      throw new Error('Citizen should be suspended');
    }
    
    return {
      suspended: result.ubiStatus.suspended,
      reason: result.ubiStatus.suspensionReason
    };
  });

  // Test 10: Reinstate UBI Payments
  await runTest(results, 'Reinstate UBI Payments', async () => {
    if (!citizen2Id) throw new Error('Citizen 2 not registered');
    
    const result = await ubiService.reinstateUBI(citizen2Id, 'test-admin-001');
    
    if (!result.success) {
      throw new Error(result.error || 'Reinstatement failed');
    }
    
    return {
      citizenId: result.citizenId,
      reinstated: true
    };
  });

  // Test 11: Process Monthly Payments (Simulated)
  await runTest(results, 'Process Monthly Payments', async () => {
    const result = await ubiService.processMonthlyPayments('test-admin-001');
    
    if (!result.success) {
      throw new Error(result.error || 'Payment processing failed');
    }
    
    return {
      totalProcessed: result.summary.totalProcessed,
      successful: result.summary.successful,
      failed: result.summary.failed,
      totalAmount: result.summary.totalAmount,
      duration: result.summary.duration
    };
  });

  // Test 12: Get System Statistics
  await runTest(results, 'Get System Statistics', async () => {
    const result = await ubiService.getSystemStatistics();
    
    if (!result.success) {
      throw new Error(result.error || 'Failed to get statistics');
    }
    
    return {
      totalCitizens: result.statistics.citizens.total,
      eligibleCitizens: result.statistics.citizens.eligible,
      monthlyBudget: result.statistics.payments.monthlyBudget,
      annualBudget: result.statistics.payments.annualBudget
    };
  });

  // Test 13: Validate Citizen Data
  await runTest(results, 'Validate Citizen Data', async () => {
    const invalidData = {
      personalInfo: {
        firstName: 'Test'
        // Missing required fields
      }
    };
    
    const validation = ubiService.validateCitizenData(invalidData);
    
    if (validation.valid) {
      throw new Error('Invalid data should not pass validation');
    }
    
    return {
      valid: validation.valid,
      errorCount: validation.errors.length,
      errors: validation.errors
    };
  });

  // Print Summary
  console.log('\n' + '='.repeat(80));
  console.log('TEST SUMMARY');
  console.log('='.repeat(80));
  console.log(`Total Tests: ${results.totalTests}`);
  console.log(`Passed: ${results.passed} ✓`);
  console.log(`Failed: ${results.failed} ✗`);
  console.log(`Success Rate: ${((results.passed / results.totalTests) * 100).toFixed(2)}%`);
  console.log('='.repeat(80) + '\n');

  // Print Failed Tests
  if (results.failed > 0) {
    console.log('FAILED TESTS:');
    console.log('-'.repeat(80));
    results.tests
      .filter(t => !t.passed)
      .forEach(t => {
        console.log(`❌ ${t.name}`);
        console.log(`   Error: ${t.error}`);
      });
    console.log('='.repeat(80) + '\n');
  }

  return results;
}

/**
 * Helper function to run individual tests
 */
async function runTest(results, testName, testFn) {
  results.totalTests++;
  
  console.log(`\nTest ${results.totalTests}: ${testName}`);
  console.log('-'.repeat(80));
  
  try {
    const result = await testFn();
    results.passed++;
    
    console.log('✓ PASSED');
    console.log('Result:', JSON.stringify(result, null, 2));
    
    results.tests.push({
      name: testName,
      passed: true,
      result: result
    });
  } catch (error) {
    results.failed++;
    
    console.log('✗ FAILED');
    console.log('Error:', error.message);
    
    results.tests.push({
      name: testName,
      passed: false,
      error: error.message
    });
  }
}

// Run tests if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runUBITests()
    .then(results => {
      process.exit(results.failed > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('Fatal error running tests:', error);
      process.exit(1);
    });
}

export { runUBITests };
