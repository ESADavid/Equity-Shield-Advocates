/**
 * Test Script for Oscar Broome Login Override System
 * Tests emergency, admin, and technical override functionality
 */

const axios = require('axios');

// Configuration
const BASE_URL = 'http://localhost:4000';
const API_BASE = `${BASE_URL}/api/override`;

// Test credentials
const TEST_USERS = {
    emergency: {
        userId: 'oscar.broome@oscarsystem.com',
        emergencyCode: 'OSCAR_BROOME_EMERGENCY_2024'
    },
    admin: {
        adminUserId: 'admin@oscarsystem.com',
        targetUserId: 'test.user@oscarsystem.com'
    },
    technical: {
        supportUserId: 'support@oscarsystem.com',
        targetUserId: 'test.user@oscarsystem.com',
        ticketNumber: 'TECH-1234'
    }
};

// Test functions
async function testEmergencyOverride() {
    console.log('\n=== Testing Emergency Override ===');

    try {
        const response = await axios.post(`${API_BASE}/emergency`, {
            userId: TEST_USERS.emergency.userId,
            reason: 'emergency_access',
            emergencyCode: TEST_USERS.emergency.emergencyCode
        });

        console.log('✅ Emergency Override Success:', response.data);
        return response.data.data.overrideId;
    } catch (error) {
        console.log('❌ Emergency Override Failed:', error.response?.data || error.message);
        return null;
    }
}

async function testAdminOverride() {
    console.log('\n=== Testing Admin Override ===');

    try {
        const response = await axios.post(`${API_BASE}/admin`, {
            adminUserId: TEST_USERS.admin.adminUserId,
            targetUserId: TEST_USERS.admin.targetUserId,
            reason: 'account_locked',
            justification: 'User account locked due to security policy. Administrative override required for immediate access.'
        });

        console.log('✅ Admin Override Success:', response.data);
        return response.data.data.overrideId;
    } catch (error) {
        console.log('❌ Admin Override Failed:', error.response?.data || error.message);
        return null;
    }
}

async function testTechnicalOverride() {
    console.log('\n=== Testing Technical Support Override ===');

    try {
        const response = await axios.post(`${API_BASE}/technical`, {
            supportUserId: TEST_USERS.technical.supportUserId,
            targetUserId: TEST_USERS.technical.targetUserId,
            reason: 'mfa_failure',
            ticketNumber: TEST_USERS.technical.ticketNumber
        });

        console.log('✅ Technical Override Success:', response.data);
        return response.data.data.overrideId;
    } catch (error) {
        console.log('❌ Technical Override Failed:', error.response?.data || error.message);
        return null;
    }
}

async function testOverrideValidation(overrideId) {
    console.log('\n=== Testing Override Validation ===');

    try {
        const response = await axios.post(`${API_BASE}/validate/${overrideId}`, {
            userId: TEST_USERS.emergency.userId
        });

        console.log('✅ Override Validation Success:', response.data);
        return true;
    } catch (error) {
        console.log('❌ Override Validation Failed:', error.response?.data || error.message);
        return false;
    }
}

async function testOverrideStats() {
    console.log('\n=== Testing Override Statistics ===');

    try {
        const response = await axios.get(`${API_BASE}/stats`);

        console.log('✅ Override Stats Success:', response.data);
        return true;
    } catch (error) {
        console.log('❌ Override Stats Failed:', error.response?.data || error.message);
        return false;
    }
}

async function testHealthCheck() {
    console.log('\n=== Testing Health Check ===');

    try {
        const response = await axios.get(`${API_BASE}/health`);

        console.log('✅ Health Check Success:', response.data);
        return true;
    } catch (error) {
        console.log('❌ Health Check Failed:', error.response?.data || error.message);
        return false;
    }
}

async function testInvalidEmergencyCode() {
    console.log('\n=== Testing Invalid Emergency Code ===');

    try {
        await axios.post(`${API_BASE}/emergency`, {
            userId: TEST_USERS.emergency.userId,
            reason: 'emergency_access',
            emergencyCode: 'INVALID_CODE'
        });

        console.log('❌ Invalid Code Test Failed: Should have been rejected');
        return false;
    } catch (error) {
        if (error.response?.status === 403) {
            console.log('✅ Invalid Code Test Success: Correctly rejected');
            return true;
        } else {
            console.log('❌ Invalid Code Test Failed:', error.response?.data || error.message);
            return false;
        }
    }
}

async function testMissingJustification() {
    console.log('\n=== Testing Missing Admin Justification ===');

    try {
        await axios.post(`${API_BASE}/admin`, {
            adminUserId: TEST_USERS.admin.adminUserId,
            targetUserId: TEST_USERS.admin.targetUserId,
            reason: 'account_locked'
            // Missing justification
        });

        console.log('❌ Missing Justification Test Failed: Should have been rejected');
        return false;
    } catch (error) {
        if (error.response?.status === 400) {
            console.log('✅ Missing Justification Test Success: Correctly rejected');
            return true;
        } else {
            console.log('❌ Missing Justification Test Failed:', error.response?.data || error.message);
            return false;
        }
    }
}

async function testInvalidTicketNumber() {
    console.log('\n=== Testing Invalid Ticket Number ===');

    try {
        await axios.post(`${API_BASE}/technical`, {
            supportUserId: TEST_USERS.technical.supportUserId,
            targetUserId: TEST_USERS.technical.targetUserId,
            reason: 'mfa_failure',
            ticketNumber: 'INVALID-123'
        });

        console.log('❌ Invalid Ticket Test Failed: Should have been rejected');
        return false;
    } catch (error) {
        if (error.response?.status === 400) {
            console.log('✅ Invalid Ticket Test Success: Correctly rejected');
            return true;
        } else {
            console.log('❌ Invalid Ticket Test Failed:', error.response?.data || error.message);
            return false;
        }
    }
}

// Main test runner
async function runTests() {
    console.log('🚀 Starting Oscar Broome Login Override System Tests');
    console.log('=' .repeat(60));

    const results = {
        passed: 0,
        failed: 0,
        total: 0
    };

    function recordResult(success, testName) {
        results.total++;
        if (success) {
            results.passed++;
            console.log(`✅ ${testName}: PASSED`);
        } else {
            results.failed++;
            console.log(`❌ ${testName}: FAILED`);
        }
    }

    // Test health check first
    const healthOk = await testHealthCheck();
    recordResult(healthOk, 'Health Check');

    if (!healthOk) {
        console.log('\n❌ Server is not running or override system is not healthy. Aborting tests.');
        return;
    }

    // Test successful overrides
    const emergencyId = await testEmergencyOverride();
    recordResult(emergencyId !== null, 'Emergency Override');

    const adminId = await testAdminOverride();
    recordResult(adminId !== null, 'Admin Override');

    const technicalId = await testTechnicalOverride();
    recordResult(technicalId !== null, 'Technical Override');

    // Test validation if we have override IDs
    if (emergencyId) {
        const validationOk = await testOverrideValidation(emergencyId);
        recordResult(validationOk, 'Override Validation');
    }

    // Test statistics
    const statsOk = await testOverrideStats();
    recordResult(statsOk, 'Override Statistics');

    // Test error cases
    const invalidCodeOk = await testInvalidEmergencyCode();
    recordResult(invalidCodeOk, 'Invalid Emergency Code Rejection');

    const missingJustificationOk = await testMissingJustification();
    recordResult(missingJustificationOk, 'Missing Justification Rejection');

    const invalidTicketOk = await testInvalidTicketNumber();
    recordResult(invalidTicketOk, 'Invalid Ticket Number Rejection');

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total Tests: ${results.total}`);
    console.log(`Passed: ${results.passed}`);
    console.log(`Failed: ${results.failed}`);
    console.log(`Success Rate: ${((results.passed / results.total) * 100).toFixed(1)}%`);

    if (results.failed === 0) {
        console.log('\n🎉 All tests passed! Login Override System is working correctly.');
    } else {
        console.log(`\n⚠️  ${results.failed} test(s) failed. Please check the implementation.`);
    }

    console.log('\n🔗 Override Dashboard: http://localhost:4000/override-dashboard');
    console.log('🔗 API Documentation: Check routes/login_override_routes.js for available endpoints');
}

// Run tests if this script is executed directly
if (require.main === module) {
    runTests().catch(error => {
        console.error('Test runner failed:', error);
        process.exit(1);
    });
}

module.exports = {
    testEmergencyOverride,
    testAdminOverride,
    testTechnicalOverride,
    testOverrideValidation,
    testOverrideStats,
    testHealthCheck,
    testInvalidEmergencyCode,
    testMissingJustification,
    testInvalidTicketNumber,
    runTests
};
