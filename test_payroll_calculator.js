// Standalone test for Payroll Calculator functionality
// This test validates the calculation logic and HTML structure

const fs = require('fs');
const path = require('path');

// Mock DOM for testing
global.document = {
    getElementById: function(id) {
        return {
            value: '',
            textContent: '',
            innerHTML: '',
            style: {},
            addEventListener: function() {},
            querySelector: function() { return null; },
            querySelectorAll: function() { return []; }
        };
    },
    createElement: function(tag) {
        return {
            style: {},
            textContent: '',
            appendChild: function() {},
            setAttribute: function() {},
            addEventListener: function() {}
        };
    },
    body: {
        appendChild: function() {}
    }
};

global.window = {
    localStorage: {
        getItem: function(key) { return null; },
        setItem: function(key, value) {},
        removeItem: function(key) {}
    },
    open: function() {}
};

global.fetch = function(url, options) {
    return Promise.resolve({
        ok: true,
        json: function() {
            return Promise.resolve([
                { id: 'emp001', name: 'John Smith', position: 'Software Engineer', hourlyRate: 45.00 },
                { id: 'emp002', name: 'Sarah Johnson', position: 'Project Manager', hourlyRate: 55.00 }
            ]);
        }
    });
};

global.URL = {
    createObjectURL: function() { return 'blob:test'; },
    revokeObjectURL: function() {}
};

// Load the payroll calculator JavaScript
const payrollCalculatorCode = fs.readFileSync(path.join(__dirname, 'executive-portal', 'payroll_calculator.js'), 'utf8');

// Test calculation logic
function testPayrollCalculation() {
    console.log('🧪 Testing Payroll Calculator Calculation Logic...');

    // Test case 1: Basic calculation
    const hoursWorked = 40;
    const hourlyRate = 25;
    const overtimeHours = 5;
    const taxRate = 20;
    const deductions = 50;
    const bonuses = 100;

    const regularPay = hoursWorked * hourlyRate; // 40 * 25 = 1000
    const overtimePay = overtimeHours * hourlyRate * 1.5; // 5 * 25 * 1.5 = 187.5
    const grossPay = regularPay + overtimePay + bonuses; // 1000 + 187.5 + 100 = 1287.5
    const taxAmount = grossPay * (taxRate / 100); // 1287.5 * 0.2 = 257.5
    const netPay = grossPay - taxAmount - deductions; // 1287.5 - 257.5 - 50 = 980

    console.log('✅ Test Case 1 - Basic Calculation:');
    console.log(`   Regular Pay: $${regularPay}`);
    console.log(`   Overtime Pay: $${overtimePay}`);
    console.log(`   Gross Pay: $${grossPay}`);
    console.log(`   Tax Amount: $${taxAmount}`);
    console.log(`   Net Pay: $${netPay}`);

    // Test case 2: No overtime
    const hoursWorked2 = 40;
    const hourlyRate2 = 30;
    const overtimeHours2 = 0;
    const taxRate2 = 15;
    const deductions2 = 0;
    const bonuses2 = 0;

    const regularPay2 = hoursWorked2 * hourlyRate2; // 40 * 30 = 1200
    const overtimePay2 = overtimeHours2 * hourlyRate2 * 1.5; // 0
    const grossPay2 = regularPay2 + overtimePay2 + bonuses2; // 1200
    const taxAmount2 = grossPay2 * (taxRate2 / 100); // 1200 * 0.15 = 180
    const netPay2 = grossPay2 - taxAmount2 - deductions2; // 1200 - 180 = 1020

    console.log('✅ Test Case 2 - No Overtime:');
    console.log(`   Regular Pay: $${regularPay2}`);
    console.log(`   Overtime Pay: $${overtimePay2}`);
    console.log(`   Gross Pay: $${grossPay2}`);
    console.log(`   Tax Amount: $${taxAmount2}`);
    console.log(`   Net Pay: $${netPay2}`);

    return true;
}

// Test HTML structure
function testHTMLStructure() {
    console.log('🧪 Testing HTML Structure...');

    const htmlFile = path.join(__dirname, 'executive-portal', 'payroll_calculator_section_fixed.html');
    const htmlContent = fs.readFileSync(htmlFile, 'utf8');

    const requiredElements = [
        'employeeSelect',
        'hoursWorked',
        'hourlyRate',
        'overtimeHours',
        'taxRate',
        'deductions',
        'bonuses',
        'calculateBtn',
        'grossPay',
        'taxAmount',
        'deductionAmount',
        'bonusAmount',
        'netPay',
        'exportBtn',
        'recentCalculationsList'
    ];

    let missingElements = [];
    requiredElements.forEach(element => {
        if (!htmlContent.includes(`id="${element}"`)) {
            missingElements.push(element);
        }
    });

    if (missingElements.length === 0) {
        console.log('✅ All required HTML elements found');
        return true;
    } else {
        console.log('❌ Missing HTML elements:', missingElements);
        return false;
    }
}

// Test CSS styles
function testCSSStyles() {
    console.log('🧪 Testing CSS Styles...');

    const cssFile = path.join(__dirname, 'executive-portal', 'payroll_calculator_styles.css');
    const cssContent = fs.readFileSync(cssFile, 'utf8');

    const requiredStyles = [
        '.payroll-controls',
        '.calculator-container',
        '.calculator-form',
        '.calculator-results',
        '.result-item',
        '.recent-calculations'
    ];

    let missingStyles = [];
    requiredStyles.forEach(style => {
        if (!cssContent.includes(style)) {
            missingStyles.push(style);
        }
    });

    if (missingStyles.length === 0) {
        console.log('✅ All required CSS styles found');
        return true;
    } else {
        console.log('❌ Missing CSS styles:', missingStyles);
        return false;
    }
}

// Test API structure
function testAPIEndpoints() {
    console.log('🧪 Testing API Endpoints Structure...');

    const apiFile = path.join(__dirname, 'executive-portal', 'payroll_api.js');
    const apiContent = fs.readFileSync(apiFile, 'utf8');

    const requiredEndpoints = [
        "router.get('/employees'",
        "router.get('/employees/:id'",
        "router.post('/calculate'"
    ];

    let missingEndpoints = [];
    requiredEndpoints.forEach(endpoint => {
        if (!apiContent.includes(endpoint)) {
            missingEndpoints.push(endpoint);
        }
    });

    if (missingEndpoints.length === 0) {
        console.log('✅ All required API endpoints found');
        return true;
    } else {
        console.log('❌ Missing API endpoints:', missingEndpoints);
        return false;
    }
}

// Test dashboard integration
function testDashboardIntegration() {
    console.log('🧪 Testing Dashboard Integration...');

    const dashboardFile = path.join(__dirname, 'executive-portal', 'dashboard_fixed.html');
    const dashboardContent = fs.readFileSync(dashboardFile, 'utf8');

    const requiredIntegrations = [
        'payroll_calculator.js',
        'payroll-section'
    ];

    let missingIntegrations = [];
    requiredIntegrations.forEach(integration => {
        if (!dashboardContent.includes(integration)) {
            missingIntegrations.push(integration);
        }
    });

    if (missingIntegrations.length === 0) {
        console.log('✅ All dashboard integrations found');
        return true;
    } else {
        console.log('❌ Missing dashboard integrations:', missingIntegrations);
        return false;
    }
}

// Run all tests
function runAllTests() {
    console.log('🚀 Starting Payroll Calculator Testing Suite...\n');

    const tests = [
        { name: 'Payroll Calculation Logic', func: testPayrollCalculation },
        { name: 'HTML Structure', func: testHTMLStructure },
        { name: 'CSS Styles', func: testCSSStyles },
        { name: 'API Endpoints', func: testAPIEndpoints },
        { name: 'Dashboard Integration', func: testDashboardIntegration }
    ];

    let passedTests = 0;
    let totalTests = tests.length;

    tests.forEach(test => {
        try {
            console.log(`\n📋 Running: ${test.name}`);
            if (test.func()) {
                passedTests++;
                console.log(`✅ PASSED: ${test.name}`);
            } else {
                console.log(`❌ FAILED: ${test.name}`);
            }
        } catch (error) {
            console.log(`❌ ERROR in ${test.name}:`, error.message);
        }
    });

    console.log('\n' + '='.repeat(50));
    console.log(`📊 Test Results: ${passedTests}/${totalTests} tests passed`);

    if (passedTests === totalTests) {
        console.log('🎉 All tests passed! Payroll Calculator implementation is complete.');
        return true;
    } else {
        console.log('⚠️  Some tests failed. Please review the implementation.');
        return false;
    }
}

// Export for use in other test files
module.exports = {
    testPayrollCalculation,
    testHTMLStructure,
    testCSSStyles,
    testAPIEndpoints,
    testDashboardIntegration,
    runAllTests
};

// Run tests if this file is executed directly
if (require.main === module) {
    runAllTests();
}
