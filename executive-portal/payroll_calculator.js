// Payroll Calculator Functions for Executive Dashboard

import ExecutiveDashboard from './dashboard.js';

// Create global dashboard instance
const dashboard = new ExecutiveDashboard();

/* global dashboard */

// Utility functions
const Utils = {
    formatCurrency: (amount) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(amount);
    },

    formatDate: (date) => {
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        }).format(new Date(date));
    }
};

// Add payroll case to loadSectionData
const originalLoadSectionData = ExecutiveDashboard.prototype.loadSectionData;
ExecutiveDashboard.prototype.loadSectionData = function(section) {
    if (section === 'payroll') {
        this.loadPayrollData();
    } else {
        originalLoadSectionData.call(this, section);
    }
};

// Premium rates data from PDF (per pay period)
const premiumRates = {
    "NVIDIA HSA Plan": {
        "You Only": { exempt: 0, nonExempt: 0 },
        "You + Spouse": { exempt: 0, nonExempt: 0 },
        "You + 1 Child": { exempt: 0, nonExempt: 0 },
        "You + 2 or More Children": { exempt: 0, nonExempt: 0 },
        "You + Spouse + 1 Child": { exempt: 0, nonExempt: 0 },
        "You + Spouse + 2 or More Children": { exempt: 0, nonExempt: 0 }
    },
    "NVIDIA HSA Plus Plan": {
        "You Only": { exempt: 34.5, nonExempt: 31.85 },
        "You + Spouse": { exempt: 69.5, nonExempt: 64.15 },
        "You + 1 Child": { exempt: 57, nonExempt: 52.62 },
        "You + 2 or More Children": { exempt: 87, nonExempt: 80.31 },
        "You + Spouse + 1 Child": { exempt: 96, nonExempt: 88.62 },
        "You + Spouse + 2 or More Children": { exempt: 117.5, nonExempt: 108.46 }
    },
    "NVIDIA PPO Plan": {
        "You Only": { exempt: 55.5, nonExempt: 38.15 },
        "You + Spouse": { exempt: 174.5, nonExempt: 161.08 },
        "You + 1 Child": { exempt: 115.5, nonExempt: 139.85 },
        "You + 2 or More Children": { exempt: 218.5, nonExempt: 201.69 },
        "You + Spouse + 1 Child": { exempt: 236.5, nonExempt: 218.31 },
        "You + Spouse + 2 or More Children": { exempt: 280.5, nonExempt: 258.92 }
    },
    "Kaiser CA HSA": {
        "You Only": { exempt: 21.5, nonExempt: 19.85 },
        "You + Spouse": { exempt: 41, nonExempt: 37.85 },
        "You + 1 Child": { exempt: 34, nonExempt: 31.38 },
        "You + 2 or More Children": { exempt: 35.5, nonExempt: 32.77 },
        "You + Spouse + 1 Child": { exempt: 65.5, nonExempt: 60.45 },
        "You + Spouse + 2 or More Children": { exempt: 68, nonExempt: 52.77 }
    },
    "Kaiser CA HMO": {
        "You Only": { exempt: 44, nonExempt: 40.62 },
        "You + Spouse": { exempt: 84, nonExempt: 77.54 },
        "You + 1 Child": { exempt: 69.5, nonExempt: 64.15 },
        "You + 2 or More Children": { exempt: 73, nonExempt: 67.38 },
        "You + Spouse + 1 Child": { exempt: 138, nonExempt: 127.38 },
        "You + Spouse + 2 or More Children": { exempt: 142, nonExempt: 131.08 }
    },
    "UHA Hawaii": {
        "You Only": { exempt: 32.5, nonExempt: 57.5 },
        "You + Spouse": { exempt: 109, nonExempt: 100.62 },
        "You + 1 Child": { exempt: 108.5, nonExempt: 100.15 },
        "You + 2 or More Children": { exempt: 167, nonExempt: 154.15 },
        "You + Spouse + 1 Child": { exempt: 167, nonExempt: 154.15 },
        "You + Spouse + 2 or More Children": { exempt: 0, nonExempt: 0 }
    }
};

ExecutiveDashboard.prototype.loadPayrollData = async function() {
    // Load employee data for the dropdown
    await this.loadEmployeeList();

    // Load recent calculations
    this.loadRecentCalculations();

    // Load premium plans and coverage options
    this.loadPremiumOptions();
};

ExecutiveDashboard.prototype.loadPremiumOptions = function() {
    const planSelect = document.getElementById('medicalPlanSelect');
    const coverageSelect = document.getElementById('coverageLevelSelect');

    if (!planSelect || !coverageSelect) return;

    // Populate medical plans
    planSelect.innerHTML = '<option value="">Select Medical Plan</option>';
    for (const plan of Object.keys(premiumRates)) {
        const option = document.createElement('option');
        option.value = plan;
        option.textContent = plan;
        planSelect.appendChild(option);
    }

    // Populate coverage levels (assuming all plans have same coverage levels)
    coverageSelect.innerHTML = '<option value="">Select Coverage Level</option>';
    const coverageLevels = Object.keys(premiumRates[Object.keys(premiumRates)[0]]);
    for (const level of coverageLevels) {
        const option = document.createElement('option');
        option.value = level;
        option.textContent = level;
        coverageSelect.appendChild(option);
    }
};

ExecutiveDashboard.prototype.loadEmployeeList = async function() {
    try {
        const response = await fetch('/api/payroll/employees', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('executiveToken')
            }
        });
        if (!response.ok) {
            throw new Error('Failed to load employee data');
        }
        const employees = await response.json();
        const select = document.getElementById('employeeSelect');
        if (select) {
            select.innerHTML = '<option value="">Choose employee...</option>';
            employees.forEach(employee => {
                const option = document.createElement('option');
                option.value = employee.employeeId || employee.id || '';
                option.textContent = employee.name || 'Unknown';
                option.dataset.employee = JSON.stringify(employee);
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading employee list:', error);
        if (dashboard && dashboard.showError) {
            dashboard.showError('Failed to load employee data');
        }
    }
};

ExecutiveDashboard.prototype.loadRecentCalculations = function() {
    const recentCalculations = JSON.parse(localStorage.getItem('recentPayrollCalculations') || '[]');
    const container = document.getElementById('recentCalculations');
    if (!container) return;

    container.innerHTML = recentCalculations.map(calc => `
        <div class="calculation-item">
            <div class="employee-name">${calc.employeeName}</div>
            <div class="calculation-date">${Utils.formatDate(calc.date)}</div>
            <div class="net-pay">${Utils.formatCurrency(calc.netPay)}</div>
        </div>
    `).join('');
};

ExecutiveDashboard.prototype.calculatePaycheck = function() {
    const hoursWorked = parseFloat(document.getElementById('hoursWorked').value) || 0;
    const hourlyRate = parseFloat(document.getElementById('hourlyRate').value) || 0;
    const overtimeHours = parseFloat(document.getElementById('overtimeHours').value) || 0;
    const taxRate = parseFloat(document.getElementById('taxRate').value) || 0;
    const deductionsInput = parseFloat(document.getElementById('deductions').value) || 0;
    const bonuses = parseFloat(document.getElementById('bonuses').value) || 0;

    const planSelect = document.getElementById('medicalPlanSelect');
    const coverageSelect = document.getElementById('coverageLevelSelect');
    const isExempt = document.getElementById('exemptStatusCheckbox') ? document.getElementById('exemptStatusCheckbox').checked : false;

    let premiumDeduction = 0;
    if (planSelect && coverageSelect && planSelect.value && coverageSelect.value) {
        const plan = planSelect.value;
        const coverage = coverageSelect.value;
        const exemptionStatus = isExempt ? 'exempt' : 'nonExempt';
        premiumDeduction = premiumRates[plan][coverage][exemptionStatus] || 0;
    }

    // Calculate gross pay
    const regularPay = hoursWorked * hourlyRate;
    const overtimePay = overtimeHours * hourlyRate * 1.5;
    const grossPay = regularPay + overtimePay + bonuses;

    // Calculate taxes and deductions including premium deduction
    const taxAmount = grossPay * (taxRate / 100);
    const totalDeductions = deductionsInput + premiumDeduction;
    const netPay = grossPay - taxAmount - totalDeductions;

    // Update results
    document.getElementById('grossPay').textContent = Utils.formatCurrency(grossPay);
    document.getElementById('taxAmount').textContent = Utils.formatCurrency(taxAmount);
    document.getElementById('deductionAmount').textContent = Utils.formatCurrency(totalDeductions);
    document.getElementById('bonusAmount').textContent = Utils.formatCurrency(bonuses);
    document.getElementById('netPay').textContent = Utils.formatCurrency(netPay);
    document.getElementById('premiumDeductionAmount').textContent = Utils.formatCurrency(premiumDeduction);

    // Save calculation
    this.saveCalculation({
        hoursWorked,
        hourlyRate,
        overtimeHours,
        taxRate,
        deductions: totalDeductions,
        bonuses,
        premiumDeduction,
        grossPay,
        taxAmount,
        netPay
    });

    this.showSuccess('Paycheck calculated successfully');
};

ExecutiveDashboard.prototype.saveCalculation = function(calculation) {
    const select = document.getElementById('employeeSelect');
    const selectedOption = select.options[select.selectedIndex];

    const calculationData = {
        ...calculation,
        employeeName: selectedOption ? selectedOption.textContent : 'Unknown Employee',
        employeeId: select.value,
        date: new Date().toISOString()
    };

    // Save to localStorage
    const recentCalculations = JSON.parse(localStorage.getItem('recentPayrollCalculations') || '[]');
    recentCalculations.unshift(calculationData);

    // Keep only last 10 calculations
    if (recentCalculations.length > 10) {
        recentCalculations.splice(10);
    }

    localStorage.setItem('recentPayrollCalculations', JSON.stringify(recentCalculations));

    // Refresh recent calculations display
    this.loadRecentCalculations();
};

ExecutiveDashboard.prototype.exportPaycheck = function() {
    const netPay = document.getElementById('netPay').textContent;
    if (netPay === '$0.00') {
        this.showError('Please calculate a paycheck first');
        return;
    }

    const select = document.getElementById('employeeSelect');
    const selectedOption = select.options[select.selectedIndex];
    const employeeName = selectedOption ? selectedOption.textContent : 'Unknown Employee';

    const paycheckData = {
        employee: employeeName,
        netPay: netPay,
        date: new Date().toLocaleDateString(),
        grossPay: document.getElementById('grossPay').textContent,
        taxes: document.getElementById('taxAmount').textContent,
        deductions: document.getElementById('deductionAmount').textContent,
        bonuses: document.getElementById('bonusAmount').textContent
    };

    // Create and download text file
    const content = `
PAYCHECK SUMMARY
================
Employee: ${paycheckData.employee}
Date: ${paycheckData.date}

Gross Pay: ${paycheckData.grossPay}
Taxes: ${paycheckData.taxes}
Deductions: ${paycheckData.deductions}
Bonuses: ${paycheckData.bonuses}

Net Pay: ${paycheckData.netPay}
    `.trim();

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `paycheck_${employeeName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    this.showSuccess('Paycheck exported successfully');
};

// Global functions for payroll calculator
async function syncPayrollData() {
    try {
        const response = await fetch('/api/payroll/sync', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('executiveToken'),
                'Content-Type': 'application/json'
            }
        });
        const result = await response.json();
        if (result.success) {
            if (dashboard && dashboard.loadPayrollData) {
                await dashboard.loadPayrollData();
            }
            if (dashboard && dashboard.showSuccess) {
                dashboard.showSuccess('Payroll data synchronized successfully');
            }
        } else {
            if (dashboard && dashboard.showError) {
                dashboard.showError('Payroll data sync failed');
            }
        }
    } catch (error) {
        console.error('Error syncing payroll data:', error);
        if (dashboard && dashboard.showError) {
            dashboard.showError('Error syncing payroll data');
        }
    }
}



function openQuickBooksCalculator() {
    window.open('https://quickbooks.intuit.com/oa/payroll/?cid=ppc_YB_p_US_.Payroll_US_BNG_NonBrand_NonTop_Search_Desktop_WP._payroll%20for%20business_txt&agid=58700008023089342&infinity=ict2~net~gaw~ar~~kw~payroll%20for%20business~mt~p~cmp~Payroll_US_BNG_NonBrand_NonTop_Search_Desktop_WP~ag~Business&gclid=17e0719bf69a119d858e192dcf40dfdd&gclsrc=3p.ds&msclkid=17e0719bf69a119d858e192dcf40dfdd', '_blank');
}

function calculatePaycheck() {
    if (dashboard && dashboard.calculatePaycheck) {
        dashboard.calculatePaycheck();
    }
}

function saveCalculation() {
    if (dashboard && dashboard.saveCalculation) {
        dashboard.saveCalculation();
    }
}

function exportPaycheck() {
    if (dashboard && dashboard.exportPaycheck) {
        dashboard.exportPaycheck();
    }
}
