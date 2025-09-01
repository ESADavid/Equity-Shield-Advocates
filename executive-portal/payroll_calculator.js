// Payroll Calculator Functions for Executive Dashboard

// Add payroll case to loadSectionData
const originalLoadSectionData = ExecutiveDashboard.prototype.loadSectionData;
ExecutiveDashboard.prototype.loadSectionData = function(section) {
    switch (section) {
        case 'payroll':
            this.loadPayrollData();
            break;
        default:
            originalLoadSectionData.call(this, section);
    }
};

// Payroll-specific methods
ExecutiveDashboard.prototype.loadPayrollData = async function() {
    // Load employee data for the dropdown
    await this.loadEmployeeList();

    // Load recent calculations
    this.loadRecentCalculations();
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
                option.value = employee.id;
                option.textContent = `${employee.name} (${employee.position})`;
                option.dataset.employee = JSON.stringify(employee);
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading employee list:', error);
        this.showError('Failed to load employee data');
    }
};

ExecutiveDashboard.prototype.loadRecentCalculations = function() {
    // Load recent paycheck calculations from localStorage
    const recentCalculations = JSON.parse(localStorage.getItem('recentPayrollCalculations') || '[]');
    const container = document.getElementById('recentCalculationsList');

    if (container && recentCalculations.length > 0) {
        container.innerHTML = recentCalculations.slice(0, 5).map(calc => `
            <div class="calculation-item">
                <div class="calculation-info">
                    <span class="employee-name">${calc.employeeName}</span>
                    <span class="calculation-date">${Utils.formatDate(calc.date)}</span>
                </div>
                <div class="calculation-amount">${Utils.formatCurrency(calc.netPay)}</div>
            </div>
        `).join('');
    } else if (container) {
        container.innerHTML = '<p>No recent calculations</p>';
    }
};

ExecutiveDashboard.prototype.calculatePaycheck = function() {
    const hoursWorked = parseFloat(document.getElementById('hoursWorked').value) || 0;
    const hourlyRate = parseFloat(document.getElementById('hourlyRate').value) || 0;
    const overtimeHours = parseFloat(document.getElementById('overtimeHours').value) || 0;
    const taxRate = parseFloat(document.getElementById('taxRate').value) || 0;
    const deductions = parseFloat(document.getElementById('deductions').value) || 0;
    const bonuses = parseFloat(document.getElementById('bonuses').value) || 0;

    // Calculate gross pay
    const regularPay = hoursWorked * hourlyRate;
    const overtimePay = overtimeHours * hourlyRate * 1.5;
    const grossPay = regularPay + overtimePay + bonuses;

    // Calculate taxes and deductions
    const taxAmount = grossPay * (taxRate / 100);
    const netPay = grossPay - taxAmount - deductions;

    // Update results
    document.getElementById('grossPay').textContent = Utils.formatCurrency(grossPay);
    document.getElementById('taxAmount').textContent = Utils.formatCurrency(taxAmount);
    document.getElementById('deductionAmount').textContent = Utils.formatCurrency(deductions);
    document.getElementById('bonusAmount').textContent = Utils.formatCurrency(bonuses);
    document.getElementById('netPay').textContent = Utils.formatCurrency(netPay);

    // Save calculation
    this.saveCalculation({
        hoursWorked,
        hourlyRate,
        overtimeHours,
        taxRate,
        deductions,
        bonuses,
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
function syncPayrollData() {
    if (dashboard && dashboard.loadPayrollData) {
        dashboard.loadPayrollData();
        dashboard.showSuccess('Payroll data synchronized successfully');
    }
}

function openQuickBooksCalculator() {
    window.open('https://quickbooks.intuit.com/payroll/paycheck-calculator/', '_blank');
}

function loadEmployeeData() {
    if (dashboard && dashboard.loadEmployeeList) {
        dashboard.loadEmployeeList();
    }
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
