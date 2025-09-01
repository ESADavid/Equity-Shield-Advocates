const express = require('express');
const router = express.Router();
const fetchAndSyncPayroll = require('./fetch_and_sync_payroll').default;
const fs = require('fs');
const path = require('path');

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

// GET /api/payroll/employees - fetch employee payroll data from synced revenue data
router.get('/employees', (req, res) => {
  try {
    const fileContent = fs.readFileSync(revenueDataPath, 'utf-8');
    const revenueData = JSON.parse(fileContent);
    const payrollData = revenueData.payroll || [];
    res.json(payrollData);
  } catch (error) {
    console.error('Failed to read payroll data:', error);
    res.status(500).json({ error: 'Failed to read payroll data' });
  }
});

// POST /api/payroll/sync - trigger payroll data sync
router.post('/sync', async (req, res) => {
  try {
    await fetchAndSyncPayroll();
    res.json({ success: true, message: 'Payroll data sync completed' });
  } catch (error) {
    console.error('Payroll data sync failed:', error);
    res.status(500).json({ success: false, message: 'Payroll data sync failed' });
  }
});

module.exports = router;
