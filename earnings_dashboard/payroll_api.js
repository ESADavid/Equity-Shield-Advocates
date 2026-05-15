import { info, error, warn, debug } from 'utils/loggerWrapper.js';

/**
 * Custom logger with typed parameters
 * @param {string} msg - The log message
 * @param {Error|string} err - The error object or message
 */
const logger = {
  /**
   * Log error message with optional error details
   * @param {string} msg - The log message
   * @param {Error|string} err - The error object or message
   */
  error: (/** @type {string} */ msg, /** @type {Error|string} */ err) =>
    error(err instanceof Error ? err.message : err, err),
  /** @param {string} msg */
  info: (msg) => info(msg),
  /** @param {string} msg */
  warn: (msg) => warn(msg),
  /** @param {string} msg */
  debug: (msg) => debug(msg),
};

const express = require('express');
const router = express.Router();
const fetchAndSyncPayroll = require('./fetch_and_sync_payroll').default;
const fs = require('node:fs');
const path = require('node:path');

const revenueDataPath = path.resolve(
  __dirname,
  '../owlban_repos/sample_repo/revenue.json'
);

// GET /api/payroll/employees - fetch employee payroll data from synced revenue data
router.get('/employees', (_req, res) => {
  try {
    const fileContent = fs.readFileSync(revenueDataPath, 'utf-8');
    const revenueData = JSON.parse(fileContent);
    const payrollData = revenueData.payroll || [];
    res.json(payrollData);
  } catch (error) {
    logger.error('Failed to read payroll data:', error);
    res.status(500).json({ error: 'Failed to read payroll data' });
  }
});

// POST /api/payroll/sync - trigger payroll data sync
router.post('/sync', async (_req, res) => {
  try {
    await fetchAndSyncPayroll();
    res.json({ success: true, message: 'Payroll data sync completed' });
  } catch (error) {
    logger.error('Payroll data sync failed:', error);
    res
      .status(500)
      .json({ success: false, message: 'Payroll data sync failed' });
  }
});

module.exports = router;
