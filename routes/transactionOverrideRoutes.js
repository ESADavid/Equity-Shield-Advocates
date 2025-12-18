/**
 * Transaction Override API Routes
 * RESTful endpoints for transaction override operations
 */

import express from 'express';
const router = express.Router();
import TransactionOverride from '../models/TransactionOverride.js';
import { authorizeOverride, auditOverride } from '../middleware/authOverride.js';

// GET /api/transactions/overrides - List all override requests
router.get('/overrides', authorizeOverride(['admin', 'override_manager']), (req, res) => {
  try {
    // In production, this would query a database
    const overrides = []; // Mock data - replace with actual database query
    
    res.json({
      success: true,
      data: overrides,
      count: overrides.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve override requests',
      message: error.message
    });
  }
});

// POST /api/transactions/override - Create new override request
router.post('/override', authorizeOverride(['admin', 'override_manager']), (req, res) => {
  try {
    const {
      originalTransactionId,
      transactionType,
      overrideType,
      originalValue,
      newValue,
      reason
    } = req.body;

    // Validate required fields
    if (!originalTransactionId || !transactionType || !overrideType || !reason) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        required: ['originalTransactionId', 'transactionType', 'overrideType', 'reason']
      });
    }

    // Create new override request
    const override = new TransactionOverride({
      originalTransactionId,
      transactionType,
      overrideType,
      originalValue,
      newValue,
      reason,
      requestedBy: req.overrideUser.username
    });

    // In production, save to database
    logger.info('New override request:', override.toJSON());

    res.json({
      success: true,
      data: override.toJSON(),
      message: 'Override request created successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to create override request',
      message: error.message
    });
  }
});

// PUT /api/transactions/:id/override - Update existing transaction
router.put('/:id/override', authorizeOverride(['admin']), (req, res) => {
  try {
    const { id } = req.params;
    const { newValue, reason } = req.body;

    // In production, update transaction in database
    logger.info(`Updating transaction ${id} with override:`, { newValue, reason });

    res.json({
      success: true,
      message: 'Transaction updated successfully',
      transactionId: id,
      updatedBy: req.overrideUser.username
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update transaction',
      message: error.message
    });
  }
});

// DELETE /api/transactions/:id/override - Reject override request
router.delete('/:id/override', authorizeOverride(['admin']), (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    // In production, update override status in database
    logger.info(`Rejecting override ${id}:`, reason);

    res.json({
      success: true,
      message: 'Override request rejected',
      overrideId: id,
      rejectedBy: req.overrideUser.username
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to reject override',
      message: error.message
    });
  }
});

// GET /api/transactions/:id/audit - Get transaction audit trail
router.get('/:id/audit', authorizeOverride(['admin', 'override_manager']), async (req, res) => {
  try {
    const { id } = req.params;

    // Import blockchain service dynamically to avoid circular dependencies
    const { getBlockchainService } = await import('../blockchain/blockchainService.js');
    const blockchainService = getBlockchainService();

    const auditResult = await blockchainService.getAuditTrail(id);

    if (!auditResult.success) {
      return res.status(404).json({
        success: false,
        message: 'Transaction audit trail not found in blockchain'
      });
    }

    res.json({
      success: true,
      data: {
        transactionId: id,
        auditTrail: auditResult.auditTrail,
        verification: auditResult.verificationStatus
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve audit trail',
      message: error.message
    });
  }
});

export default router;
