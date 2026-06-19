/**
 * Asset Routes
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome)
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 * This module implements proprietary encryption methods.
 * Access and use subject to OWLBAN GROUP ownership and licensing.
 */

import express from 'express';
import authMiddleware from '../utils/authMiddleware.js';
import PersonalAssetService from '../services/personalAssetService.js';

const router = express.Router();
const assetService = new PersonalAssetService();

router.use(authMiddleware);

// GET /api/assets/:citizenId - List all
router.get('/:citizenId', async (req, res) => {
  const { citizenId } = req.params;
  const result = await assetService.getAllAssets(citizenId);
  if (result.success) {
    res.json(result.assets);
  } else {
    res.status(404).json({ error: result.error });
  }
});

// POST /api/assets/:citizenId - Add new
router.post('/:citizenId', async (req, res) => {
  const { citizenId } = req.params;
  const result = await assetService.addAsset(citizenId, req.body);
  if (result.success) {
    res.status(201).json({ assetId: result.assetId });
  } else {
    res.status(400).json({ error: result.error });
  }
});

// PUT /api/assets/:citizenId/:assetId - Update
router.put('/:citizenId/:assetId', async (req, res) => {
  const { citizenId, assetId } = req.params;
  const result = await assetService.updateAsset(citizenId, assetId, req.body);
  if (result.success) {
    res.json({ success: true });
  } else {
    res.status(400).json({ error: result.error });
  }
});

// DELETE /api/assets/:citizenId/:assetId - Delete
router.delete('/:citizenId/:assetId', async (req, res) => {
  const { citizenId, assetId } = req.params;
  const result = await assetService.deleteAsset(citizenId, assetId);
  if (result.success) {
    res.json({ success: true });
  } else {
    res.status(400).json({ error: result.error });
  }
});

export default router;
