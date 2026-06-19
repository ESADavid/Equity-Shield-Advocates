/**
 * Education Routes - Heaven on Earth Phase 2
 * Mandatory education management and compliance
 */

import express from 'express';
import { info, error } from '../utils/loggerWrapper.js';
import { authenticateToken } from '../utils/authMiddleware.js';
import EducationService from '../services/educationService.js';

const router = express.Router();

// Welcome endpoint
router.get('/welcome', (req, res) => {
  res.json({
    message: 'Education System - Heaven on Earth',
    mission: 'Mandatory Education for All',
    curriculums: ['Military', 'Law', 'Technology', 'Agriculture'],
    minimumProgress: 80,
  });
});

// POST /api/education/enroll
router.post('/enroll', authenticateToken, async (req, res) => {
  try {
    const { citizenId, curriculum, durationMonths } = req.body;
    const result = await EducationService.enrollCitizen(citizenId, curriculum, durationMonths);
    res.json(result);
  } catch (error) {
    error(`Education enrollment failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// PUT /api/education/progress/:citizenId
router.put('/progress/:citizenId', authenticateToken, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { progress } = req.body;
    const result = await EducationService.updateProgress(citizenId, progress);
    res.json(result);
  } catch (error) {
    error(`Education progress update failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/education/compliance/:citizenId
router.get('/compliance/:citizenId', authenticateToken, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const report = await EducationService.getComplianceReport(citizenId);
    res.json(report);
  } catch (error) {
    error(`Education compliance report failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/education/non-compliant
router.get('/non-compliant', authenticateToken, async (req, res) => {
  try {
    const citizens = await EducationService.getNonCompliantCitizens();
    res.json({ citizens, count: citizens.length });
  } catch (error) {
    error(`Non-compliant citizens fetch failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/education/report/:curriculum
router.get('/report/:curriculum', authenticateToken, async (req, res) => {
  try {
    const { curriculum } = req.params;
    const report = await EducationService.generateCurriculumReport(curriculum);
    res.json(report);
  } catch (error) {
    error(`Curriculum report failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

export default router;
