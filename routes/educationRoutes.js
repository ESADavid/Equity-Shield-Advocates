/**
 * Education Routes - Heaven on Earth Phase 2
 * API endpoints for mandatory education system
 */

const express = require('express');
const router = express.Router();
const EducationService = require('../services/educationService');
const authMiddleware = require('../utils/authMiddleware');
const logger = require('../utils/logger');

// POST /api/education/enroll
router.post('/enroll', authMiddleware, async (req, res) => {
  try {
    const { citizenId, curriculum, durationMonths } = req.body;
    const result = await EducationService.enrollCitizen(
      citizenId,
      curriculum,
      durationMonths
    );
    res.json(result);
  } catch (error) {
    logger.error(`Education enrollment failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// PUT /api/education/progress/:citizenId
router.put('/progress/:citizenId', authMiddleware, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { progress } = req.body;
    const education = await EducationService.updateProgress(
      citizenId,
      progress
    );
    res.json(education);
  } catch (error) {
    logger.error(`Education progress update failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/education/compliance/:citizenId
router.get('/compliance/:citizenId', authMiddleware, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const report = await EducationService.getComplianceReport(citizenId);
    res.json(report);
  } catch (error) {
    logger.error(`Compliance report failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/education/non-compliant
router.get('/non-compliant', authMiddleware, async (req, res) => {
  try {
    const nonCompliant = await EducationService.getNonCompliantCitizens();
    res.json(nonCompliant);
  } catch (error) {
    logger.error(`Non-compliant list failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/education/report/:curriculum
router.get('/report/:curriculum', authMiddleware, async (req, res) => {
  try {
    const { curriculum } = req.params;
    const report = await EducationService.generateCurriculumReport(curriculum);
    res.json(report);
  } catch (error) {
    logger.error(`Curriculum report failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

module.exports = router;
