/**
 * Blackbox.ai Multi-Agent API Routes
 * /api/multi-agent/*
 */

import express from 'express';
import blackboxService from '../services/blackboxMultiAgentService.js';
import { info } from '../utils/loggerWrapper.js';

const router = express.Router();

// POST /api/multi-agent/create
router.post('/create', async (req, res) => {
  try {
    const { prompt, selectedAgents, repoUrl, branch } = req.body;

    info(`Multi-agent task request: ${prompt?.substring(0, 100)}`);

    const result = await blackboxService.createMultiAgentTask(
      prompt,
      selectedAgents,
      repoUrl,
      branch
    );

    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/multi-agent/status/:taskId
router.get('/status/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;
    const result = await blackboxService.getTaskDetails(taskId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/multi-agent/poll/:taskId
router.post('/poll/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { pollInterval } = req.body;
    const result = await blackboxService.pollTaskUntilComplete(taskId, pollInterval);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/multi-agent/optimize
router.post('/optimize', async (req, res) => {
  try {
    const { prompt } = req.body;
    const result = await blackboxService.optimizeRepo(prompt);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;

