/**
 * NVIDIA BLACKWELL GPU ROUTES
 * API endpoints for Blackwell GPU acceleration and quantum hybrid computing
 */
import express from 'express';
const router = express.Router();
import NvidiaBlackwellService from '../services/nvidiaBlackwellService.js';

const blackwellService = new NvidiaBlackwellService();

// Middleware for Blackwell authentication
router.use((req, res, next) => {
  // Verify Blackwell access permissions
  const hasAccess = req.headers['x-blackwell-access'] === 'granted';
  if (!hasAccess) {
    return res.status(403).json({
      success: false,
      error: 'Blackwell GPU access denied'
    });
  }
  next();
});

// Initialize Blackwell GPUs
router.post('/initialize', async (req, res) => {
  try {
    const result = await blackwellService.initializeBlackwellGPUs();
    res.json({
      success: result.success,
      gpuCount: result.gpuCount,
      capabilities: blackwellService.blackwellCapabilities,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Blackwell initialization failed',
      details: error.message
    });
  }
});

// Run Blackwell-accelerated inference
router.post('/inference', async (req, res) => {
  try {
    const { model, input, options = {} } = req.body;

    if (!model || !input) {
      return res.status(400).json({
        success: false,
        error: 'Model and input are required'
      });
    }

    const result = await blackwellService.runBlackwellInference(model, input, options);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Blackwell inference failed',
      details: error.message
    });
  }
});

// Allocate Blackwell memory
router.post('/memory/allocate', async (req, res) => {
  try {
    const { gpuId, size, quantumShared = false } = req.body;

    if (gpuId === undefined || !size) {
      return res.status(400).json({
        success: false,
        error: 'GPU ID and size are required'
      });
    }

    const result = await blackwellService.allocateBlackwellMemory(gpuId, size, quantumShared);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Memory allocation failed',
      details: error.message
    });
  }
});

// Free Blackwell memory
router.post('/memory/free', async (req, res) => {
  try {
    const { gpuId, allocationId, size } = req.body;

    if (gpuId === undefined || !allocationId || !size) {
      return res.status(400).json({
        success: false,
        error: 'GPU ID, allocation ID, and size are required'
      });
    }

    const result = await blackwellService.freeBlackwellMemory(gpuId, allocationId, size);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Memory deallocation failed',
      details: error.message
    });
  }
});

// Quantum-Blackwell hybrid computing
router.post('/quantum-hybrid', async (req, res) => {
  try {
    const { quantumCircuit, classicalData } = req.body;

    if (!quantumCircuit || !classicalData) {
      return res.status(400).json({
        success: false,
        error: 'Quantum circuit and classical data are required'
      });
    }

    const result = await blackwellService.runQuantumBlackwellHybrid(quantumCircuit, classicalData);
    res.json({
      success: true,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Quantum-Blackwell hybrid computation failed',
      details: error.message
    });
  }
});

// Get Blackwell metrics
router.get('/metrics', (req, res) => {
  try {
    const metrics = blackwellService.getBlackwellMetrics();
    res.json({
      success: true,
      metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve Blackwell metrics',
      details: error.message
    });
  }
});

// Optimize Blackwell performance
router.post('/optimize', async (req, res) => {
  try {
    const result = await blackwellService.optimizeBlackwellPerformance();
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Blackwell optimization failed',
      details: error.message
    });
  }
});

// Bill Blackwell usage
router.post('/billing/:kernelId', async (req, res) => {
  try {
    const { kernelId } = req.params;
    const { hoursUsed, memoryUsageGB, operationsPerformed } = req.body;

    if (!hoursUsed || !memoryUsageGB || !operationsPerformed) {
      return res.status(400).json({
        success: false,
        error: 'Usage metrics are required'
      });
    }

    const usageMetrics = { hoursUsed, memoryUsageGB, operationsPerformed };
    const result = await blackwellService.billBlackwellUsage(kernelId, usageMetrics);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Blackwell billing failed',
      details: error.message
    });
  }
});

// Get Blackwell capabilities
router.get('/capabilities', (req, res) => {
  res.json({
    success: true,
    capabilities: blackwellService.blackwellCapabilities,
    gpuDevices: blackwellService.gpuDevices.length,
    quantumHybridMode: blackwellService.quantumHybridMode,
    timestamp: new Date().toISOString()
  });
});

// Health check for Blackwell service
router.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    blackwellService: 'operational',
    gpuCount: blackwellService.gpuDevices.length,
    activeKernels: blackwellService.activeKernels.size,
    quantumMode: blackwellService.quantumHybridMode,
    timestamp: new Date().toISOString()
  };

  res.json(health);
});

export default router;
