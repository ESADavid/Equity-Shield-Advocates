import { info, error } from '../utils/loggerWrapper.js';
import PMCOperation from '../models/PMCOperation.js';

export default class PMCIntegrationService {
  constructor() {
    info('PMCIntegrationService initialized (real DB mode)');
  }

  async createCoordinatedOperation(data, userId) {
    try {
      const operation = new PMCOperation({ ...data, assignedTo: userId });
      await operation.save();
      info(`PMC operation created: ${operation.operationId} by ${userId}`);
      return { success: true, operationId: operation.operationId };
    } catch (err) {
      error('Create PMC operation failed:', err);
      return { success: false, error: err.message };
    }
  }

  async getOperations(filters = {}) {
    try {
      const operations = await PMCOperation.find(filters)
        .populate('partners assignedTo')
        .limit(50);
      return { success: true, operations, count: operations.length };
    } catch (err) {
      error('Get operations failed:', err);
      return { success: false, error: err.message };
    }
  }

  async getOperation(operationId) {
    try {
      const operation = await PMCOperation.findOne({ operationId }).populate(
        'partners assignedTo'
      );
      if (!operation) return { success: false, error: 'Operation not found' };
      return { success: true, operation };
    } catch (err) {
      error(`Get operation ${operationId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  async updateOperationStatus(operationId, status, data, userId) {
    try {
      const operation = await PMCOperation.findOne({ operationId });
      if (!operation) return { success: false, error: 'Operation not found' };

      await operation.updateStatus(status, userId);
      info(`Operation ${operationId} status updated to ${status}`);
      return { success: true };
    } catch (err) {
      error(`Update operation ${operationId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  async allocateResources(operationId, data, userId) {
    try {
      const operation = await PMCOperation.findOne({ operationId });
      if (!operation) return { success: false, error: 'Operation not found' };

      await operation.allocateResources(data);
      info(`Resources allocated to ${operationId} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Allocate resources failed for ${operationId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async generateOperationReport(operationId, reportType, userId) {
    try {
      const operation = await PMCOperation.findOne({ operationId });
      if (!operation) return { success: false, error: 'Operation not found' };

      await operation.addReport({
        type: reportType,
        date: new Date(),
        content: `Generated ${reportType} report for ${operationId}`,
        fileId: `report-${Date.now()}`,
      });
      info(`Report generated for ${operationId} by ${userId}`);
      return { success: true, reportId: `report-${operationId}-${Date.now()}` };
    } catch (err) {
      error(`Generate report failed for ${operationId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async createTrainingProgram(data, userId) {
    try {
      const training = new PMCOperation({
        ...data,
        type: 'training',
        status: 'planning',
        assignedTo: userId,
      });
      await training.save();
      info(`Training program created: ${training.operationId}`);
      return { success: true, programId: training.operationId };
    } catch (err) {
      error('Create training program failed:', err);
      return { success: false, error: err.message };
    }
  }

  // getIntegrationStatus kept for route compatibility
  getIntegrationStatus() {
    return { status: 'integrated-real', version: '2.0.0' };
  }

  async getStatistics() {
    try {
      const total = await PMCOperation.countDocuments();
      const active = await PMCOperation.countDocuments({ status: 'active' });

      return {
        success: true,
        stats: {
          totalOperations: total,
          activeOperations: active,
          avgPersonnel: await PMCOperation.aggregate([
            { $group: { _id: null, avg: { $avg: '$resources.personnel' } } },
          ]).then((res) => Math.round(res[0]?.avg || 0)),
        },
      };
    } catch (err) {
      error('PMC statistics failed:', err);
      return { success: false, error: err.message };
    }
  }

  getHealthStatus() {
    return { status: 'healthy', mode: 'real-db-enhanced' };
  }
}
