import express from 'express';
import tenantService from '../services/tenantService.js';
import { authenticate, requireRole, requirePermission } from '../middleware/auth.js';
import { resolveTenant, requireFeature, checkLimits, logTenantActivity } from '../middleware/tenant.js';
import winston from 'winston';

const router = express.Router();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'tenant-routes' },
  transports: [
    new winston.transports.File({ filename: 'logs/tenant-routes.log' }),
    new winston.transports.File({ filename: 'logs/tenant-routes-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Apply tenant resolution to all routes
router.use(resolveTenant);
router.use(logTenantActivity('tenant-api-access'));

// Get current tenant information
router.get('/current',
  authenticate,
  async (req, res) => {
    try {
      const tenant = req.tenant;
      const usage = await tenantService.getTenantUsage(tenant.tenantId);

      res.json({
        success: true,
        tenant: {
          tenantId: tenant.tenantId,
          name: tenant.name,
          domain: tenant.domain,
          status: tenant.status,
          settings: tenant.settings,
          subscription: tenant.subscription,
          usage
        }
      });
    } catch (error) {
      logger.error('Error getting current tenant', { error: error.message, tenantId: req.tenant?.tenantId });
      res.status(500).json({
        success: false,
        message: 'Failed to get tenant information'
      });
    }
  }
);

// Get tenant usage statistics
router.get('/usage',
  authenticate,
  requirePermission('tenant.view'),
  async (req, res) => {
    try {
      const usage = await tenantService.getTenantUsage(req.tenant.tenantId);

      res.json({
        success: true,
        usage
      });
    } catch (error) {
      logger.error('Error getting tenant usage', { error: error.message, tenantId: req.tenant.tenantId });
      res.status(500).json({
        success: false,
        message: 'Failed to get usage statistics'
      });
    }
  }
);

// Check tenant limits
router.get('/limits/:type',
  authenticate,
  requirePermission('tenant.view'),
  async (req, res) => {
    try {
      const { type } = req.params;
      const limits = await tenantService.checkTenantLimits(req.tenant.tenantId, type);

      res.json({
        success: true,
        limits
      });
    } catch (error) {
      logger.error('Error checking tenant limits', {
        error: error.message,
        tenantId: req.tenant.tenantId,
        type: req.params.type
      });
      res.status(500).json({
        success: false,
        message: 'Failed to check limits'
      });
    }
  }
);

// Update tenant settings (admin only)
router.put('/settings',
  authenticate,
  requireRole('admin'),
  requirePermission('tenant.update'),
  async (req, res) => {
    try {
      const { settings } = req.body;

      if (!settings) {
        return res.status(400).json({
          success: false,
          message: 'Settings data is required'
        });
      }

      const updatedTenant = await tenantService.updateTenant(
        req.tenant.tenantId,
        { settings },
        req.user._id
      );

      logger.info('Tenant settings updated', {
        tenantId: req.tenant.tenantId,
        updatedBy: req.user._id,
        settingsKeys: Object.keys(settings)
      });

      res.json({
        success: true,
        message: 'Tenant settings updated successfully',
        tenant: {
          tenantId: updatedTenant.tenantId,
          settings: updatedTenant.settings
        }
      });
    } catch (error) {
      logger.error('Error updating tenant settings', {
        error: error.message,
        tenantId: req.tenant.tenantId,
        userId: req.user._id
      });
      res.status(500).json({
        success: false,
        message: 'Failed to update tenant settings'
      });
    }
  }
);

// Create API key for tenant
router.post('/api-keys',
  authenticate,
  requireRole('admin'),
  requirePermission('tenant.api-keys.create'),
  async (req, res) => {
    try {
      const { name, permissions } = req.body;

      if (!name) {
        return res.status(400).json({
          success: false,
          message: 'API key name is required'
        });
      }

      const tenant = await tenantService.getTenantById(req.tenant.tenantId);
      const apiKey = {
        key: generateApiKey(),
        name,
        permissions: permissions || ['read'],
        createdAt: new Date(),
        lastUsed: null,
        isActive: true
      };

      tenant.apiKeys.push(apiKey);
      await tenant.save();

      logger.info('API key created for tenant', {
        tenantId: req.tenant.tenantId,
        keyName: name,
        createdBy: req.user._id
      });

      res.json({
        success: true,
        message: 'API key created successfully',
        apiKey: {
          name: apiKey.name,
          permissions: apiKey.permissions,
          createdAt: apiKey.createdAt,
          isActive: apiKey.isActive
        }
      });
    } catch (error) {
      logger.error('Error creating API key', {
        error: error.message,
        tenantId: req.tenant.tenantId,
        userId: req.user._id
      });
      res.status(500).json({
        success: false,
        message: 'Failed to create API key'
      });
    }
  }
);

// List API keys for tenant
router.get('/api-keys',
  authenticate,
  requireRole('admin'),
  requirePermission('tenant.api-keys.view'),
  async (req, res) => {
    try {
      const tenant = await tenantService.getTenantById(req.tenant.tenantId);

      const apiKeys = tenant.apiKeys.map(key => ({
        name: key.name,
        permissions: key.permissions,
        createdAt: key.createdAt,
        lastUsed: key.lastUsed,
        isActive: key.isActive
      }));

      res.json({
        success: true,
        apiKeys
      });
    } catch (error) {
      logger.error('Error listing API keys', {
        error: error.message,
        tenantId: req.tenant.tenantId,
        userId: req.user._id
      });
      res.status(500).json({
        success: false,
        message: 'Failed to list API keys'
      });
    }
  }
);

// Delete API key
router.delete('/api-keys/:keyName',
  authenticate,
  requireRole('admin'),
  requirePermission('tenant.api-keys.delete'),
  async (req, res) => {
    try {
      const { keyName } = req.params;
      const tenant = await tenantService.getTenantById(req.tenant.tenantId);

      const keyIndex = tenant.apiKeys.findIndex(key => key.name === keyName && key.isActive);
      if (keyIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'API key not found'
        });
      }

      tenant.apiKeys[keyIndex].isActive = false;
      await tenant.save();

      logger.info('API key deleted', {
        tenantId: req.tenant.tenantId,
        keyName,
        deletedBy: req.user._id
      });

      res.json({
        success: true,
        message: 'API key deleted successfully'
      });
    } catch (error) {
      logger.error('Error deleting API key', {
        error: error.message,
        tenantId: req.tenant.tenantId,
        keyName: req.params.keyName,
        userId: req.user._id
      });
      res.status(500).json({
        success: false,
        message: 'Failed to delete API key'
      });
    }
  }
);

// Check feature access
router.get('/features/:feature',
  authenticate,
  async (req, res) => {
    try {
      const { feature } = req.params;
      const hasAccess = await tenantService.hasFeatureAccess(req.tenant.tenantId, feature);

      res.json({
        success: true,
        feature,
        hasAccess
      });
    } catch (error) {
      logger.error('Error checking feature access', {
        error: error.message,
        tenantId: req.tenant.tenantId,
        feature: req.params.feature
      });
      res.status(500).json({
        success: false,
        message: 'Failed to check feature access'
      });
    }
  }
);

// Admin routes (system admin only)

// Get all tenants (admin only)
router.get('/admin/all',
  authenticate,
  requireRole('admin'),
  requirePermission('system.tenants.view'),
  async (req, res) => {
    try {
      const tenants = await tenantService.getActiveTenants();

      res.json({
        success: true,
        tenants
      });
    } catch (error) {
      logger.error('Error getting all tenants', { error: error.message, userId: req.user._id });
      res.status(500).json({
        success: false,
        message: 'Failed to get tenants'
      });
    }
  }
);

// Create new tenant (admin only)
router.post('/admin/create',
  authenticate,
  requireRole('admin'),
  requirePermission('system.tenants.create'),
  async (req, res) => {
    try {
      const tenantData = {
        ...req.body,
        audit: {
          createdBy: req.user._id
        }
      };

      const tenant = await tenantService.createTenant(tenantData);

      logger.info('New tenant created by admin', {
        newTenantId: tenant.tenantId,
        createdBy: req.user._id
      });

      res.status(201).json({
        success: true,
        message: 'Tenant created successfully',
        tenant: {
          tenantId: tenant.tenantId,
          name: tenant.name,
          domain: tenant.domain,
          status: tenant.status
        }
      });
    } catch (error) {
      logger.error('Error creating tenant', {
        error: error.message,
        userId: req.user._id,
        tenantData: req.body
      });
      res.status(500).json({
        success: false,
        message: 'Failed to create tenant'
      });
    }
  }
);

// Update tenant (admin only)
router.put('/admin/:tenantId',
  authenticate,
  requireRole('admin'),
  requirePermission('system.tenants.update'),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const updateData = req.body;

      const tenant = await tenantService.updateTenant(tenantId, updateData, req.user._id);

      logger.info('Tenant updated by admin', {
        tenantId,
        updatedBy: req.user._id,
        changes: Object.keys(updateData)
      });

      res.json({
        success: true,
        message: 'Tenant updated successfully',
        tenant: {
          tenantId: tenant.tenantId,
          name: tenant.name,
          status: tenant.status
        }
      });
    } catch (error) {
      logger.error('Error updating tenant', {
        error: error.message,
        tenantId: req.params.tenantId,
        userId: req.user._id
      });
      res.status(500).json({
        success: false,
        message: 'Failed to update tenant'
      });
    }
  }
);

// Suspend/reactivate tenant (admin only)
router.put('/admin/:tenantId/status',
  authenticate,
  requireRole('admin'),
  requirePermission('system.tenants.manage'),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { action, reason } = req.body;

      const tenant = await tenantService.getTenantById(tenantId);
      if (!tenant) {
        return res.status(404).json({
          success: false,
          message: 'Tenant not found'
        });
      }

      let result;
      if (action === 'suspend') {
        result = await tenant.suspend(reason || 'Suspended by admin');
      } else if (action === 'reactivate') {
        result = await tenant.reactivate();
      } else {
        return res.status(400).json({
          success: false,
          message: 'Invalid action. Use "suspend" or "reactivate"'
        });
      }

      logger.info(`Tenant ${action}ed by admin`, {
        tenantId,
        action,
        reason,
        adminId: req.user._id
      });

      res.json({
        success: true,
        message: `Tenant ${action}ed successfully`,
        tenant: {
          tenantId: tenant.tenantId,
          name: tenant.name,
          status: tenant.status
        }
      });
    } catch (error) {
      logger.error(`Error ${req.body.action}ing tenant`, {
        error: error.message,
        tenantId: req.params.tenantId,
        action: req.body.action,
        userId: req.user._id
      });
      res.status(500).json({
        success: false,
        message: `Failed to ${req.body.action} tenant`
      });
    }
  }
);

// Helper function to generate API key
function generateApiKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export default router;
