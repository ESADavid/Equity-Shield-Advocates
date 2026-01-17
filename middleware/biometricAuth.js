import biometricAuthService from '../services/biometricAuthService.js';
import permissionService from '../services/permissionService.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'biometric-middleware' },
  transports: [
    new winston.transports.File({ filename: 'logs/biometric-middleware.log' }),
    new winston.transports.File({
      filename: 'logs/biometric-middleware-error.log',
      level: 'error',
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

/**
 * Middleware to require biometric verification
 * @param {Array<string>} biometricTypes - Required biometric types (e.g., ['fingerprint', 'facial'])
 * @param {number} minimumRequired - Minimum number of biometrics required
 */
export function requireBiometric(biometricTypes = ['fingerprint'], minimumRequired = 1) {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user._id) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
        });
      }

      const userId = req.user._id;
      const tenantId = req.tenantId || 'default';

      // Get biometric data from request headers or body
      const biometrics = {
        fingerprint: req.headers['x-biometric-fingerprint'] || req.body.biometric_fingerprint,
        facial: req.headers['x-biometric-facial'] || req.body.biometric_facial,
        voice: req.headers['x-biometric-voice'] || req.body.biometric_voice,
      };

      // Check if any biometrics were provided
      const providedBiometrics = Object.keys(biometrics).filter(key => biometrics[key]);
      
      if (providedBiometrics.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'Biometric verification required',
          requiredBiometrics: biometricTypes,
          minimumRequired,
        });
      }

      // Verify biometrics
      const context = {
        ipAddress: req.ip,
        deviceId: req.headers['x-device-id'],
        userAgent: req.headers['user-agent'],
      };

      const verificationResult = await biometricAuthService.verifyMultipleBiometrics(
        userId,
        tenantId,
        biometrics,
        context
      );

      if (!verificationResult.overall) {
        logger.warn('Biometric verification failed', {
          userId,
          tenantId,
          verifiedCount: verificationResult.verifiedCount,
          requiredCount: verificationResult.requiredCount,
        });

        return res.status(403).json({
          success: false,
          message: 'Biometric verification failed',
          verifiedCount: verificationResult.verifiedCount,
          requiredCount: verificationResult.requiredCount,
          results: verificationResult,
        });
      }

      // Check if minimum biometrics requirement is met
      if (verificationResult.verifiedCount < minimumRequired) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient biometric verifications',
          verifiedCount: verificationResult.verifiedCount,
          minimumRequired,
        });
      }

      logger.info('Biometric verification successful', {
        userId,
        tenantId,
        verifiedCount: verificationResult.verifiedCount,
      });

      // Attach verification result to request
      req.biometricVerification = verificationResult;

      next();
    } catch (error) {
      logger.error('Biometric middleware error', {
        error: error.message,
        stack: error.stack,
      });

      res.status(500).json({
        success: false,
        message: 'Biometric verification error',
        error: error.message,
      });
    }
  };
}

/**
 * Middleware to require specific permission
 * @param {string} permissionCode - Required permission code
 */
export function requirePermission(permissionCode) {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user._id) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
        });
      }

      const userId = req.user._id;
      const tenantId = req.tenantId || 'default';

      // Build context from request
      const context = {
        ipAddress: req.ip,
        deviceType: req.headers['x-device-type'] || 'unknown',
        isVPN: req.headers['x-is-vpn'] === 'true',
        isSecureNetwork: req.headers['x-secure-network'] === 'true',
        isTrustedDevice: req.headers['x-trusted-device'] === 'true',
      };

      // Check permission
      const permissionCheck = await permissionService.checkPermission(
        userId,
        permissionCode,
        tenantId,
        context
      );

      if (!permissionCheck.allowed) {
        logger.warn('Permission denied', {
          userId,
          permissionCode,
          tenantId,
          reason: permissionCheck.reason,
        });

        return res.status(403).json({
          success: false,
          message: 'Permission denied',
          reason: permissionCheck.reason,
          violations: permissionCheck.violations,
        });
      }

      // If permission requires biometric, check if biometric verification was done
      if (permissionCheck.requiresBiometric && !req.biometricVerification) {
        return res.status(403).json({
          success: false,
          message: 'Biometric verification required for this permission',
          requiredBiometrics: permissionCheck.biometricTypes,
          minimumRequired: permissionCheck.minimumBiometrics,
        });
      }

      logger.info('Permission granted', {
        userId,
        permissionCode,
        tenantId,
      });

      // Log permission usage
      await permissionService.logPermissionUsage(userId, permissionCode, tenantId, context);

      // Attach permission to request
      req.permission = permissionCheck.permission;

      next();
    } catch (error) {
      logger.error('Permission middleware error', {
        error: error.message,
        stack: error.stack,
      });

      res.status(500).json({
        success: false,
        message: 'Permission check error',
        error: error.message,
      });
    }
  };
}

/**
 * Middleware to validate context restrictions
 */
export function validateContext() {
  return async (req, res, next) => {
    try {
      const context = {
        ipAddress: req.ip,
        deviceType: req.headers['x-device-type'] || 'unknown',
        isVPN: req.headers['x-is-vpn'] === 'true',
        isSecureNetwork: req.headers['x-secure-network'] === 'true',
        isTrustedDevice: req.headers['x-trusted-device'] === 'true',
      };

      // Attach context to request
      req.securityContext = context;

      next();
    } catch (error) {
      logger.error('Context validation error', {
        error: error.message,
        stack: error.stack,
      });

      res.status(500).json({
        success: false,
        message: 'Context validation error',
        error: error.message,
      });
    }
  };
}

/**
 * Middleware to check time restrictions
 */
export function checkTimeRestrictions(allowedDays = [], allowedHours = {}) {
  return (req, res, next) => {
    try {
      const now = new Date();
      const currentDay = now.toLocaleLowerCase().substring(0, 3); // 'mon', 'tue', etc.
      const currentHour = now.getHours();

      // Check day restrictions
      if (allowedDays.length > 0 && !allowedDays.includes(currentDay)) {
        return res.status(403).json({
          success: false,
          message: 'Access not allowed on this day',
          allowedDays,
          currentDay,
        });
      }

      // Check hour restrictions
      if (allowedHours.start !== undefined && allowedHours.end !== undefined) {
        const startHour = parseInt(allowedHours.start.split(':')[0]);
        const endHour = parseInt(allowedHours.end.split(':')[0]);

        if (currentHour < startHour || currentHour >= endHour) {
          return res.status(403).json({
            success: false,
            message: 'Access not allowed at this time',
            allowedHours,
            currentHour,
          });
        }
      }

      next();
    } catch (error) {
      logger.error('Time restriction check error', {
        error: error.message,
        stack: error.stack,
      });

      res.status(500).json({
        success: false,
        message: 'Time restriction check error',
        error: error.message,
      });
    }
  };
}

/**
 * Combined middleware for biometric + permission check
 * @param {string} permissionCode - Required permission code
 * @param {Array<string>} biometricTypes - Required biometric types
 * @param {number} minimumBiometrics - Minimum number of biometrics required
 */
export function requireBiometricPermission(permissionCode, biometricTypes = ['fingerprint'], minimumBiometrics = 1) {
  return [
    validateContext(),
    requireBiometric(biometricTypes, minimumBiometrics),
    requirePermission(permissionCode),
  ];
}

export default {
  requireBiometric,
  requirePermission,
  validateContext,
  checkTimeRestrictions,
  requireBiometricPermission,
};
