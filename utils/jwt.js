import jwt from 'jsonwebtoken';
import { error } from './loggerWrapper.js';

/** @type {string} */
const JWT_SECRET =
  process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
/** @type {string} */
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ||
  'your-super-secret-refresh-key-change-in-production';
/** @type {string} */
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
/** @type {string} */
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';

/**
 * Generate JWT access token
 * @param {object} payload - Token payload
 * @returns {string} Signed JWT token
 */
export const generateAccessToken = (
  /** @type {object} */ payload
) => {
  // @ts-expect-error - jsonwebtoken types are strict about payload type
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
};

/**
 * Generate JWT refresh token
 * @param {object} payload - Token payload
 * @returns {string} Signed refresh token
 */
export const generateRefreshToken = (
  /** @type {object} */ payload
) => {
  // @ts-expect-error - jsonwebtoken types are strict about payload type
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY,
  });
};

/**
 * Verify JWT access token
 * @param {string} token - Token to verify
 * @returns {object|null} Decoded token or null if invalid
 */
export const verifyAccessToken = (
  /** @type {string} */ token
) => {
  // @ts-expect-error - jsonwebtoken verify return type is complex
  return jwt.verify(token, JWT_SECRET);
};

/**
 * Verify JWT refresh token
 * @param {string} token - Token to verify
 * @returns {object|null} Decoded token or null if invalid
 */
export const verifyRefreshToken = (
  /** @type {string} */ token
) => {
  // @ts-expect-error - jsonwebtoken verify return type is complex
  return jwt.verify(token, JWT_REFRESH_SECRET);
};

export { JWT_SECRET, JWT_REFRESH_SECRET };
