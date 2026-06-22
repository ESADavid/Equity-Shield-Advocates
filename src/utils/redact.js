/**
 * Redaction utility for sensitive data
 * Removes or masks secrets, tokens, and sensitive information from logs/responses
 */

const SENSITIVE_KEYS = [
  'password',
  'secret',
  'client_secret',
  'access_token',
  'refresh_token',
  'authorization',
  'bearer',
  'token',
  'ssn',
  'social_security',
  'ein',
  'credit_card',
  'card_number',
  'cvv',
  'pin',
  'api_key',
  'private_key'
];

const TOKEN_PATTERN = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;

/**
 * Redacts sensitive keys from an object
 */
export function redact(obj) {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  const result = Array.isArray(obj) ? [] : {};
  
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const lowerKey = key.toLowerCase();
    
    // Check if this key is sensitive
    const isSensitive = SENSITIVE_KEYS.some(sk => lowerKey.includes(sk));
    
    // Check if value looks like a token
    const isToken = typeof value === 'string' && TOKEN_PATTERN.test(value);
    
    if (isSensitive || isToken) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      // Recursively redact nested objects
      result[key] = redact(value);
    } else {
      result[key] = value;
    }
  }
  
  return result;
}

/**
 * Redacts a string value if it appears to be sensitive
 */
export function redactValue(value) {
  if (typeof value !== 'string') {
    return value;
  }
  
  if (TOKEN_PATTERN.test(value)) {
    return '[REDACTED]';
  }
  
  return value;
}
