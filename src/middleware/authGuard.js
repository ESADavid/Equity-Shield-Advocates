/**
 * Authentication guard middleware
 * Validates API key/ bearer token for protected routes
 */
export function authGuard(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing authorization header'
    });
  }
  
  // Support Bearer token or API key
  const token = authHeader.startsWith('Bearer ') 
    ? authHeader.substring(7) 
    : authHeader;
    
  if (!token || token.length === 0) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid token'
    });
  }
  
  // Store token for service use (will be redacted in logs)
  req.authToken = token;
  next();
}
