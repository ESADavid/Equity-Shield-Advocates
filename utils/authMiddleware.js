import { verifyAccessToken, verifyRefreshToken } from './jwt.js';

export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1]; // Bearer TOKEN


  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  const user = verifyAccessToken(token);
  if (!user) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }

  req.user = user;
  next();
};

export const authenticateRefreshToken = (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ success: false, message: 'Refresh token required' });
  }

  const user = verifyRefreshToken(refreshToken);
  if (!user) {
    return res.status(403).json({ success: false, message: 'Invalid refresh token' });
  }

  req.user = user;
  next();
};

export const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

