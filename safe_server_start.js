/**
 * SAFE SERVER START - Desktop Optimized
 * Single instance, low memory, no cluster
 * Prevents system crashes/freezes
 */

import app from './app.js';
const PORT = process.env.PORT || 3000;


// Resource limits for desktop
process.env.UV_THREADPOOL_SIZE = '4';
process.env.NODE_OPTIONS = '--max-old-space-size=1024 --optimize-for-size';

app.listen(PORT, 'localhost', async () => {
  const { info } = await import('./utils/loggerWrapper.js');
  info(`🚀 Safe Server running at http://localhost:${PORT}`);
  info('💻 Desktop mode - low resources. For production: use Docker/Cloud.');
  info('🛑 Kill with Ctrl+C. No PM2 autorestart.');
});
