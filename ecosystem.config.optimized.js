module.exports = {
  apps: [
    {
      name: 'oscar-broome-revenue-fast',
      script: 'server-enhanced.js',
      instances: 'max', // Use all CPU cores for maximum performance
      exec_mode: 'cluster', // Cluster mode for load balancing
      autorestart: true,
      watch: false,
      max_memory_restart: '1G', // Lower memory limit for faster restarts
      node_args: '--max-old-space-size=1024 --optimize-for-size --gc-interval=50', // Optimized GC
      env: {
        NODE_ENV: 'development',
        PORT: 3000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000,
        // Performance optimizations
        UV_THREADPOOL_SIZE: 128, // Increased for I/O intensive operations
        NODE_OPTIONS: '--max-old-space-size=2048 --optimize-for-size --gc-interval=100 --enable-source-maps=false',
      },
      env_staging: {
        NODE_ENV: 'staging',
        PORT: 3001,
        UV_THREADPOOL_SIZE: 64,
        NODE_OPTIONS: '--max-old-space-size=1024 --optimize-for-size --gc-interval=50',
      },
      // Optimized logging
      error_file: './logs/pm2-error.log',
      out_file: './logs/pm2-out.log',
      log_file: './logs/pm2-combined.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      time: false, // Disable timestamp for faster logging
      // Fast health checks
      health_check: {
        enabled: true,
        max_restarts: 3, // Reduced for faster recovery
        min_uptime: '5s', // Reduced for faster startup
      },
      // Optimized load balancing
      listen_timeout: 2000, // Reduced timeout
      kill_timeout: 3000, // Reduced kill timeout
      // Performance environment variables
      env_production_optimized: {
        ...process.env,
        NODE_ENV: 'production',
        PORT: 3000,
        UV_THREADPOOL_SIZE: 128,
        NODE_OPTIONS: '--max-old-space-size=2048 --optimize-for-size --gc-interval=100 --enable-source-maps=false --trace-warnings=false',
        // Disable unnecessary features for speed
        DISABLE_V8_COMPILE_CACHE: 'false',
        V8_COMPILE_CACHE_SIZE: '50MB',
      },
    },
  ],

  // Optimized deployment configuration
  deploy: {
    production: {
      user: 'node',
      host: 'your-production-server.com',
      ref: 'origin/main',
      repo: 'git@github.com:your-org/oscar-broome-revenue.git',
      path: '/var/www/oscar-broome-revenue',
      'pre-deploy-local': '',
      'post-deploy': 'npm ci --production && pm2 reload ecosystem.config.optimized.js --env production_optimized',
      'pre-setup': '',
    },
    staging: {
      user: 'node',
      host: 'your-staging-server.com',
      ref: 'origin/staging',
      repo: 'git@github.com:your-org/oscar-broome-revenue.git',
      path: '/var/www/oscar-broome-revenue-staging',
      'pre-deploy-local': '',
      'post-deploy': 'npm ci --production && pm2 reload ecosystem.config.optimized.js --env staging',
      'pre-setup': '',
    },
  },
};
