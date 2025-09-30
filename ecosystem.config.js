module.exports = {
  apps: [{
    name: 'oscar-broome-revenue',
    script: 'server-enhanced.js',
    instances: 'max', // Use all CPU cores
    exec_mode: 'cluster', // Cluster mode for load balancing
    autorestart: true,
    watch: false,
    max_memory_restart: '2G', // Increased memory limit
    node_args: '--max-old-space-size=2048', // 2GB heap size
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      // Production optimizations
      UV_THREADPOOL_SIZE: 64, // Optimize for I/O operations
      NODE_OPTIONS: '--max-old-space-size=4096' // 4GB heap in production
    },
    env_staging: {
      NODE_ENV: 'staging',
      PORT: 3001,
      UV_THREADPOOL_SIZE: 32,
      NODE_OPTIONS: '--max-old-space-size=2048'
    },
    // Performance monitoring
    error_file: './logs/pm2-error.log',
    out_file: './logs/pm2-out.log',
    log_file: './logs/pm2-combined.log',
    time: true,
    // Health checks
    health_check: {
      enabled: true,
      max_restarts: 5,
      min_uptime: '10s'
    },
    // Load balancing
    listen_timeout: 3000,
    kill_timeout: 5000,
    // Environment variables for performance
    env_production: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: 3000,
      UV_THREADPOOL_SIZE: 64,
      NODE_OPTIONS: '--max-old-space-size=4096 --optimize-for-size --gc-interval=100'
    }
  }],

  // Deployment configuration
  deploy: {
    production: {
      user: 'node',
      host: 'your-production-server.com',
      ref: 'origin/main',
      repo: 'git@github.com:your-org/oscar-broome-revenue.git',
      path: '/var/www/oscar-broome-revenue',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    },
    staging: {
      user: 'node',
      host: 'your-staging-server.com',
      ref: 'origin/staging',
      repo: 'git@github.com:your-org/oscar-broome-revenue.git',
      path: '/var/www/oscar-broome-revenue-staging',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env staging',
      'pre-setup': ''
    }
  }
};
