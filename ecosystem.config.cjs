module.exports = {
  apps: [
    {
      name: 'equity-shield-advocates-api',
      script: 'src/server.js',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '300M',
      env: {
        NODE_ENV: 'production',
        PORT: 8080,
        LOG_LEVEL: 'info',
        ENABLE_VERBOSE_ERRORS: 'false',
        DISABLE_AI_ROUTES: 'true'
      },
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      merge_logs: true,
      time: true
    }
  ]
};
