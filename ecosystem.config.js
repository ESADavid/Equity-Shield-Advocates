module.exports = {
  apps: [
    {
      name: "owlban-earnings-dashboard",
      script: "./earnings_dashboard/server_rebuilt.js",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "200M",
      env: {
        NODE_ENV: "development",
        PORT: 4000,
      },
      env_production: {
        NODE_ENV: "production",
        PORT: 4000,
      },
    },
  ],
};
