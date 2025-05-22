module.exports = {
  apps: [
    {
      name: "oscar-broome-revenue",
      script: "earnings_dashboard/server.js",
      instances: "max",
      exec_mode: "cluster",
      env: {
        NODE_ENV: "development",
        PORT: 4000,
        ADMIN_USER: "admin",
        ADMIN_PASS: "securepassword",
        CORS_ORIGIN: "https://your-frontend-domain.com"
      },
      env_production: {
        NODE_ENV: "production",
        PORT: 4000,
        ADMIN_USER: "admin",
        ADMIN_PASS: "securepassword",
        CORS_ORIGIN: "https://your-frontend-domain.com"
      }
    }
  ]
};
