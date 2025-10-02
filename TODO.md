# Project TODO List

- [x] Fix await expression in production_deploy.mjs by adding spawn import at top and adjusting PM2 logic
- [x] Fix duplicate child_process imports in production_deploy_simple.mjs
- [x] Adjust PM2 error handling in both files to avoid SonarLint catch warnings
- [x] Test the deployment scripts to ensure they still work
