# Fix Server Startup Issues

## Issues Identified
- MongoDB connection error: "option buffermaxentries is not supported" (deprecated option)
- MongoDB server not running: "connect ECONNREFUSED 127.0.0.1:27017"
- 'head' command not available on Windows for curl output

## Plan
1. Update database config to remove any deprecated options
2. Ensure MongoDB is installed and running on Windows
3. Clear npm cache and reinstall dependencies if needed
4. Provide Windows-compatible curl command
5. Test server startup

## Steps
- [ ] Check MongoDB installation and start service
- [ ] Update config/database.js if needed
- [ ] Run npm install to ensure correct versions
- [ ] Start server and test health endpoint
- [ ] Provide Windows curl alternative
