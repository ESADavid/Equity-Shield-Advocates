# OSCAR-BROOME-REVENUE

REVENUE FOR OSCAR BROOME FROM ALL THE OWLBAN GROUP REPOSITORYS

## Patents

This project includes patents related to the FOUR ERA AI & OWLBAIN Group.  
Please see the [PATENTS.md](PATENTS.md) file for detailed patent summaries and claims.

## Deployment

To deploy the OSCAR-BROOME-REVENUE server, follow these steps:

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file in the root directory based on `.env.example` and set the environment variables:
   - `PORT`: Port number for the server (default 4000)
   - `ADMIN_USER`: Basic auth username
   - `ADMIN_PASS`: Basic auth password
   - `NODE_ENV`: Set to `production` for production mode

3. Start the server:
   ```
   npm start
   ```

4. The server will be accessible at `http://localhost:<PORT>`.

5. Ensure your frontend domain is configured in `earnings_dashboard/server.js` CORS settings.

6. For production deployment, consider using a process manager like PM2 or containerization with Docker.

