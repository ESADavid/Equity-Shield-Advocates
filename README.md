# OSCAR-BROOME-REVENUE

REVENUE FOR OSCAR BROOME FROM ALL THE OWLBAN GROUP REPOSITORYS

## Patents

This project includes patents related to the FOUR ERA AI & OWLBAIN Group.  
Please see the [PATENTS.md](PATENTS.md) file for detailed patent summaries and claims.

## Deployment

To deploy the OSCAR-BROOME-REVENUE server, follow these steps:

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create a `.env` file in the root directory based on `.env.example` and set the environment variables:
   - `PORT`: Port number for the server (default 4000)
   - `ADMIN_USER`: Basic auth username
   - `ADMIN_PASS`: Basic auth password
   - `NODE_ENV`: Set to `production` for production mode
   - `CORS_ORIGIN`: Your frontend domain URL (e.g., <https://your-frontend-domain.com>)

3. Make sure `.env` is included in your `.gitignore` file to avoid committing sensitive information.

4. Start the server:

   ```bash
   npm start
   ```

5. The server will be accessible at [`http://localhost:<PORT>`](http://localhost:<PORT>).

6. Ensure your frontend domain is configured in the `CORS_ORIGIN` environment variable.

7. For production deployment, consider using a process manager like PM2 or containerization with Docker.

### Using PM2

- Install PM2 globally if not installed:

  ```bash
  npm install -g pm2
  ```

- Start the app with PM2 using the ecosystem config:

  ```bash
  pm2 start ecosystem.config.js --env production
  ```

- To view logs:

  ```bash
  pm2 logs oscar-broome-revenue
  ```

- To stop the app:

  ```bash
  pm2 stop oscar-broome-revenue
  ```

### Using Docker

- Build the Docker image:

  ```bash
  docker build -t oscar-broome-revenue .
  ```

- Run the Docker container:

  ```bash
  docker run -d -p 4000:4000 --env-file .env oscar-broome-revenue
  ```

- The app will be accessible at `http://localhost:4000`.

pm2 stop oscar-broome-revenue
