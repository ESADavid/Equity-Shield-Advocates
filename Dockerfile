# Use official Node.js LTS image with specific patch version
FROM node:18-buster-slim

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies and clean npm cache
RUN apt-get update && apt-get upgrade -y && \
    npm install --production && npm cache clean --force && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Add a non-root user and switch to it
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Set environment variables for app
ENV PORT=4000
ENV ADMIN_USER=admin
ENV ADMIN_PASS=securepassword
ENV NODE_ENV=production

USER appuser

# Copy app source code
COPY --chown=appuser:appgroup . .

# Expose port
EXPOSE 4000

# Start the app with debugging and keep container alive
CMD ["sh", "-c", "echo Starting app... && node earnings_dashboard/server.js || tail -f /dev/null"]
