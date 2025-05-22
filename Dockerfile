# Use official Node.js LTS image with specific patch version
FROM node:18.16.0-slim

# Create app directory
WORKDIR /usr/src/app

# Add a non-root user and switch to it
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
USER appuser

# Copy package files
COPY package*.json ./

# Install dependencies and clean npm cache
RUN apt-get update && apt-get upgrade -y && \
    npm install --production && npm cache clean --force && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy app source code
COPY --chown=appuser:appgroup . .

# Expose port
EXPOSE 4000

# Start the app
CMD ["node", "earnings_dashboard/server.js"]
