# Use official Node.js LTS image with specific patch version
FROM node:18.16.0-alpine

# Create app directory
WORKDIR /usr/src/app

# Add a non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Copy package files
COPY package*.json ./

# Install dependencies and clean npm cache
RUN npm install --production && npm cache clean --force

# Copy app source code
COPY --chown=appuser:appgroup . .

# Expose port
EXPOSE 4000

# Start the app
CMD ["node", "earnings_dashboard/server.js"]
