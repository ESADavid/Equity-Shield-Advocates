# Use official Node.js LTS image
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy app source code
COPY earnings_dashboard ./earnings_dashboard
COPY owlban_repos ./owlban_repos

# Expose port
EXPOSE 4000

# Start the server
CMD ["node", "earnings_dashboard/server_rebuilt.js"]
