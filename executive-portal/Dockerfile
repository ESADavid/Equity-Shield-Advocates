# Executive Portal - Production Dockerfile
FROM nginx:alpine

# Copy the executive portal files
COPY login.html /usr/share/nginx/html/index.html
COPY styles.css /usr/share/nginx/html/
COPY executive-login.js /usr/share/nginx/html/

# Copy nginx configuration for executive portal
COPY nginx.conf /etc/nginx/nginx.conf

# Create logs directory
RUN mkdir -p /var/log/nginx

# Expose port 8080 for executive portal
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
