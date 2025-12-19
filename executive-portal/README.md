# Oscar Broome Executive Portal

A production-ready executive login portal for Oscar Broome's revenue systems, built with modern web technologies and containerized for easy deployment.

## 🚀 Features

- **Secure Login Form**: Email, password, and 2FA authentication
- **Real-time Validation**: Client-side validation with immediate feedback
- **Password Strength Indicator**: Visual feedback with color-coded strength levels
- **Responsive Design**: Mobile-first approach with professional styling
- **Accessibility**: WCAG compliant with proper ARIA labels and keyboard navigation
- **Production Ready**: Containerized with Docker and Nginx

## 🏗️ Architecture

```text
Executive Portal
├── login.html          # Main login interface
├── styles.css          # Professional styling
├── executive-login.js  # Client-side validation logic
├── Dockerfile          # Container build configuration
├── nginx.conf          # Web server configuration
├── docker-compose.yml  # Container orchestration
└── deploy.sh          # Deployment automation script
```

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 1GB RAM minimum
- 500MB free disk space

## 🚀 Quick Start

### Development Mode (Current)

The portal is currently running in development mode at `http://localhost:8080`

### Production Deployment

1. **Navigate to the executive portal directory:**

   ```bash
   cd owlban_revenue_repo/executive-portal
   ```

2. **Deploy with one command:**

   ```bash
   ./deploy.sh --all
   ```

   Or step-by-step:

   ```bash
   ./deploy.sh --build    # Build the container
   ./deploy.sh --deploy   # Start the services
   ./deploy.sh --health   # Verify deployment
   ```

3. **Access the portal:**
   - Production URL: `http://localhost:8080`
   - Health Check: `http://localhost:8080/health`

## 🔧 Configuration

### Environment Variables

The portal uses the following configuration (set in docker-compose.yml):

```yaml
ports:
  - '8080:8080' # Host:Container port mapping
```

### Nginx Configuration

- **Port**: 8080
- **Security Headers**: XSS protection, content type options, frame options
- **Compression**: Gzip enabled for better performance
- **Caching**: Static assets cached for 1 year

## 🧪 Testing

### Manual Testing Checklist

- [ ] Form validation (email format, password strength, 2FA)
- [ ] Responsive design (mobile, tablet, desktop)
- [ ] Accessibility (keyboard navigation, screen readers)
- [ ] Browser compatibility (Chrome, Firefox, Safari, Edge)
- [ ] Security headers and HTTPS readiness

### Automated Health Checks

The deployment script includes automated health checks:

```bash
./deploy.sh --health
```

## 🔒 Security Features

- **Input Validation**: Client-side and server-side validation
- **Security Headers**: XSS protection, content sniffing prevention
- **HTTPS Ready**: SSL/TLS configuration prepared
- **Container Security**: Non-root user, minimal attack surface

## 📊 Monitoring

### Health Endpoints

- **Application Health**: `GET /health`
- **Container Status**: Docker health checks
- **Logs**: Available via `docker-compose logs`

### Performance Metrics

- Response times
- Error rates
- Resource utilization
- User experience metrics

## 🔄 Updates and Maintenance

### Rolling Updates

```bash
# Update the application
git pull origin main

# Rebuild and redeploy
./deploy.sh --build --deploy --health
```

### Backup Strategy

- Container images are versioned
- Configuration files are in version control
- Logs are persisted in Docker volumes

## 🐛 Troubleshooting

### Common Issues

1. **Port 8080 already in use:**

   ```bash
   # Check what's using the port
   netstat -tulpn | grep :8080

   # Change port in docker-compose.yml
   ports:
     - "8081:8080"
   ```

2. **Container fails to start:**

   ```bash
   # Check logs
   docker-compose logs executive-portal

   # Rebuild without cache
   docker-compose build --no-cache
   ```

3. **Health check fails:**

   ```bash
   # Manual health check
   curl http://localhost:8080/health

   # Check container status
   docker-compose ps
   ```

### Debug Commands

```bash
# View real-time logs
docker-compose logs -f executive-portal

# Access container shell
docker-compose exec executive-portal sh

# Restart services
docker-compose restart executive-portal

# Clean up
docker-compose down
docker system prune -f
```

## 📚 API Reference

### Health Check Endpoint

```http
GET /health
```

**Response:**

```json
"healthy"
```

**Status Codes:**

- `200` - Service is healthy
- `500` - Service is unhealthy

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with proper testing
4. Submit a pull request

## 📄 License

This project is proprietary software for Oscar Broome's revenue systems.

## 🆘 Support

For technical support or questions:

- Check the troubleshooting section above
- Review Docker and Nginx documentation
- Contact the development team

---

**🎯 Production Status**: Ready for deployment

**📍 Access URL**: <http://localhost:8080>

**✅ Last Tested**: All features verified working
