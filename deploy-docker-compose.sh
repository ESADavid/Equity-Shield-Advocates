#!/bin/bash

# OSCAR BROOME REVENUE - Docker Compose Deployment Script
# Simple, fast deployment using Docker Compose for development/production

set -e

echo "🚀 OSCAR BROOME REVENUE - DOCKER COMPOSE DEPLOYMENT"
echo "==================================================="

START_TIME=$(date +%s)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Configuration
COMPOSE_FILE="docker-compose.production.yml"
PROJECT_NAME="oscar-broome-revenue"

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        error "Docker not found. Please install Docker."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose not found. Please install Docker Compose."
        exit 1
    fi

    if [ ! -f "$COMPOSE_FILE" ]; then
        error "Docker Compose file '$COMPOSE_FILE' not found."
        exit 1
    fi

    success "Prerequisites check passed"
}

# Deploy with Docker Compose
deploy_compose() {
    local environment=${1:-production}

    log "Deploying with Docker Compose ($environment environment)..."

    # Stop existing containers
    log "Stopping existing containers..."
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down || true

    # Remove old images to ensure fresh build
    log "Cleaning up old images..."
    docker image prune -f || true

    # Build and start services
    log "Building and starting services..."
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d --build

    # Wait for services to be healthy
    log "Waiting for services to be healthy..."
    max_attempts=30
    attempt=1

    while [ $attempt -le $max_attempts ]; do
        # Check if all containers are running
        running_containers=$(docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps | grep "Up" | wc -l)
        total_containers=$(docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps | grep -E "(Up|Exit)" | wc -l)

        if [ "$running_containers" -eq "$total_containers" ] && [ "$total_containers" -gt 0 ]; then
            success "All containers are running"
            break
        fi

        log "Waiting for containers... ($running_containers/$total_containers up, attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done

    if [ $attempt -gt $max_attempts ]; then
        warning "Container health check timed out, but deployment may still be successful"
    fi

    # Show service status
    log "Service status:"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps

    # Get service URLs
    get_service_urls
}

# Get service URLs
get_service_urls() {
    log "Getting service URLs..."

    # Get container ports
    app_port=$(docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME port app 3000 2>/dev/null | cut -d: -f2)

    if [ -n "$app_port" ]; then
        echo ""
        echo "🌐 SERVICE URLS"
        echo "==============="
        echo "📱 Application: http://localhost:$app_port"
        echo "💚 Health Check: http://localhost:$app_port/health"
    fi
}

# Show logs
show_logs() {
    log "Showing recent logs..."
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs --tail=50
}

# Main deployment process
main() {
    local environment=${1:-production}
    local show_logs_flag=${2:-false}

    log "Starting Docker Compose deployment process..."

    check_prerequisites
    deploy_compose $environment

    # Calculate deployment time
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    success "🎉 DOCKER COMPOSE DEPLOYMENT COMPLETED IN ${DURATION}s"
    echo ""
    echo "📊 DEPLOYMENT SUMMARY"
    echo "===================="
    echo "🐳 Project: $PROJECT_NAME"
    echo "📄 Compose File: $COMPOSE_FILE"
    echo "🔧 View status: docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps"
    echo "📊 View logs: docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f"
    echo "🛑 Stop services: docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down"

    if [ "$show_logs_flag" = true ]; then
        echo ""
        show_logs
    fi
}

# Show usage
usage() {
    echo "Usage: $0 [environment] [--logs]"
    echo ""
    echo "Environments:"
    echo "  production    Production environment (default)"
    echo "  staging       Staging environment"
    echo "  development   Development environment"
    echo ""
    echo "Options:"
    echo "  --logs        Show logs after deployment"
    echo ""
    echo "Examples:"
    echo "  $0                    # Deploy to production"
    echo "  $0 staging           # Deploy to staging"
    echo "  $0 production --logs # Deploy to production and show logs"
}

# Parse arguments
ENVIRONMENT="production"
SHOW_LOGS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --logs)
            SHOW_LOGS=true
            shift
            ;;
        production|staging|development)
            ENVIRONMENT="$1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run main function
main "$ENVIRONMENT" "$SHOW_LOGS"
