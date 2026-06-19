#!/bin/bash

# Oscar Broome Executive Portal - Production Deployment Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="oscar-broome-executive-portal"
TAG="${TAG:-latest}"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."

    command -v docker >/dev/null 2>&1 || { log_error "Docker is required but not installed."; exit 1; }
    command -v docker-compose >/dev/null 2>&1 || { log_error "Docker Compose is required but not installed."; exit 1; }

    log_success "Dependencies check passed"
}

build_application() {
    log_info "Building executive portal..."

    # Build the application image
    docker build -t ${PROJECT_NAME}:${TAG} .

    log_success "Executive portal built successfully"
}

deploy_services() {
    log_info "Deploying executive portal..."

    # Deploy with docker-compose
    docker-compose up -d

    log_success "Executive portal deployed successfully"
}

run_health_checks() {
    log_info "Running health checks..."

    # Wait for services to be ready
    sleep 10

    # Check if services are running
    if docker-compose ps | grep -q "Up"; then
        log_success "Services are running"
    else
        log_error "Services failed to start"
        docker-compose logs
        exit 1
    fi

    # Health check the application
    max_attempts=5
    attempt=1

    while [ $attempt -le $max_attempts ]; do
        log_info "Health check attempt $attempt/$max_attempts..."

        if curl -f http://localhost:8080/health >/dev/null 2>&1; then
            log_success "Executive portal health check passed"
            break
        else
            log_warning "Health check failed, retrying in 5 seconds..."
            sleep 5
            ((attempt++))
        fi
    done

    if [ $attempt -gt $max_attempts ]; then
        log_error "Executive portal health check failed after $max_attempts attempts"
        docker-compose logs executive-portal
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -b, --build         Build application image"
    echo "  -d, --deploy        Deploy services"
    echo "  -h, --health        Run health checks"
    echo "  --all               Run full deployment (build, deploy, health)"
    echo "  --help              Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  TAG                 Image tag (default: latest)"
}

# Main deployment logic
main() {
    local build=false
    local deploy=false
    local health=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -b|--build)
                build=true
                shift
                ;;
            -d|--deploy)
                deploy=true
                shift
                ;;
            -h|--health)
                health=true
                shift
                ;;
            --all)
                build=true
                deploy=true
                health=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Default to full deployment if no options specified
    if [ "$build" = false ] && [ "$deploy" = false ] && [ "$health" = false ]; then
        log_info "No options specified. Running full deployment..."
        build=true
        deploy=true
        health=true
    fi

    # Run selected operations
    check_dependencies

    if [ "$build" = true ]; then
        build_application
    fi

    if [ "$deploy" = true ]; then
        deploy_services
    fi

    if [ "$health" = true ]; then
        run_health_checks
    fi

    log_success "🎉 Oscar Broome Executive Portal deployment completed successfully!"
    log_info "Executive portal is available at: http://localhost:8080"
}

# Run main function
main "$@"
