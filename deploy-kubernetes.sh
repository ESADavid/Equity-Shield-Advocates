#!/bin/bash

# OSCAR BROOME REVENUE - Kubernetes Deployment Script
# Production-ready Kubernetes deployment with high availability

set -e

echo "🚀 OSCAR BROOME REVENUE - KUBERNETES DEPLOYMENT"
echo "==============================================="

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

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        error "kubectl not found. Please install kubectl."
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        error "Unable to connect to Kubernetes cluster."
        exit 1
    fi

    success "Prerequisites check passed"
}

# Deploy to Kubernetes
deploy_kubernetes() {
    local environment=${1:-production}

    log "Deploying to Kubernetes ($environment environment)..."

    # Create namespace if it doesn't exist
    kubectl create namespace oscar-broome-$environment --dry-run=client -o yaml | kubectl apply -f -

    # Deploy database
    log "Deploying database..."
    kubectl apply -f k8s/database-production.yml -n oscar-broome-$environment

    # Wait for database to be ready
    log "Waiting for database to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/oscar-broome-db -n oscar-broome-$environment

    # Deploy application
    log "Deploying application..."
    kubectl apply -f k8s/production-deployment.yml -n oscar-broome-$environment

    # Deploy monitoring stack
    log "Deploying monitoring stack..."
    kubectl apply -f k8s/monitoring-stack.yml -n oscar-broome-$environment

    # Wait for application to be ready
    log "Waiting for application to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/oscar-broome-app -n oscar-broome-$environment

    # Get service information
    local service_ip=$(kubectl get svc oscar-broome-app -n oscar-broome-$environment -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    local service_port=$(kubectl get svc oscar-broome-app -n oscar-broome-$environment -o jsonpath='{.spec.ports[0].port}')

    success "Kubernetes deployment completed"
    echo ""
    echo "📊 DEPLOYMENT SUMMARY"
    echo "===================="
    echo "🌐 Service URL: http://$service_ip:$service_port"
    echo "📝 Namespace: oscar-broome-$environment"
    echo "🔧 Check status: kubectl get all -n oscar-broome-$environment"
    echo "📊 View logs: kubectl logs -f deployment/oscar-broome-app -n oscar-broome-$environment"
}

# Main deployment process
main() {
    local environment=${1:-production}

    log "Starting Kubernetes deployment process..."

    check_prerequisites
    deploy_kubernetes $environment

    # Calculate deployment time
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    success "🎉 KUBERNETES DEPLOYMENT COMPLETED IN ${DURATION}s"
}

# Show usage if no arguments provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 [environment]"
    echo "Environments: production, staging, development"
    echo "Default: production"
    exit 1
fi

# Run main function
main "$@"
