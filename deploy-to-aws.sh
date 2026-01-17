#!/bin/bash

# OSCAR BROOME REVENUE - Deploy Application to AWS
# This script deploys the application to the AWS infrastructure

echo "🚀 OSCAR BROOME REVENUE - Application Deployment to AWS"
echo "======================================================="

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS CLI not configured. Please run 'aws configure' first."
    exit 1
fi

# Set variables
REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REPO="oscar-broome-revenue"
CLUSTER_NAME="oscar-broome-prod"
SERVICE_NAME="oscar-broome-service"
FAMILY_NAME="oscar-broome-revenue"

echo "📍 Region: $REGION"
echo "🏗️  Account: $ACCOUNT_ID"
echo "🐳 ECR Repo: $ECR_REPO"

# Step 1: Build Docker image
echo "🐳 Step 1: Building Docker image..."
docker build -t $ECR_REPO .

if [ $? -ne 0 ]; then
    echo "❌ Docker build failed"
    exit 1
fi
echo "✅ Docker image built successfully"

# Step 2: Authenticate with ECR
echo "🔐 Step 2: Authenticating with ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

if [ $? -ne 0 ]; then
    echo "❌ ECR authentication failed"
    exit 1
fi
echo "✅ ECR authentication successful"

# Step 3: Tag and push image
echo "📤 Step 3: Tagging and pushing Docker image..."
docker tag $ECR_REPO:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest

if [ $? -ne 0 ]; then
    echo "❌ Docker push failed"
    exit 1
fi
echo "✅ Docker image pushed to ECR"

# Step 4: Get infrastructure endpoints
echo "🔍 Step 4: Retrieving infrastructure endpoints..."

# Get DocumentDB endpoint
DOCDB_ENDPOINT=$(aws docdb describe-db-clusters --db-cluster-identifier oscar-broome-mongo-prod --region $REGION --query 'DBClusters[0].Endpoint' --output text)
if [ -z "$DOCDB_ENDPOINT" ]; then
    echo "❌ Could not retrieve DocumentDB endpoint"
    exit 1
fi
echo "📄 DocumentDB Endpoint: $DOCDB_ENDPOINT"

# Get Redis endpoint
REDIS_ENDPOINT=$(aws elasticache describe-cache-clusters --cache-cluster-id oscar-broome-redis-prod --region $REGION --query 'CacheClusters[0].CacheNodes[0].Endpoint.Address' --output text)
if [ -z "$REDIS_ENDPOINT" ]; then
    echo "❌ Could not retrieve Redis endpoint"
    exit 1
fi
echo "🔄 Redis Endpoint: $REDIS_ENDPOINT"

# Step 5: Update environment variables
echo "⚙️  Step 5: Updating environment variables..."
cat > .env.production << EOF
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://admin:TempPassword123!@$DOCDB_ENDPOINT:27017/oscar-broome-revenue?ssl=true&replicaSet=rs0
REDIS_URL=redis://$REDIS_ENDPOINT:6379
JWT_SECRET=$(openssl rand -hex 32)
SESSION_SECRET=$(openssl rand -hex 32)
LOG_LEVEL=info
EOF
echo "✅ Production environment file created"

# Step 6: Create ECS task definition
echo "📋 Step 6: Creating ECS task definition..."
cat > task-definition.json << EOF
{
    "family": "$FAMILY_NAME",
    "taskRoleArn": "arn:aws:iam::$ACCOUNT_ID:role/oscar-broome-ecs-task-execution-role",
    "executionRoleArn": "arn:aws:iam::$ACCOUNT_ID:role/oscar-broome-ecs-task-execution-role",
    "networkMode": "awsvpc",
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "1024",
    "memory": "2048",
    "containerDefinitions": [
        {
            "name": "oscar-broome-app",
            "image": "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest",
            "essential": true,
            "portMappings": [
                {
                    "containerPort": 3000,
                    "protocol": "tcp"
                }
            ],
            "environment": [
                {"name": "NODE_ENV", "value": "production"},
                {"name": "PORT", "value": "3000"},
                {"name": "MONGODB_URI", "value": "mongodb://admin:TempPassword123!@$DOCDB_ENDPOINT:27017/oscar-broome-revenue?ssl=true&replicaSet=rs0"},
                {"name": "REDIS_URL", "value": "redis://$REDIS_ENDPOINT:6379"},
                {"name": "JWT_SECRET", "value": "$(openssl rand -hex 32)"},
                {"name": "SESSION_SECRET", "value": "$(openssl rand -hex 32)"},
                {"name": "LOG_LEVEL", "value": "info"}
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/ecs/oscar-broome-revenue",
                    "awslogs-region": "$REGION",
                    "awslogs-stream-prefix": "ecs"
                }
            },
            "healthCheck": {
                "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
                "interval": 30,
                "timeout": 5,
                "retries": 3,
                "startPeriod": 60
            }
        }
    ]
}
EOF

# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json --region $REGION

if [ $? -ne 0 ]; then
    echo "❌ Task definition registration failed"
    exit 1
fi
echo "✅ ECS task definition registered"

# Step 7: Get subnet and security group IDs
echo "🔍 Step 7: Retrieving network configuration..."

# Get subnets
SUBNETS=$(aws ec2 describe-subnets --filters "Name=tag:Name,Values=oscar-broome-subnet" --region $REGION --query 'Subnets[*].SubnetId' --output text | tr '\n' ',' | sed 's/,$//')
if [ -z "$SUBNETS" ]; then
    echo "❌ Could not retrieve subnet IDs"
    exit 1
fi

# Get security group
SG_ID=$(aws ec2 describe-security-groups --group-names oscar-broome-ecs-sg --region $REGION --query 'SecurityGroups[0].GroupId' --output text)
if [ -z "$SG_ID" ]; then
    echo "❌ Could not retrieve security group ID"
    exit 1
fi

echo "📡 Subnets: $SUBNETS"
echo "🔒 Security Group: $SG_ID"

# Step 8: Create or update ECS service
echo "🚢 Step 8: Creating/updating ECS service..."

# Check if service exists
SERVICE_EXISTS=$(aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE_NAME --region $REGION --query 'services[0].serviceName' --output text 2>/dev/null)

if [ "$SERVICE_EXISTS" = "$SERVICE_NAME" ]; then
    echo "🔄 Updating existing service..."
    aws ecs update-service \
        --cluster $CLUSTER_NAME \
        --service $SERVICE_NAME \
        --task-definition $FAMILY_NAME \
        --region $REGION \
        --force-new-deployment
else
    echo "🆕 Creating new service..."
    aws ecs create-service \
        --cluster $CLUSTER_NAME \
        --service-name $SERVICE_NAME \
        --task-definition $FAMILY_NAME \
        --desired-count 1 \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG_ID],assignPublicIp=ENABLED}" \
        --region $REGION
fi

if [ $? -ne 0 ]; then
    echo "❌ Service creation/update failed"
    exit 1
fi
echo "✅ ECS service deployed"

# Step 9: Wait for service to be stable
echo "⏳ Step 9: Waiting for service to stabilize..."
aws ecs wait services-stable --cluster $CLUSTER_NAME --services $SERVICE_NAME --region $REGION

if [ $? -ne 0 ]; then
    echo "❌ Service failed to stabilize"
    exit 1
fi
echo "✅ Service stabilized"

# Step 10: Get ALB DNS name
echo "🌐 Step 10: Retrieving ALB endpoint..."
ALB_DNS=$(aws elbv2 describe-load-balancers --names oscar-broome-alb --region $REGION --query 'LoadBalancers[0].DNSName' --output text)

if [ -z "$ALB_DNS" ]; then
    echo "❌ Could not retrieve ALB DNS name"
    exit 1
fi

echo "🎉 DEPLOYMENT COMPLETE!"
echo "======================"
echo ""
echo "🌐 Application URL: http://$ALB_DNS"
echo "📊 Health Check: http://$ALB_DNS/health"
echo "📄 API Documentation: http://$ALB_DNS/api/docs"
echo ""
echo "🔐 Database: $DOCDB_ENDPOINT"
echo "🔄 Redis: $REDIS_ENDPOINT"
echo ""
echo "⚠️  IMPORTANT NEXT STEPS:"
echo "1. Update DNS records to point to ALB"
echo "2. Configure SSL/TLS certificate"
echo "3. Set up production credentials (JPMorgan, etc.)"
echo "4. Configure monitoring and alerts"
echo "5. Test all endpoints thoroughly"
echo ""
echo "🧪 Test Commands:"
echo "curl http://$ALB_DNS/health"
echo "curl http://$ALB_DNS/api/status"
echo ""
echo "📊 Monitor service:"
echo "aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE_NAME --region $REGION"
echo ""
echo "🚀 Ready to serve 11.5M citizens with $33K/year UBI!"

# Clean up
rm task-definition.json

echo ""
echo "✅ Application successfully deployed to AWS!"
