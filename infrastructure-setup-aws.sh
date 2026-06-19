#!/bin/bash

# OSCAR BROOME REVENUE - AWS Infrastructure Setup
# This script sets up the complete AWS infrastructure for production deployment

echo "🚀 OSCAR BROOME REVENUE - AWS Infrastructure Setup"
echo "=================================================="

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI first."
    echo "Visit: https://aws.amazon.com/cli/"
    exit 1
fi

# Check if user is logged in
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ Not logged in to AWS. Please run 'aws configure' first."
    exit 1
fi

echo "✅ AWS CLI configured and authenticated"

# Set variables
REGION="us-east-1"
CLUSTER_NAME="oscar-broome-prod"
DB_INSTANCE_IDENTIFIER="oscar-broome-mongo-prod"
CACHE_CLUSTER_ID="oscar-broome-redis-prod"
VPC_NAME="oscar-broome-vpc"
SUBNET_GROUP_NAME="oscar-broome-subnets"

echo "📍 Using region: $REGION"
echo "🏗️  Setting up infrastructure..."

# 1. Create VPC
echo "🏗️  Step 1: Creating VPC..."
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 --region $REGION --query 'Vpc.VpcId' --output text)
aws ec2 create-tags --resources $VPC_ID --tags Key=Name,Value=$VPC_NAME --region $REGION

# Create subnets
echo "🏗️  Step 2: Creating subnets..."
SUBNET1_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone ${REGION}a --region $REGION --query 'Subnet.SubnetId' --output text)
SUBNET2_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 --availability-zone ${REGION}b --region $REGION --query 'Subnet.SubnetId' --output text)
SUBNET3_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.3.0/24 --availability-zone ${REGION}c --region $REGION --query 'Subnet.SubnetId' --output text)

# Create Internet Gateway
echo "🏗️  Step 3: Creating Internet Gateway..."
IGW_ID=$(aws ec2 create-internet-gateway --region $REGION --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID --region $REGION

# Create route table
echo "🏗️  Step 4: Creating route table..."
RT_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --region $REGION --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id $RT_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID --region $REGION

# Associate subnets with route table
aws ec2 associate-route-table --subnet-id $SUBNET1_ID --route-table-id $RT_ID --region $REGION
aws ec2 associate-route-table --subnet-id $SUBNET2_ID --route-table-id $RT_ID --region $REGION
aws ec2 associate-route-table --subnet-id $SUBNET3_ID --route-table-id $RT_ID --region $REGION

# 2. Create Security Groups
echo "🔒 Step 5: Creating security groups..."

# Application Load Balancer Security Group
ALB_SG_ID=$(aws ec2 create-security-group --group-name oscar-broome-alb-sg --description "ALB Security Group" --vpc-id $VPC_ID --region $REGION --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $ALB_SG_ID --protocol tcp --port 80 --cidr 0.0.0.0/0 --region $REGION
aws ec2 authorize-security-group-ingress --group-id $ALB_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 --region $REGION

# ECS Security Group
ECS_SG_ID=$(aws ec2 create-security-group --group-name oscar-broome-ecs-sg --description "ECS Security Group" --vpc-id $VPC_ID --region $REGION --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $ECS_SG_ID --protocol tcp --port 3000 --source-group $ALB_SG_ID --region $REGION

# Database Security Group
DB_SG_ID=$(aws ec2 create-security-group --group-name oscar-broome-db-sg --description "Database Security Group" --vpc-id $VPC_ID --region $REGION --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $DB_SG_ID --protocol tcp --port 27017 --source-group $ECS_SG_ID --region $REGION

# Redis Security Group
REDIS_SG_ID=$(aws ec2 create-security-group --group-name oscar-broome-redis-sg --description "Redis Security Group" --vpc-id $VPC_ID --region $REGION --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $REDIS_SG_ID --protocol tcp --port 6379 --source-group $ECS_SG_ID --region $REGION

# 3. Create DB Subnet Group
echo "🗄️  Step 6: Creating DB subnet group..."
aws rds create-db-subnet-group \
    --db-subnet-group-name $SUBNET_GROUP_NAME \
    --db-subnet-group-description "Oscar Broome DB Subnet Group" \
    --subnet-ids $SUBNET1_ID $SUBNET2_ID $SUBNET3_ID \
    --region $REGION

# 4. Create MongoDB DocumentDB Cluster
echo "🗄️  Step 7: Creating MongoDB DocumentDB cluster..."
aws docdb create-db-cluster \
    --db-cluster-identifier $DB_INSTANCE_IDENTIFIER \
    --engine docdb \
    --master-username admin \
    --master-user-password "TempPassword123!" \
    --db-subnet-group-name $SUBNET_GROUP_NAME \
    --vpc-security-group-ids $DB_SG_ID \
    --region $REGION

# Wait for cluster to be available
echo "⏳ Waiting for DocumentDB cluster to be available..."
aws docdb wait db-cluster-available --db-cluster-identifier $DB_INSTANCE_IDENTIFIER --region $REGION

# Create DB instance
aws docdb create-db-instance \
    --db-instance-identifier "${DB_INSTANCE_IDENTIFIER}-instance" \
    --db-instance-class db.r5.large \
    --db-cluster-identifier $DB_INSTANCE_IDENTIFIER \
    --region $REGION

# 5. Create ElastiCache Redis Cluster
echo "🔄 Step 8: Creating Redis ElastiCache cluster..."
aws elasticache create-cache-cluster \
    --cache-cluster-id $CACHE_CLUSTER_ID \
    --cache-node-type cache.r5.large \
    --engine redis \
    --num-cache-nodes 1 \
    --cache-subnet-group-name $SUBNET_GROUP_NAME \
    --security-group-ids $REDIS_SG_ID \
    --region $REGION

# 6. Create ECR Repository
echo "🐳 Step 9: Creating ECR repository..."
aws ecr create-repository --repository-name oscar-broome-revenue --region $REGION

# 7. Create ECS Cluster
echo "🚢 Step 10: Creating ECS cluster..."
aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $REGION

# 8. Create Application Load Balancer
echo "⚖️  Step 11: Creating Application Load Balancer..."
ALB_ARN=$(aws elbv2 create-load-balancer \
    --name oscar-broome-alb \
    --subnets $SUBNET1_ID $SUBNET2_ID $SUBNET3_ID \
    --security-groups $ALB_SG_ID \
    --region $REGION \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text)

# Create target group
TARGET_GROUP_ARN=$(aws elbv2 create-target-group \
    --name oscar-broome-targets \
    --protocol HTTP \
    --port 3000 \
    --vpc-id $VPC_ID \
    --target-type ip \
    --region $REGION \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text)

# Create listener
aws elbv2 create-listener \
    --load-balancer-arn $ALB_ARN \
    --protocol HTTP \
    --port 80 \
    --default-actions Type=forward,TargetGroupArn=$TARGET_GROUP_ARN \
    --region $REGION

# 9. Create CloudWatch Log Group
echo "📊 Step 12: Creating CloudWatch log group..."
aws logs create-log-group --log-group-name /ecs/oscar-broome-revenue --region $REGION

# 10. Create IAM Role for ECS Task Execution
echo "🔑 Step 13: Creating IAM role for ECS..."
cat > ecs-task-execution-role.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ecs-tasks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

aws iam create-role \
    --role-name oscar-broome-ecs-task-execution-role \
    --assume-role-policy-document file://ecs-task-execution-role.json \
    --region $REGION

aws iam attach-role-policy \
    --role-name oscar-broome-ecs-task-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy \
    --region $REGION

# Clean up
rm ecs-task-execution-role.json

echo "🎉 AWS Infrastructure Setup Complete!"
echo "====================================="
echo ""
echo "📋 Infrastructure Created:"
echo "• VPC: $VPC_ID"
echo "• Subnets: $SUBNET1_ID, $SUBNET2_ID, $SUBNET3_ID"
echo "• Security Groups: ALB, ECS, DB, Redis"
echo "• DocumentDB Cluster: $DB_INSTANCE_IDENTIFIER"
echo "• ElastiCache Redis: $CACHE_CLUSTER_ID"
echo "• ECS Cluster: $CLUSTER_NAME"
echo "• ALB: $(aws elbv2 describe-load-balancers --load-balancer-arns $ALB_ARN --region $REGION --query 'LoadBalancers[0].DNSName' --output text)"
echo "• ECR Repository: oscar-broome-revenue"
echo ""
echo "⚠️  IMPORTANT NEXT STEPS:"
echo "1. Update your .env file with the new database and Redis endpoints"
echo "2. Build and push Docker image to ECR"
echo "3. Create ECS task definition and service"
echo "4. Update DNS records to point to ALB"
echo "5. Obtain SSL certificate and configure HTTPS"
echo ""
echo "💰 Estimated Monthly Cost: $5,000 - $8,000"
echo ""
echo "🔐 Security Reminder: Change default passwords and rotate credentials regularly"
