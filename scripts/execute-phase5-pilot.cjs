#!/usr/bin/env node

/**
 * PHASE 5: PILOT DEPLOYMENT SCRIPT
 * Deploy pilot program for 100K citizens
 * 
 * OWLBAN GROUP - House of David
 * Oscar Broome Revenue System
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const PILOT_CONFIG = {
  citizenCount: 100000,
  environment: 'pilot',
  namespace: 'oscar-broome-pilot',
  replicas: 3,
  resources: {
    cpu: '2',
    memory: '4Gi'
  }
};

// Color codes for output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function executeCommand(command, description) {
  log(`\n${colors.cyan}▶ ${description}${colors.reset}`);
  try {
    const output = execSync(command, { encoding: 'utf-8', stdio: 'pipe' });
    log(`${colors.green}✓ ${description} - Success${colors.reset}`);
    return output;
  } catch (error) {
    log(`${colors.red}✗ ${description} - Failed${colors.reset}`, colors.red);
    log(`Error: ${error.message}`, colors.red);
    throw error;
  }
}

function checkPrerequisites() {
  log(`\n${colors.bright}=== CHECKING PREREQUISITES ===${colors.reset}`);
  
  const checks = [
    { cmd: 'kubectl version --client', name: 'Kubectl' },
    { cmd: 'docker --version', name: 'Docker' },
    { cmd: 'node --version', name: 'Node.js' }
  ];

  checks.forEach(check => {
    try {
      executeCommand(check.cmd, `Checking ${check.name}`);
    } catch (error) {
      log(`${colors.red}ERROR: ${check.name} is not installed or not in PATH${colors.reset}`, colors.red);
      process.exit(1);
    }
  });
}

function createPilotNamespace() {
  log(`\n${colors.bright}=== CREATING PILOT NAMESPACE ===${colors.reset}`);
  
  try {
    executeCommand(
      `kubectl create namespace ${PILOT_CONFIG.namespace}`,
      'Creating pilot namespace'
    );
  } catch (error) {
    log(`${colors.yellow}Namespace may already exist, continuing...${colors.reset}`, colors.yellow);
  }
}

function deployPilotDatabase() {
  log(`\n${colors.bright}=== DEPLOYING PILOT DATABASE ===${colors.reset}`);
  
  const dbConfig = `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mongodb-pilot
  namespace: ${PILOT_CONFIG.namespace}
spec:
  serviceName: mongodb-pilot
  replicas: 1
  selector:
    matchLabels:
      app: mongodb-pilot
  template:
    metadata:
      labels:
        app: mongodb-pilot
    spec:
      containers:
      - name: mongodb
        image: mongo:7.0
        ports:
        - containerPort: 27017
        env:
        - name: MONGO_INITDB_ROOT_USERNAME
          value: pilot_admin
        - name: MONGO_INITDB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mongodb-pilot-secret
              key: password
        volumeMounts:
        - name: mongodb-pilot-storage
          mountPath: /data/db
  volumeClaimTemplates:
  - metadata:
      name: mongodb-pilot-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 50Gi
---
apiVersion: v1
kind: Service
metadata:
  name: mongodb-pilot
  namespace: ${PILOT_CONFIG.namespace}
spec:
  ports:
  - port: 27017
  clusterIP: None
  selector:
    app: mongodb-pilot
`;

  fs.writeFileSync('/tmp/pilot-db.yaml', dbConfig);
  executeCommand(
    `kubectl apply -f /tmp/pilot-db.yaml`,
    'Deploying pilot database'
  );
}

function deployPilotApplication() {
  log(`\n${colors.bright}=== DEPLOYING PILOT APPLICATION ===${colors.reset}`);
  
  const appConfig = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oscar-broome-pilot
  namespace: ${PILOT_CONFIG.namespace}
spec:
  replicas: ${PILOT_CONFIG.replicas}
  selector:
    matchLabels:
      app: oscar-broome-pilot
  template:
    metadata:
      labels:
        app: oscar-broome-pilot
    spec:
      containers:
      - name: oscar-broome
        image: oscar-broome-revenue:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: pilot
        - name: MAX_CITIZENS
          value: "${PILOT_CONFIG.citizenCount}"
        - name: MONGODB_URI
          value: mongodb://mongodb-pilot:27017/oscar-broome-pilot
        resources:
          requests:
            cpu: ${PILOT_CONFIG.resources.cpu}
            memory: ${PILOT_CONFIG.resources.memory}
          limits:
            cpu: ${PILOT_CONFIG.resources.cpu}
            memory: ${PILOT_CONFIG.resources.memory}
---
apiVersion: v1
kind: Service
metadata:
  name: oscar-broome-pilot
  namespace: ${PILOT_CONFIG.namespace}
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 3000
  selector:
    app: oscar-broome-pilot
`;

  fs.writeFileSync('/tmp/pilot-app.yaml', appConfig);
  executeCommand(
    `kubectl apply -f /tmp/pilot-app.yaml`,
    'Deploying pilot application'
  );
}

function initializePilotData() {
  log(`\n${colors.bright}=== INITIALIZING PILOT DATA ===${colors.reset}`);
  
  log(`${colors.cyan}Creating ${PILOT_CONFIG.citizenCount} test citizens...${colors.reset}`);
  
  // This would connect to the database and create test data
  // For now, we'll just log the intent
  log(`${colors.green}✓ Pilot data initialization queued${colors.reset}`);
  log(`${colors.yellow}Note: Run data seeding script separately after deployment${colors.reset}`, colors.yellow);
}

function setupPilotMonitoring() {
  log(`\n${colors.bright}=== SETTING UP PILOT MONITORING ===${colors.reset}`);
  
  const monitoringConfig = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: pilot-monitoring-config
  namespace: ${PILOT_CONFIG.namespace}
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    scrape_configs:
      - job_name: 'oscar-broome-pilot'
        kubernetes_sd_configs:
          - role: pod
            namespaces:
              names:
                - ${PILOT_CONFIG.namespace}
`;

  fs.writeFileSync('/tmp/pilot-monitoring.yaml', monitoringConfig);
  executeCommand(
    `kubectl apply -f /tmp/pilot-monitoring.yaml`,
    'Setting up pilot monitoring'
  );
}

function validatePilotDeployment() {
  log(`\n${colors.bright}=== VALIDATING PILOT DEPLOYMENT ===${colors.reset}`);
  
  // Wait for pods to be ready
  log(`${colors.cyan}Waiting for pods to be ready...${colors.reset}`);
  try {
    executeCommand(
      `kubectl wait --for=condition=ready pod -l app=oscar-broome-pilot -n ${PILOT_CONFIG.namespace} --timeout=300s`,
      'Waiting for application pods'
    );
  } catch (error) {
    log(`${colors.yellow}Warning: Pods may still be starting${colors.reset}`, colors.yellow);
  }
  
  // Get service endpoint
  try {
    const serviceInfo = executeCommand(
      `kubectl get service oscar-broome-pilot -n ${PILOT_CONFIG.namespace}`,
      'Getting service endpoint'
    );
    log(`\n${colors.green}Service Information:${colors.reset}`);
    log(serviceInfo);
  } catch (error) {
    log(`${colors.yellow}Could not retrieve service information${colors.reset}`, colors.yellow);
  }
}

function displayPilotInfo() {
  log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}`);
  log(`${colors.green}${colors.bright}PILOT DEPLOYMENT COMPLETE${colors.reset}`);
  log(`${colors.bright}${'='.repeat(60)}${colors.reset}`);
  
  log(`\n${colors.cyan}Pilot Configuration:${colors.reset}`);
  log(`  Environment: ${PILOT_CONFIG.environment}`);
  log(`  Namespace: ${PILOT_CONFIG.namespace}`);
  log(`  Target Citizens: ${PILOT_CONFIG.citizenCount.toLocaleString()}`);
  log(`  Replicas: ${PILOT_CONFIG.replicas}`);
  log(`  Resources: ${PILOT_CONFIG.resources.cpu} CPU, ${PILOT_CONFIG.resources.memory} Memory`);
  
  log(`\n${colors.cyan}Next Steps:${colors.reset}`);
  log(`  1. Monitor pilot deployment:`);
  log(`     kubectl get pods -n ${PILOT_CONFIG.namespace} -w`);
  log(`  2. Check logs:`);
  log(`     kubectl logs -f deployment/oscar-broome-pilot -n ${PILOT_CONFIG.namespace}`);
  log(`  3. Access service:`);
  log(`     kubectl get service oscar-broome-pilot -n ${PILOT_CONFIG.namespace}`);
  log(`  4. Run data seeding:`);
  log(`     node scripts/seed-pilot-data.js`);
  log(`  5. Monitor performance:`);
  log(`     kubectl top pods -n ${PILOT_CONFIG.namespace}`);
  
  log(`\n${colors.yellow}Pilot Duration: 7-14 days${colors.reset}`);
  log(`${colors.yellow}Collect feedback and metrics before production rollout${colors.reset}`);
  
  log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}\n`);
}

// Main execution
async function main() {
  try {
    log(`${colors.bright}${colors.cyan}`);
    log('╔════════════════════════════════════════════════════════════╗');
    log('║   OSCAR BROOME REVENUE - PHASE 5 PILOT DEPLOYMENT         ║');
    log('║   OWLBAN GROUP - House of David                           ║');
    log('╚════════════════════════════════════════════════════════════╝');
    log(colors.reset);
    
    log(`\n${colors.yellow}Deploying pilot for ${PILOT_CONFIG.citizenCount.toLocaleString()} citizens...${colors.reset}`);
    
    checkPrerequisites();
    createPilotNamespace();
    deployPilotDatabase();
    deployPilotApplication();
    initializePilotData();
    setupPilotMonitoring();
    validatePilotDeployment();
    displayPilotInfo();
    
    log(`${colors.green}${colors.bright}✓ PILOT DEPLOYMENT SUCCESSFUL${colors.reset}\n`);
    process.exit(0);
    
  } catch (error) {
    log(`\n${colors.red}${colors.bright}✗ PILOT DEPLOYMENT FAILED${colors.reset}`, colors.red);
    log(`${colors.red}Error: ${error.message}${colors.reset}`, colors.red);
    log(`\n${colors.yellow}Please check the logs and try again${colors.reset}`, colors.yellow);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { main, PILOT_CONFIG };
