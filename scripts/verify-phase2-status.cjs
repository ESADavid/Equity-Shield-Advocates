#!/usr/bin/env node

/**
 * Phase 2 Status Verification Script
 * Checks actual implementation status of all Phase 2 files
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 PHASE 2 STATUS VERIFICATION\n');
console.log('='.repeat(60));

const phase2Files = [
  // UBI System
  { path: 'models/UBIPayment.js', task: 'UBI System', required: true },
  { path: 'services/ubiPaymentService.js', task: 'UBI System', required: true },
  { path: 'routes/ubiPaymentRoutes.js', task: 'UBI System', required: true },
  { path: 'blockchain/ubiLedger.js', task: 'UBI System', required: true },

  // Education System
  { path: 'models/Course.js', task: 'Education System', required: true },
  {
    path: 'services/aiLearningService.js',
    task: 'Education System',
    required: true,
  },
  {
    path: 'routes/educationRoutes.js',
    task: 'Education System',
    required: true,
  },

  // Compliance & Notifications
  {
    path: 'services/complianceMonitoringService.js',
    task: 'Compliance',
    required: true,
  },
  {
    path: 'services/multiChannelNotificationService.js',
    task: 'Notifications',
    required: true,
  },
  {
    path: 'routes/notificationRoutes.js',
    task: 'Notifications',
    required: true,
  },

  // Partner Integration
  { path: 'models/Partner.js', task: 'Partner System', required: true },
  {
    path: 'services/partnerCoordinationService.js',
    task: 'Partner System',
    required: true,
  },
  {
    path: 'services/pmcIntegrationService.js',
    task: 'PMC Integration',
    required: true,
  },
  { path: 'routes/partnerRoutes.js', task: 'Partner System', required: true },

  // Citizen Portal
  {
    path: 'services/citizenPortalService.js',
    task: 'Citizen Portal',
    required: true,
  },
  {
    path: 'routes/citizenPortalRoutes.js',
    task: 'Citizen Portal',
    required: true,
  },

  // Dashboards (optional)
  {
    path: 'earnings_dashboard/src/UBIAdminDashboard.jsx',
    task: 'UBI Dashboard',
    required: false,
  },
  {
    path: 'earnings_dashboard/src/EducationDashboard.jsx',
    task: 'Education Dashboard',
    required: false,
  },
  {
    path: 'earnings_dashboard/src/PartnerDashboard.jsx',
    task: 'Partner Dashboard',
    required: false,
  },
  {
    path: 'earnings_dashboard/src/CitizenDashboard.jsx',
    task: 'Citizen Dashboard',
    required: false,
  },
];

const results = {
  exists: [],
  missing: [],
  hasCode: [],
  isEmpty: [],
};

console.log('\n📋 Checking Phase 2 Files...\n');

phase2Files.forEach((file) => {
  const filePath = path.join(process.cwd(), file.path);
  const exists = fs.existsSync(filePath);

  if (exists) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').filter((line) => line.trim()).length;
    const hasSubstantialCode = lines > 50;

    if (hasSubstantialCode) {
      results.hasCode.push({ ...file, lines });
      console.log(`✅ ${file.path} (${lines} lines)`);
    } else {
      results.isEmpty.push({ ...file, lines });
      console.log(`⚠️  ${file.path} (${lines} lines - may be stub)`);
    }
    results.exists.push(file);
  } else {
    results.missing.push(file);
    if (file.required) {
      console.log(`❌ ${file.path} - MISSING (REQUIRED)`);
    } else {
      console.log(`⚪ ${file.path} - Missing (optional)`);
    }
  }
});

console.log('\n' + '='.repeat(60));
console.log('\n📊 VERIFICATION SUMMARY\n');

console.log(`Total Files Checked: ${phase2Files.length}`);
console.log(`Files Exist: ${results.exists.length}`);
console.log(`Files with Code: ${results.hasCode.length}`);
console.log(`Empty/Stub Files: ${results.isEmpty.length}`);
console.log(`Missing Files: ${results.missing.length}`);

const requiredFiles = phase2Files.filter((f) => f.required);
const requiredExists = results.exists.filter((f) => f.required);
const requiredMissing = results.missing.filter((f) => f.required);

console.log(`\nRequired Files: ${requiredFiles.length}`);
console.log(`Required Exist: ${requiredExists.length}`);
console.log(`Required Missing: ${requiredMissing.length}`);

console.log('\n' + '='.repeat(60));
console.log('\n🎯 PHASE 2 STATUS\n');

const completionRate = Math.round(
  (results.hasCode.length / requiredFiles.length) * 100
);
console.log(`Completion Rate: ${completionRate}%`);

if (requiredMissing.length === 0 && results.isEmpty.length === 0) {
  console.log('\n✅ PHASE 2 IS COMPLETE!');
  console.log('   All required files exist with substantial code.');
} else if (requiredMissing.length > 0) {
  console.log('\n❌ PHASE 2 IS INCOMPLETE');
  console.log(`   ${requiredMissing.length} required file(s) missing:`);
  requiredMissing.forEach((f) => console.log(`   - ${f.path}`));
} else if (results.isEmpty.length > 0) {
  console.log('\n⚠️  PHASE 2 NEEDS WORK');
  console.log(`   ${results.isEmpty.length} file(s) are stubs/empty:`);
  results.isEmpty.forEach((f) =>
    console.log(`   - ${f.path} (${f.lines} lines)`)
  );
}

console.log('\n' + '='.repeat(60));
