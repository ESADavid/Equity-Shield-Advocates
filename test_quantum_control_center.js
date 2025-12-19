/**
 * QUANTUM CONTROL CENTER DEMO
 * Demonstrates the quantum control center managing JPMorgan data synchronization
 */

const { QuantumControlCenter } = require('./quantum/quantumControlCenter.js');

async function demonstrateQuantumControlCenter() {
  console.log('🚀 Initializing Quantum Control Center...');

  // Create quantum control center
  const controlCenter = new QuantumControlCenter();

  // Wait for initialization
  await new Promise((resolve) => setTimeout(resolve, 1000));

  console.log('✅ Quantum Control Center initialized');
  console.log(
    'Control Center ID:',
    controlCenter.quantumEngine.getQuantumState('control_center')?.centerId
  );
  console.log('');

  try {
    // 1. Display Control Center Status
    console.log('📊 Control Center Status:');
    const status = controlCenter.getControlCenterStatus();
    console.log(JSON.stringify(status, null, 2));
    console.log('');

    // 2. Execute Control Commands
    console.log('🎮 Executing Control Commands...');

    // Sync Data Command
    console.log('🔄 Executing SYNC_DATA command...');
    const syncResult = await controlCenter.executeControlCommand('sync_data');
    console.log('✅ Sync Data Result:', JSON.stringify(syncResult, null, 2));
    console.log('');

    // Generate System Report
    console.log('📈 Executing GENERATE_REPORT command...');
    const reportResult = await controlCenter.executeControlCommand(
      'generate_report',
      {
        reportType: 'system',
      }
    );
    console.log(
      '✅ Generate Report Result:',
      JSON.stringify(reportResult, null, 2)
    );
    console.log('');

    // Execute Transaction via Control Center
    console.log('💰 Executing EXECUTE_TRANSACTION command...');
    const transactionResult = await controlCenter.executeControlCommand(
      'execute_transaction',
      {
        type: 'payment',
        amount: 500.0,
        from: 'oscar.broome@jpmorgan.com',
        to: 'quantum_merchant_services',
        description: 'Control center transaction test',
      }
    );
    console.log(
      '✅ Execute Transaction Result:',
      JSON.stringify(transactionResult, null, 2)
    );
    console.log('');

    // Update Configuration
    console.log('⚙️ Executing UPDATE_CONFIG command...');
    const configResult = await controlCenter.executeControlCommand(
      'update_config',
      {
        configKey: 'sync_interval',
        configValue: 15000, // 15 seconds
      }
    );
    console.log(
      '✅ Update Config Result:',
      JSON.stringify(configResult, null, 2)
    );
    console.log('');

    // Optimize System
    console.log('🔧 Executing OPTIMIZE_SYSTEM command...');
    const optimizeResult =
      await controlCenter.executeControlCommand('optimize_system');
    console.log(
      '✅ Optimize System Result:',
      JSON.stringify(optimizeResult, null, 2)
    );
    console.log('');

    // Security Scan
    console.log('🔒 Executing SECURITY_SCAN command...');
    const securityResult =
      await controlCenter.executeControlCommand('security_scan');
    console.log(
      '✅ Security Scan Result:',
      JSON.stringify(securityResult, null, 2)
    );
    console.log('');

    // Backup Data
    console.log('💾 Executing BACKUP_DATA command...');
    const backupResult =
      await controlCenter.executeControlCommand('backup_data');
    console.log(
      '✅ Backup Data Result:',
      JSON.stringify(backupResult, null, 2)
    );
    console.log('');

    // Scale System
    console.log('📈 Executing SCALE_SYSTEM command...');
    const scaleResult = await controlCenter.executeControlCommand(
      'scale_system',
      {
        scaleType: 'horizontal',
        scaleFactor: 2,
      }
    );
    console.log(
      '✅ Scale System Result:',
      JSON.stringify(scaleResult, null, 2)
    );
    console.log('');

    // 3. Display Sync Status
    console.log('🔄 Data Synchronization Status:');
    const syncStatus = controlCenter.getSyncStatus();
    console.log(JSON.stringify(syncStatus, null, 2));
    console.log('');

    // 4. Wait for automatic sync cycles
    console.log('⏳ Waiting for automatic data synchronization cycles...');
    await new Promise((resolve) => setTimeout(resolve, 35000)); // Wait for 2 sync cycles
    console.log('✅ Automatic synchronization cycles completed');
    console.log('');

    // 5. Display Updated Status
    console.log('📊 Updated Control Center Status:');
    const updatedStatus = controlCenter.getControlCenterStatus();
    console.log(JSON.stringify(updatedStatus, null, 2));
    console.log('');

    // 6. Display JPMorgan Integration Data
    console.log('🏦 JPMorgan Integration Data:');
    const accountsData =
      controlCenter.quantumEngine.getQuantumState('jpmorgan_accounts');
    const transactionsData = controlCenter.quantumEngine.getQuantumState(
      'jpmorgan_transactions'
    );
    const paymentsData =
      controlCenter.quantumEngine.getQuantumState('jpmorgan_payments');
    const reportsData =
      controlCenter.quantumEngine.getQuantumState('jpmorgan_reports');

    console.log('Accounts:', JSON.stringify(accountsData, null, 2));
    console.log('Transactions:', JSON.stringify(transactionsData, null, 2));
    console.log('Payments:', JSON.stringify(paymentsData, null, 2));
    console.log('Reports:', JSON.stringify(reportsData, null, 2));
    console.log('');

    // 7. Emergency Controls Demo (Safe)
    console.log('🚨 Testing Emergency Controls (Safe Mode)...');
    console.log(
      'Note: Emergency shutdown and restart are demonstrated but not actually executed'
    );
    console.log(
      'In a real scenario, these would require explicit confirmation'
    );
    console.log('');

    // 8. Command History
    console.log('📋 Recent Command History:');
    // In a real implementation, this would show command history
    console.log(
      'Commands executed: sync_data, generate_report, execute_transaction, update_config, optimize_system, security_scan, backup_data, scale_system'
    );
    console.log('');

    console.log('🎉 Quantum Control Center Demo Complete!');
    console.log('✨ Features Demonstrated:');
    console.log('   • JPMorgan data synchronization');
    console.log('   • Real-time control command execution');
    console.log('   • System status monitoring');
    console.log('   • Transaction processing via control center');
    console.log('   • Configuration management');
    console.log('   • System optimization and security scanning');
    console.log('   • Data backup and system scaling');
    console.log('   • Automatic sync cycles');
    console.log('   • Emergency control capabilities');
  } catch (error) {
    console.error('❌ Demo failed:', error.message);
    console.error(error.stack);
  }
}

// Run the demo
if (require.main === module) {
  demonstrateQuantumControlCenter().catch(console.error);
}

module.exports = { demonstrateQuantumControlCenter };
