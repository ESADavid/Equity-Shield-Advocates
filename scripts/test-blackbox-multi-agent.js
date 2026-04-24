/**
 * Test Blackbox Multi-Agent Integration
 * Run: node scripts/test-blackbox-multi-agent.js
 */

import { info } from 'utils/loggerWrapper.js';
import blackboxService from '../services/blackboxMultiAgentService.js';

async function testMultiAgent() {
  info('🧪 Testing Blackbox Multi-Agent Integration...');

  // 1. Create task
  const createResult = await blackboxService.createMultiAgentTask(
    'Review payroll services for optimization and divine efficiency improvements'
  );

  if (!createResult.success) {
    info('❌ Create failed - check BLACKBOX_API_KEY');
    return;
  }

  info(`✅ Task created: ${createResult.taskId}`);
  info(`📊 Monitor: ${createResult.taskUrl}`);

  // 2. Poll for completion (optional, uncomment)
  /*
  const pollResult = await blackboxService.pollTaskUntilComplete(createResult.taskId);
  info('🏁 Poll result:', pollResult);
  */

  info('✅ Test complete! Set BLACKBOX_API_KEY and run again.');
}

testMultiAgent().catch(console.error);

