/**
 * Mock for node-cron module
 * Used in tests to avoid actual scheduling
 */

class MockTask {
  constructor(cronTime, onTick) {
    this.cronTime = cronTime;
    this.onTick = onTick;
    this.started = false;
  }

  start() {
    this.started = true;
  }

  stop() {
    this.started = false;
  }

  destroy() {
    this.started = false;
  }
}

/**
 * Creates a scheduled task
 * @param {string} cronTime - Cron expression
 * @param {Function} onTick - Function to execute
 * @returns {Object} Task instance
 */
export function schedule(cronTime, onTick) {
  return new MockTask(cronTime, onTick);
}

/**
 * Validates a cron expression
 * @param {string} cronTime - Cron expression to validate
 * @returns {boolean} True if valid
 */
export function validate(cronTime) {
  // Basic validation - check for 5 or 6 parts
  const parts = cronTime.trim().split(/\s+/);
  return parts.length >= 5 && parts.length <= 6;
}

/**
 * Schedules a task to run immediately (for testing)
 * @param {Function} onTick - Function to execute
 * @returns {Object} Task instance
 */
export function scheduleNow(onTick) {
  // Execute immediately for testing
  if (onTick) {
    setImmediate(onTick);
  }
  return new MockTask('now', onTick);
}

export default {
  schedule,
  validate,
  scheduleNow,
};
