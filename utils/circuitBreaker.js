/**
 * Circuit Breaker Utility
 * Prevents cascade failures when external APIs are unavailable
 * 
 * @module utils/circuitBreaker
 */

/**
 * Circuit States
 */
export const CircuitState = {
  CLOSED: 'closed',     // Normal operation, requests pass through
  OPEN: 'open',       // Circuit is open, requests fail fast
  HALF_OPEN: 'half-open', // Testing if service recovered
};

/**
 * Circuit Breaker Class
 */
export class CircuitBreaker {
  /**
   * @param {Object} options
   * @param {number} options.failureThreshold - Number of failures before opening circuit
   * @param {number} options.successThreshold - Number of successes to close circuit
   * @param {number} options.timeout - Time in ms before trying half-open
   * @param {number} options.monitorDuration - Time window for tracking failures
   */
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.successThreshold = options.successThreshold || 3;
    this.timeout = options.timeout || 30000; // 30 seconds
    this.monitorDuration = options.monitorDuration || 60000; // 60 seconds

    this.state = CircuitState.CLOSED;
    this.lastFailureTime = null;
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttempt = Date.now();

    // Track recent failures for monitoring window
    this.recentFailures = [];
  }

  /**
   * Execute a function with circuit breaker protection
   * @param {Function} fn - Function to execute
   * @param {Function} [fallback] - Fallback function if circuit is open
   * @returns {Promise<any>}
   */
  async execute(fn, fallback = null) {
    // Check if we should attempt to close the circuit
    if (this.state === CircuitState.HALF_OPEN) {
      if (Date.now() < this.nextAttempt) {
        // Still waiting, fail fast
        if (fallback) return fallback();
        throw new Error('Circuit breaker is half-open, waiting for recovery');
      }
      // Try closing the circuit
      this.state = CircuitState.CLOSED;
      this.successCount = 0;
    }

    // If circuit is open, fail fast
    if (this.state === CircuitState.OPEN) {
      if (fallback) return fallback();
      throw new Error('Circuit breaker is open - service unavailable');
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      if (fallback) return fallback();
      throw error;
    }
  }

  /**
   * Record a successful execution
   */
  onSuccess() {
    this.failureCount = 0;
    this.successCount++;

    // If we've had enough successes in half-open state, close the circuit
    if (this.state === CircuitState.HALF_OPEN && this.successCount >= this.successThreshold) {
      this.state = CircuitState.CLOSED;
      this.successCount = 0;
      console.log('[CircuitBreaker] Circuit closed - service recovered');
    }
  }

  /**
   * Record a failed execution
   */
  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    // Track recent failures
    this.recentFailures.push(Date.now());
    
    // Clean up old failures outside monitoring window
    const cutoff = Date.now() - this.monitorDuration;
    this.recentFailures = this.recentFailures.filter(t => t > cutoff);

    // Check if we should open the circuit
    if (this.recentFailures.length >= this.failureThreshold) {
      this.state = CircuitState.OPEN;
      this.nextAttempt = Date.now() + this.timeout;
      console.log('[CircuitBreaker] Circuit opened - too many failures');
    }
  }

  /**
   * Get current circuit state
   * @returns {string}
   */
  getState() {
    return this.state;
  }

  /**
   * Reset the circuit breaker
   */
  reset() {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.recentFailures = [];
    this.lastFailureTime = null;
  }

  /**
   * Manually open the circuit
   */
  open() {
    this.state = CircuitState.OPEN;
    this.nextAttempt = Date.now() + this.timeout;
    console.log('[CircuitBreaker] Circuit manually opened');
  }

  /**
   * Manually close the circuit
   */
  close() {
    this.reset();
    console.log('[CircuitBreaker] Circuit manually closed');
  }
}

/**
 * Create a circuit breaker for external API calls
 * @param {string} name - Name of the service
 * @param {Object} options - Circuit breaker options
 * @returns {CircuitBreaker}
 */
export function createServiceCircuitBreaker(name, options = {}) {
  return new CircuitBreaker({
    failureThreshold: options.failureThreshold || 5,
    successThreshold: options.successThreshold || 3,
    timeout: options.timeout || 30000,
    monitorDuration: options.monitorDuration || 60000,
  });
}

// Export default instance
export default {
  CircuitState,
  CircuitBreaker,
  createServiceCircuitBreaker,
};
