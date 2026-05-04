/**
 * @typedef {Object} TransferRequestOptions
 * @property {string} [method]
 * @property {string} [endpoint]
 * @property {number} [timeout]
 */

/**
 * @typedef {Object} TransferTracker
 * @property {string} id
 * @property {string} accessToken
 * @property {TransferRequestOptions} options
 * @property {number} startTime
 * @property {Function} success
 * @property {Function} error
 */

class TransferEventsMonitor {
  /** @type {Map<string, TransferTracker>} */
  requests = new Map();

  /**
   * Record a transfer events request
   * @param {string} accessToken - The access token for the request
   * @param {TransferRequestOptions} options - Request options
   * @returns {TransferTracker}
   */
  recordRequest(accessToken, options) {
    const id = `${accessToken}-${Date.now()}`;
    const tracker = {
      id,
      accessToken,
      options,
      startTime: Date.now(),
      /** @param {number} _count - Number of events transferred (unused) */
      success: (_count) => {
        // Transfer events request completed successfully
        this.requests.delete(id);
      },
      /** @param {Error} _error - Error details if failed (unused) */
      error: (_error) => {
        // Transfer events request failed
        this.requests.delete(id);
      },
    };

    this.requests.set(id, tracker);
    return tracker;
  }

  getStats() {
    return {
      activeRequests: this.requests.size,
      totalRequests: this.requests.size, // Simplified
    };
  }
}

export default new TransferEventsMonitor();
