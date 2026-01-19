class TransferEventsMonitor {
  constructor() {
    this.requests = new Map();
  }

  recordRequest(accessToken, options) {
    const id = `${accessToken}-${Date.now()}`;
    const tracker = {
      id,
      accessToken,
      options,
      startTime: Date.now(),
      success: (count) => {
        console.log(`Transfer events request ${id} completed successfully with ${count} events`);
        this.requests.delete(id);
      },
      error: (error) => {
        console.error(`Transfer events request ${id} failed:`, error);
        this.requests.delete(id);
      }
    };

    this.requests.set(id, tracker);
    return tracker;
  }

  getStats() {
    return {
      activeRequests: this.requests.size,
      totalRequests: this.requests.size // Simplified
    };
  }
}

export default new TransferEventsMonitor();
