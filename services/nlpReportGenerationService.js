const logger = require('../config/logger');

class NLPReportGenerationService {
  constructor() {
    this.templates = {
      revenue: 'Revenue Report: Total revenue for the period is ${total}. Growth rate: ${growth}%. Key insights: ${insights}',
      compliance: 'Compliance Report: All systems are ${status}. Recommendations: ${recommendations}',
      performance: 'Performance Report: System uptime: ${uptime}%. Response time: ${responseTime}ms. Issues: ${issues}'
    };
  }

  generateRevenueReport(data) {
    logger.info('Using template-based revenue report generation');
    const total = data.total || 0;
    const growth = data.growth || 0;
    const insights = data.insights || 'Stable performance observed';
    return this.templates.revenue
      .replace('${total}', total)
      .replace('${growth}', growth)
      .replace('${insights}', insights);
  }

  generateComplianceReport(data) {
    logger.info('Using template-based compliance report generation');
    const status = data.status || 'compliant';
    const recommendations = data.recommendations || 'No action required';
    return this.templates.compliance
      .replace('${status}', status)
      .replace('${recommendations}', recommendations);
  }

  generatePerformanceReport(data) {
    logger.info('Using template-based performance report generation');
    const uptime = data.uptime || 100;
    const responseTime = data.responseTime || 0;
    const issues = data.issues || 'None';
    return this.templates.performance
      .replace('${uptime}', uptime)
      .replace('${responseTime}', responseTime)
      .replace('${issues}', issues);
  }

  summarizeText(text, maxLength = 100) {
    logger.info('Using simple text summarization');
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  }
}

module.exports = new NLPReportGenerationService();
