const logger = require('../config/logger');

class RecommendationService {
  constructor() {
    this.recommendations = {
      investment: [
        'Diversify portfolio across multiple asset classes',
        'Consider long-term investment strategies',
        'Regular portfolio rebalancing recommended',
        'Invest in stable, income-generating assets',
      ],
      education: [
        'Focus on STEM subjects for future opportunities',
        'Consider vocational training programs',
        'Pursue continuous learning and skill development',
        'Explore online learning platforms',
      ],
      finance: [
        'Maintain emergency fund of 3-6 months expenses',
        'Reduce high-interest debt first',
        'Create a budget and track expenses',
        'Build credit score through responsible borrowing',
      ],
      career: [
        'Network with industry professionals',
        'Develop soft skills alongside technical skills',
        'Seek mentorship opportunities',
        'Consider career advancement through certifications',
      ],
    };
  }

  getRecommendations(category, userProfile = {}) {
    logger.info(`Using predefined recommendations for category: ${category}`);
    const categoryRecs =
      this.recommendations[category] || this.recommendations.finance;

    // Simple personalization based on profile
    let personalized = [...categoryRecs];

    if (userProfile.age && userProfile.age > 50) {
      personalized.push('Consider retirement planning and pension options');
    }

    if (userProfile.income && userProfile.income < 30000) {
      personalized.push('Explore government assistance programs');
    }

    if (userProfile.riskTolerance === 'low') {
      personalized = personalized.filter((rec) => !rec.includes('high-risk'));
    }

    return {
      recommendations: personalized.slice(0, 5), // Limit to 5
      category,
      personalized: true,
    };
  }

  getPersonalizedRecommendations(userData) {
    logger.info('Using rule-based personalized recommendations');
    const recommendations = [];

    // Rule-based logic
    if (userData.savings < userData.monthlyExpenses * 3) {
      recommendations.push('Build emergency fund');
    }

    if (userData.debt > userData.income * 0.5) {
      recommendations.push('Focus on debt reduction');
    }

    if (userData.investments < userData.income * 0.1) {
      recommendations.push('Increase investment contributions');
    }

    if (!userData.insurance) {
      recommendations.push('Consider insurance coverage');
    }

    return {
      recommendations,
      priority: recommendations.length > 2 ? 'high' : 'medium',
    };
  }

  getTrendingRecommendations() {
    logger.info('Using predefined trending recommendations');
    return {
      trending: [
        'Sustainable and ESG investing',
        'Cryptocurrency education and awareness',
        'Remote work skill development',
        'Digital literacy programs',
      ],
      basedOn: 'current market trends',
    };
  }
}

module.exports = new RecommendationService();
