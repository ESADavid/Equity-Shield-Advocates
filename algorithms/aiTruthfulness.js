/**
 * AI TRUTHFULNESS MODULE
 * 
 * Implements truthfulness guarantees for AI systems:
 * - Factual verification
 * - Uncertainty acknowledgment
 * - Source citation requirements
 * - Confidence calibration
 * - Hallucination detection
 * 
 * @author Sachem Yochanan
 * @date December 20, 2025
 */

/**
 * Truth status levels
 */
export const TruthStatus = {
  VERIFIED: 'verified',
  LIKELY: 'likely',
  UNCERTAIN: 'uncertain',
  UNVERIFIABLE: 'unverifiable',
  CONTRADICTED: 'contradicted',
};

/**
 * Confidence levels
 */
export const ConfidenceLevel = {
  HIGH: { level: 0.9, label: 'High', description: 'Strong evidence, multiple sources' },
  MEDIUM: { level: 0.7, label: 'Medium', description: 'Some evidence, needs verification' },
  LOW: { level: 0.5, label: 'Low', description: 'Limited evidence, high uncertainty' },
  VERY_LOW: { level: 0.3, label: 'Very Low', description: 'Little to no evidence' },
};

/**
 * @typedef {Object} FactCheck
 * @property {string} claim - The claim being verified
 * @property {TruthStatus} status - Verification status
 * @property {number} confidence - Confidence score 0-1
 * @property {string[]} sources - Source citations
 * @property {string} explanation - Explanation of verification
 * @property {boolean} acknowledgedUncertainty - Whether uncertainty was acknowledged
 */

class AITruthfulness {
  constructor() {
    // Truth requirements configuration
    this.config = {
      requireSourceCitation: true,
      requireUncertaintyAcknowledgment: true,
      maxConfidenceWithoutSources: 0.7,
      defaultConfidenceWithoutData: 0.3,
      minEvidenceForHighConfidence: 3,
      hallucinationThreshold: 0.4,
    };
    
    // Verified facts database
    this.verifiedFacts = new Map();
    
    // Sources database
    this.sources = new Map();
    
    // Truth metrics
    this.metrics = {
      totalClaims: 0,
      verifiedClaims: 0,
      uncertainClaims: 0,
      hallucinationFlags: 0,
      sourceCitations: 0,
    };
  }

  /**
   * Verify a claim against known facts
   * @param {string} claim - The claim to verify
   * @param {string|string[]} [sources] - Source(s) for verification
   * @returns {FactCheck}
   */
  verifyClaim(claim, sources = []) {
    this.metrics.totalClaims++;
    
    const factCheck = {
      claim,
      status: TruthStatus.UNCERTAIN,
      confidence: this.config.defaultConfidenceWithoutData,
      sources: Array.isArray(sources) ? sources : sources ? [sources] : [],
      explanation: '',
      acknowledgedUncertainty: false,
    };
    
    // Check against verified facts database
    const normalizedClaim = this.normalizeClaim(claim);
    if (this.verifiedFacts.has(normalizedClaim)) {
      const verified = this.verifiedFacts.get(normalizedClaim);
      factCheck.status = TruthStatus.VERIFIED;
      factCheck.confidence = 0.95;
      factCheck.explanation = `Verified against known data: ${verified.source}`;
      factCheck.acknowledgedUncertainty = true;
      this.metrics.verifiedClaims++;
      return factCheck;
    }
    
    // Check sources
    if (sources && sources.length > 0) {
      factCheck.sources = Array.isArray(sources) ? sources : [sources];
      factCheck.confidence = this.calculateSourceConfidence(factCheck.sources);
      this.metrics.sourceCitations += factCheck.sources.length;
    } else {
      // No sources - flag as uncertain
      factCheck.status = TruthStatus.UNVERIFIABLE;
      factCheck.explanation = 'No sources provided - claim cannot be verified';
      factCheck.acknowledgedUncertainty = true;
      this.metrics.uncertainClaims++;
      return factCheck;
    }
    
    // Calculate confidence based on evidence
    const evidenceCount = factCheck.sources.length;
    if (evidenceCount >= this.config.minEvidenceForHighConfidence) {
      factCheck.confidence = Math.min(0.85, factCheck.confidence);
      factCheck.status = TruthStatus.LIKELY;
      factCheck.explanation = `Based on ${evidenceCount} sources`;
    } else {
      factCheck.status = TruthStatus.UNCERTAIN;
      factCheck.explanation = 'Limited evidence - more sources needed';
      factCheck.acknowledgedUncertainty = true;
      this.metrics.uncertainClaims++;
    }
    
    return factCheck;
  }

  /**
   * Normalize a claim for comparison
   * @param {string} claim - The claim to normalize
   * @returns {string}
   */
  normalizeClaim(claim) {
    return claim.toLowerCase().trim().replace(/\s+/g, ' ');
  }

  /**
   * Calculate confidence based on sources
   * @param {string[]} sources - Array of sources
   * @returns {number}
   */
  calculateSourceConfidence(sources) {
    if (!sources || sources.length === 0) {
      return this.config.defaultConfidenceWithoutData;
    }
    
    // Score based on number of sources
    const sourceScore = Math.min(0.8, sources.length * 0.2);
    
    // Check if sources are verified in our database
    let verifiedSources = 0;
    for (const source of sources) {
      if (this.sources.has(source.toLowerCase())) {
        verifiedSources++;
      }
    }
    
    const verifiedScore = verifiedSources > 0 
      ? (verifiedSources / sources.length) * 0.2 
      : 0;
    
    return Math.min(0.9, sourceScore + verifiedScore);
  }

  /**
   * Detect potential hallucinations
   * @param {string} output - The AI output to check
   * @param {Object} [context] - Context for hallucination detection
   * @returns {Object}
   */
  detectHallucination(output, context = {}) {
    const result = {
      isHallucination: false,
      confidence: 0,
      flags: [],
      recommendations: [],
    };
    
    // Check for unverifiable claims
    const unverifiablePatterns = [
      /according to (the )?research/i,
      /studies show/i,
      /it is (well )?known that/i,
      /experts (agree|say)/i,
    ];
    
    for (const pattern of unverifiablePatterns) {
      if (pattern.test(output)) {
        result.flags.push('Contains unverified research claims');
        result.confidence += 0.1;
      }
    }
    
    // Check for overconfident language
    const overconfidentPatterns = [
      /\bdefinitely\b/i,
      /\bcertainly\b/i,
      /\babsolutely\b/i,
      /\bunquestionably\b/i,
      /\bguaranteed\b/i,
      /\b100%\b/i,
    ];
    
    let overconfidentCount = 0;
    for (const pattern of overconfidentPatterns) {
      if (pattern.test(output)) {
        overconfidentCount++;
      }
    }
    
    if (overconfidentCount > 0) {
      result.flags.push('Overconfident language detected');
      result.confidence += overconfidentCount * 0.15;
    }
    
    // Check for specific unverifiable details
    const specificUnverifiable = /\b\d+(,\d+)?(,\d+)?\s+(people|users|customers|companies|years|days)\b/i;
    if (specificUnverifiable.test(output)) {
      result.flags.push('Contains specific unverifiable numbers');
      result.confidence += 0.1;
    }
    
    // Determine if it's likely a hallucination
    result.isHallucination = result.confidence >= this.config.hallucinationThreshold;
    result.confidence = Math.min(1, result.confidence);
    
    if (result.isHallucination) {
      this.metrics.hallucinationFlags++;
      result.recommendations.push('Verify all claims with sources');
      result.recommendations.push('Add uncertainty acknowledgment');
      result.recommendations.push('Use qualifying language');
    }
    
    return result;
  }

  /**
   * Generate a truthful response wrapper
   * @param {Object} response - The response object
   * @returns {Object}
   */
  generateTruthfulResponse(response) {
    const truthfulResponse = {
      ...response,
      _truthfulness: {
        timestamp: new Date().toISOString(),
        confidence: response.confidence || 0.5,
        uncertaintyAcknowledged: response.confidence < 0.8,
        sourcesRequired: this.config.requireSourceCitation,
        sources: response.sources || [],
        verified: false,
      },
    };
    
    // Add appropriate caveats based on confidence
    if (response.confidence < 0.5) {
      truthfulResponse.caveat = 'This information has limited verification. Proceed with caution.';
    } else if (response.confidence < 0.7) {
      truthfulResponse.caveat = 'This information is based on limited evidence. Verification recommended.';
    }
    
    // Add source requirement notice
    if (this.config.requireSourceCitation && (!response.sources || response.sources.length === 0)) {
      truthfulResponse.notice = 'No sources cited for this information.';
    }
    
    return truthfulResponse;
  }

  /**
   * Add a verified fact to the database
   * @param {string} fact - The fact to add
   * @param {string} source - Source of verification
   */
  addVerifiedFact(fact, source) {
    const normalized = this.normalizeClaim(fact);
    this.verifiedFacts.set(normalized, {
      fact,
      source,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Add a verified source
   * @param {string} sourceName - Name of the source
   * @param {string} sourceType - Type of source (api, database, document)
   */
  addVerifiedSource(sourceName, sourceType) {
    this.sources.set(sourceName.toLowerCase(), {
      name: sourceName,
      type: sourceType,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Get truthfulness metrics
   * @returns {Object}
   */
  getMetrics() {
    return {
      ...this.metrics,
      verificationRate: this.metrics.totalClaims > 0 
        ? this.metrics.verifiedClaims / this.metrics.totalClaims 
        : 0,
      uncertaintyRate: this.metrics.totalClaims > 0 
        ? this.metrics.uncertainClaims / this.metrics.totalClaims 
        : 0,
    };
  }

  /**
   * Calibrate confidence based on actual performance
   * @param {number} claimedConfidence - The claimed confidence
   * @param {boolean} wasAccurate - Whether the prediction was accurate
   * @returns {number}
   */
  calibrateConfidence(claimedConfidence, wasAccurate) {
    // Simple calibration: adjust toward actual performance
    const actualAccuracy = wasAccurate ? 1 : 0;
    const calibrationFactor = 0.3;
    
    return claimedConfidence * (1 - calibrationFactor) + 
           actualAccuracy * calibrationFactor;
  }
}

/**
 * Create a truthful output wrapper
 * @param {string} content - The content to wrap
 * @param {Object} options - Options for truthfulness
 * @returns {string}
 */
export function makeTruthful(content, options = {}) {
  const {
    confidence = 0.5,
    sources = [],
    includeUncertainty = true,
  } = options;
  
  let truthfulContent = content;
  
  // Add uncertainty acknowledgment if confidence is low
  if (includeUncertainty && confidence < 0.7) {
    const uncertaintyPhrases = [
      'This is based on limited data.',
      'More verification is needed.',
      'This may not be accurate.',
    ];
    const phrase = uncertaintyPhrases[Math.floor(confidence * uncertaintyPhrases.length)];
    truthfulContent += `\n\n⚠️ ${phrase}`;
  }
  
  // Add source citation reminder
  if (sources.length === 0) {
    truthfulContent += `\n\n📚 No sources cited for this information.`;
  } else {
    truthfulContent += `\n\n📚 Sources: ${sources.join(', ')}`;
  }
  
  return truthfulContent;
}

/**
 * Check if output contains hallucinated content
 * @param {string} output - The output to check
 * @returns {Object}
 */
export function checkForHallucinations(output) {
  const truthfulness = new AITruthfulness();
  return truthfulness.detectHallucination(output);
}

export default AITruthfulness;
