import { create, all, matrix, transpose, multiply, inv } from 'mathjs';

// Mock historical data: last 12 months revenue
const historicalData = [
  1000000, 1050000, 1100000, 1080000, 1150000, 1200000,
  1180000, 1250000, 1300000, 1280000, 1350000, 1400000
];

let slope = null;
let intercept = null;

export function trainModel() {
  if (slope !== null) return { slope, intercept };

  // Prepare data: X = month index, Y = revenue
  const X = historicalData.map((_, i) => [1, i]); // Add intercept term
  const Y = historicalData.map(v => [v]);

  // Linear regression: Y = X * beta, solve for beta
  const XT = transpose(X);
  const XTX = multiply(XT, X);
  const XTY = multiply(XT, Y);
  const beta = multiply(inv(XTX), XTY);

  intercept = beta[0][0];
  slope = beta[1][0];

  return { slope, intercept };
}

export function predictNextMonth() {
  if (slope === null) trainModel();

  const nextMonthIndex = historicalData.length;
  const prediction = intercept + slope * nextMonthIndex;

  return Math.round(prediction);
}

export function detectAnomaly(currentRevenue) {
  const mean = historicalData.reduce((a, b) => a + b) / historicalData.length;
  const variance = historicalData.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / historicalData.length;
  const stdDev = Math.sqrt(variance);

  const lowerBound = mean - 2 * stdDev;
  const upperBound = mean + 2 * stdDev;

  return currentRevenue < lowerBound || currentRevenue > upperBound;
}

export function getAnalytics() {
  const prediction = predictNextMonth();
  const currentRevenue = historicalData[historicalData.length - 1];
  const anomaly = detectAnomaly(currentRevenue);

  return {
    currentRevenue,
    predictedNextMonth: prediction,
    anomalyDetected: anomaly,
    historicalData
  };
}
