import { info, error, warn, debug } from '../utils/loggerWrapper.js';

/**
 * Script to simulate purchasing a Rolls Royce Spectra Black Badge
 * using the existing purchase auto API endpoint in the earnings dashboard system.
 *
 * This script sends a POST request to /api/purchase/auto with the required details.
 */

const fetch = require('node-fetch');

async function purchaseRollsRoyceSpectra() {
  const apiUrl = 'http://localhost:4000/api/purchase/auto'; // Adjust if server runs on different host/port

  const purchaseDetails = {
    cost: 799996,
    model: '2025 ROLLS-ROYCE BLACK BADGE SPECTRA',
    vin: 'SCATK4CO4SU229567',
    dealership:
      'ROLLS-ROYCE MOTORS CARS CHARLOTTE, 1316 SOUTH TRYON ST. CHARLOTTE NC 28203',
  };

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization:
          'Basic ' + Buffer.from('admin:securepassword').toString('base64'), // Basic auth as per server setup
      },
      body: JSON.stringify(purchaseDetails),
    });

    const result = await response.json();

    if (response.ok) {
      logger.info('Purchase successful:', result);
    } else {
      logger.error('Purchase failed:', result.error);
    }
  } catch (error) {
    logger.error('Error during purchase request:', error);
  }
}

purchaseRollsRoyceSpectra();
