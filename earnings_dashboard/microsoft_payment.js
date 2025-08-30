const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Microsoft Dynamics 365 Payments Configuration
const DYNAMICS365_BASE_URL = process.env.DYNAMICS365_BASE_URL || 'https://api.businesscentral.dynamics.com';
const DYNAMICS365_TENANT_ID = process.env.DYNAMICS365_TENANT_ID;
const DYNAMICS365_CLIENT_ID = process.env.DYNAMICS365_CLIENT_ID;
const DYNAMICS365_CLIENT_SECRET = process.env.DYNAMICS365_CLIENT_SECRET;
const DYNAMICS365_COMPANY_ID = process.env.DYNAMICS365_COMPANY_ID;

// Revenue data path
const revenueDataPath = path.resolve(__dirname, '../earnings_report_updated.json');

function readRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0,
      autoFleetDetails: []
    };
  }
  return data;
}

function writeRevenueData(data) {
  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
}

// Get Microsoft authentication token
async function getAuthToken() {
  try {
    const tokenUrl = `https://login.microsoftonline.com/${DYNAMICS365_TENANT_ID}/oauth2/v2.0/token`;
    
    const params = new URLSearchParams();
    params.append('client_id', DYNAMICS365_CLIENT_ID);
    params.append('client_secret', DYNAMICS365_CLIENT_SECRET);
    params.append('scope', 'https://api.businesscentral.dynamics.com/.default');
    params.append('grant_type', 'client_credentials');

    const response = await axios.post(tokenUrl, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    return response.data.access_token;
  } catch (error) {
    console.error('Microsoft authentication error:', error.response?.data || error.message);
    throw new Error('Failed to authenticate with Microsoft Dynamics 365');
  }
}

// Generate Microsoft authentication headers
async function generateAuthHeaders() {
  const token = await getAuthToken();
  
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'OData-MaxVersion': '4.0',
    'OData-Version': '4.0'
  };
}

// Create sales order (payment equivalent in Dynamics 365)
router.post('/create-sales-order', async (req, res) => {
  try {
    const { customerId, amount, currency = 'USD', description, items } = req.body;

    if (!customerId || !amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'Customer ID and amount are required' 
      });
    }

    const headers = await generateAuthHeaders();

    const salesOrderData = {
      customerId: customerId,
      orderDate: new Date().toISOString().split('T')[0],
      currencyCode: currency,
      paymentTermsId: '30D',
      pricesIncludeTax: false,
      requestDeliveryDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      salesOrderLines: items || [
        {
          lineType: 'Item',
          lineObjectNumber: 'SERVICE001',
          description: description || 'Payment for services',
          quantity: 1,
          unitPrice: amount,
          amount: amount
        }
      ]
    };

    const response = await axios.post(
      `${DYNAMICS365_BASE_URL}/v2.0/${DYNAMICS365_COMPANY_ID}/api/v2.0/salesOrders`,
      salesOrderData,
      { headers }
    );

    res.json({
      success: true,
      salesOrderId: response.data.id,
      orderNumber: response.data.number,
      status: response.data.status,
      orderDetails: response.data
    });

  } catch (error) {
    console.error('Microsoft sales order creation error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create sales order',
      details: error.response?.data || error.message
    });
  }
});

// Get sales order status
router.get('/order-status/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    
    const headers = await generateAuthHeaders();
    
    const response = await axios.get(
      `${DYNAMICS365_BASE_URL}/v2.0/${DYNAMICS365_COMPANY_ID}/api/v2.0/salesOrders(${orderId})`,
      { headers }
    );

    res.json({
      success: true,
      orderStatus: response.data
    });

  } catch (error) {
    console.error('Microsoft order status error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to get order status',
      details: error.response?.data || error.message
    });
  }
});

// Create payment journal entry
router.post('/create-payment', async (req, res) => {
  try {
    const { customerId, amount, currency = 'USD', description, documentNumber } = req.body;

    if (!customerId || !amount || !documentNumber) {
      return res.status(400).json({ 
        success: false, 
        error: 'Customer ID, amount, and document number are required' 
      });
    }

    const headers = await generateAuthHeaders();

    const paymentData = {
      journalDisplayName: 'Payment Journal',
      balancingAccountId: '11000', // Cash account
      balancingAccountNumber: '11000',
      documentNumber: documentNumber,
      postingDate: new Date().toISOString().split('T')[0],
      accountId: customerId,
      amount: amount,
      description: description || 'Payment received',
      currencyCode: currency
    };

    const response = await axios.post(
      `${DYNAMICS365_BASE_URL}/v2.0/${DYNAMICS365_COMPANY_ID}/api/v2.0/journals('Payment')/journalLines`,
      paymentData,
      { headers }
    );

    res.json({
      success: true,
      paymentId: response.data.id,
      journalLineNumber: response.data.lineNumber,
      status: 'Posted',
      paymentDetails: response.data
    });

  } catch (error) {
    console.error('Microsoft payment creation error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create payment',
      details: error.response?.data || error.message
    });
  }
});

// Get customer information
router.get('/customer/:customerId', async (req, res) => {
  try {
    const { customerId } = req.params;
    
    const headers = await generateAuthHeaders();
    
    const response = await axios.get(
      `${DYNAMICS365_BASE_URL}/v2.0/${DYNAMICS365_COMPANY_ID}/api/v2.0/customers(${customerId})`,
      { headers }
    );

    res.json({
      success: true,
      customer: response.data
    });

  } catch (error) {
    console.error('Microsoft customer lookup error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to get customer information',
      details: error.response?.data || error.message
    });
  }
});

// Health check endpoint for Microsoft integration
router.get('/health', async (req, res) => {
  try {
    const headers = await generateAuthHeaders();
    
    // Simple health check by making a small API call
    const response = await axios.get(
      `${DYNAMICS365_BASE_URL}/v2.0/${DYNAMICS365_COMPANY_ID}/api/v2.0/companies`,
      { headers, timeout: 5000 }
    );

    res.json({
      status: 'healthy',
      microsoftStatus: 'Connected',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: 'Microsoft Dynamics 365 API unavailable',
      details: error.message
    });
  }
});

module.exports = {
  router,
  generateAuthHeaders,
  getAuthToken
};
