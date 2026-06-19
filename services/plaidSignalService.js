import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import logger from '../config/logger.js';

// Plaid configuration
const configuration = new Configuration({
  basePath: PlaidEnvironments[process.env.PLAID_ENV || 'sandbox'],
  baseOptions: {
    headers: {
      'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID,
      'PLAID-SECRET': process.env.PLAID_SECRET,
    },
  },
});

const plaidClient = new PlaidApi(configuration);

class PlaidSignalService {
  // Plaid Signal - Evaluate transaction risk
  async evaluateTransaction(accessToken, transactionData) {
    try {
      const request = {
        access_token: accessToken,
        client_transaction_id: transactionData.client_transaction_id,
        amount: transactionData.amount,
        user: transactionData.user || {},
        device: transactionData.device || {},
        transaction_data: {
          merchant_name: transactionData.merchant_name,
          amount: transactionData.amount,
          iso_currency_code: transactionData.iso_currency_code || 'USD',
          merchant_category_code: transactionData.merchant_category_code,
          location: transactionData.location || {},
          payment_method: transactionData.payment_method || {},
          payment_processor: transactionData.payment_processor,
          transaction_type: transactionData.transaction_type,
          transaction_initiation_date:
            transactionData.transaction_initiation_date,
        },
      };

      // Remove undefined values
      Object.keys(request.transaction_data).forEach((key) => {
        if (request.transaction_data[key] === undefined) {
          delete request.transaction_data[key];
        }
      });

      const response = await plaidClient.signalEvaluate(request);
      return response.data;
    } catch (error) {
      logger.error('Error evaluating transaction with Signal:', error);
      throw error;
    }
  }

  // Plaid Signal - Report a return on a transaction
  async reportReturn(accessToken, returnData) {
    try {
      const request = {
        access_token: accessToken,
        client_transaction_id: returnData.client_transaction_id,
        return_code: returnData.return_code,
        returned_at: returnData.returned_at,
        description: returnData.description,
      };

      const response = await plaidClient.signalReturnReport(request);
      return response.data;
    } catch (error) {
      logger.error('Error reporting return with Signal:', error);
      throw error;
    }
  }

  // Plaid Signal - Report underwriting decision
  async reportDecision(accessToken, decisionData) {
    try {
      const request = {
        access_token: accessToken,
        client_transaction_id: decisionData.client_transaction_id,
        decision_outcome: decisionData.decision_outcome,
        payment_initiation_time: decisionData.payment_initiation_time,
        risk_level_at_decision: decisionData.risk_level_at_decision,
        decision_rationale: decisionData.decision_rationale || {},
      };

      const response = await plaidClient.signalDecisionReport(request);
      return response.data;
    } catch (error) {
      logger.error('Error reporting decision with Signal:', error);
      throw error;
    }
  }

  // Plaid Signal - Create custom ruleset
  async createRuleset(rulesetData) {
    try {
      const request = {
        ruleset: {
          item_id: rulesetData.item_id,
          name: rulesetData.name,
          rules: rulesetData.rules || [],
        },
      };

      const response = await plaidClient.signalRulesetCreate(request);
      return response.data;
    } catch (error) {
      logger.error('Error creating custom ruleset with Signal:', error);
      throw error;
    }
  }
}

const plaidSignalService = new PlaidSignalService();
export default plaidSignalService;
