const express = require('express');
const router = express.Router();
const paymentRouter = require('./payment');
const merchantBillPayRouter = require('./merchant_bill_pay');
const githubPayment = require('./github_payment');
const MicrosoftPayment = require('./microsoft_payment').default;
const jpmorganPaymentRouter = require('./jpmorgan_payment');

const microsoftPaymentInstance = new MicrosoftPayment(
  process.env.DYNAMICS365_BASE_URL || '',
  process.env.DYNAMICS365_ACCESS_TOKEN || ''
);

// Mount payment routes under /api/payment
router.use('/payment', paymentRouter);
router.use('/merchant-bill-pay', merchantBillPayRouter);
router.use('/github-payment', githubPayment.router);
router.use('/jpmorgan-payment', jpmorganPaymentRouter);

// Microsoft payment route
router.post('/microsoft-payment/initiate', async (req, res) => {
  try {
    const result = await microsoftPaymentInstance.initiatePayment(req.body);
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    console.error('Error in Microsoft payment API:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

const nvidiaPayment = require('./nvidia_payment');

// Additional API endpoints can be added here as needed

router.use('/nvidia-payment', nvidiaPayment.router);

module.exports = router;
