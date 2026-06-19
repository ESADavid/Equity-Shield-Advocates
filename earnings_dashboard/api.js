const express = require('express');
const router = express.Router();
const paymentRouter = require('./payment');
const merchantBillPayRouter = require('./merchant_bill_pay');
const githubPayment = require('./github_payment');
const microsoftPayment = require('./microsoft_payment');
const jpmorganPaymentRouter = require('./jpmorgan_payment');
const nvidiaPayment = require('./nvidia_payment');
const payrollApiRouter = require('./payroll_api');
const walletEndpointsRouter = require('./wallet_endpoints');

// Mount payment routes under /api/payment
router.use('/payment', paymentRouter);
router.use('/merchant-bill-pay', merchantBillPayRouter);
router.use('/github-payment', githubPayment.router);
router.use('/jpmorgan-payment', jpmorganPaymentRouter);
router.use('/microsoft-payment', microsoftPayment.router);
router.use('/nvidia-payment', nvidiaPayment.router);
router.use('/wallet', walletEndpointsRouter);

// Mount payroll API routes under /api/payroll
router.use('/payroll', payrollApiRouter);

// Additional API endpoints can be added here as needed

module.exports = router;
