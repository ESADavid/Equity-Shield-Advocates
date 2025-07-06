const express = require('express');
const router = express.Router();
const paymentRouter = require('./payment');
const merchantBillPayRouter = require('./merchant_bill_pay');

// Mount payment routes under /api/payment
router.use('/payment', paymentRouter);
router.use('/merchant-bill-pay', merchantBillPayRouter);

// Additional API endpoints can be added here as needed

module.exports = router;
