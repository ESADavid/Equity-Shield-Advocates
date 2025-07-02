const express = require('express');
const router = express.Router();
const paymentRouter = require('./payment');

// Mount payment routes under /api/payment
router.use('/payment', paymentRouter);

// Additional API endpoints can be added here as needed

module.exports = router;
