import express from 'express';

export default function createNotificationRouter(notificationService) {
  const router = express.Router();

  // GET /api/notifications/settings - Get notification settings
  router.get('/settings', (req, res) => {
    // Mock settings - in real app, this would come from database
    const settings = {
      emailEnabled: !!process.env.SMTP_HOST,
      smsEnabled: !!process.env.TWILIO_ACCOUNT_SID,
      websocketEnabled: true,
      notificationTypes: {
        revenueMilestones: true,
        anomalies: true,
        paymentFailures: true,
        systemAlerts: true
      }
    };

    res.json(settings);
  });

  // POST /api/notifications/settings - Update notification settings
  router.post('/settings', (req, res) => {
    const { email, sms, websocket, notificationTypes } = req.body;

    // In real app, save to database
    const updatedSettings = {
      emailEnabled: email,
      smsEnabled: sms,
      websocketEnabled: websocket,
      notificationTypes,
      updatedAt: new Date().toISOString()
    };

    res.json({
      success: true,
      message: 'Notification settings updated',
      settings: updatedSettings
    });
  });

  // POST /api/notifications/test - Send test notification
  router.post('/test', async (req, res) => {
    try {
      const { email, phone } = req.body;

      const result = await notificationService.sendNotification({
        email,
        phone,
        subject: 'Test Notification',
        message: `
          <h2>Test Notification</h2>
          <p>This is a test notification from the OSCAR BROOME Revenue System.</p>
          <p>Sent at: ${new Date().toISOString()}</p>
        `,
        websocket: true
      });

      res.json({
        success: true,
        message: 'Test notification sent',
        results: result
      });
    } catch (error) {
      console.error('Test notification error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to send test notification',
        error: error.message
      });
    }
  });

  // GET /api/notifications/history - Get notification history
  router.get('/history', (req, res) => {
    // Mock history - in real app, this would come from database
    const history = [
      {
        id: '1',
        type: 'revenue_milestone',
        subject: 'Revenue Milestone Reached',
        message: 'Monthly revenue target achieved',
        timestamp: new Date(Date.now() - 86400000).toISOString(),
        channels: ['websocket', 'email']
      },
      {
        id: '2',
        type: 'anomaly',
        subject: 'Revenue Anomaly Detected',
        message: 'Unusual revenue pattern detected',
        timestamp: new Date(Date.now() - 172800000).toISOString(),
        channels: ['websocket']
      }
    ];

    res.json(history);
  });

  return router;
}
