import express from 'express';

export default function createNotificationRouter(notificationService) {
  const router = express.Router();

  // Get notification history (placeholder)
  router.get('/', (req, res) => {
    res.json({
      notifications: [],
      message: 'Notification system operational',
    });
  });

  // Send test notification
  router.post('/test', (req, res) => {
    const { message } = req.body;
    notificationService.sendWebSocketNotification('test-notification', {
      message: message || 'Test notification',
      timestamp: new Date().toISOString(),
    });
    res.json({ success: true, message: 'Test notification sent' });
  });

  return router;
}
