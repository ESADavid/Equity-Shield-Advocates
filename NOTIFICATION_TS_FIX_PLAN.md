# Multi-Channel Notification Service TypeScript Fix Plan

## Task Summary
Fix TypeScript errors in `services/multiChannelNotificationService.js` based on provided diagnostic output.

## Information Gathered

### File Analyzed
- **File**: `services/multiChannelNotificationService.js`
- **Language**: JavaScript with TypeScript checking enabled (checkJs: true)
- **TypeScript Config**: strict: true, noImplicitAny: true

### Issues Identified (46 errors/warnings)

#### 1. Missing nodemailer type declaration (7016)
- **Line 17**: `import nodemailer from 'nodemailer'`
- **Fix**: Install `@types/nodemailer` or create declaration file

#### 2. Async function return type issues (1064)
- **Lines 221, 342, 693**: Async functions must return `Promise<T>`
- **Fix**: Add proper return type annotations to async functions

#### 3. Property doesn't exist on Object (2339) - Multiple instances
- **Lines 226-231**: Destructured properties from `notificationData`
- **Lines 314**: `sentAt` property access
- **Lines 606-637**: Properties accessed on filter objects
- **Fix**: Define proper interface/types for these objects

#### 4. Implicit 'any' type for expression (7053) - Multiple instances
- **Lines 293, 299, 305**: Dynamic property access on objects
- **Line 514**: Channel lookup in preferences
- **Fix**: Add proper index signatures or type guards

#### 5. Implicit 'any' parameter type (7006) - Multiple instances
- **Lines 365, 405, 433, 459**: Function parameters without types
- **Line 494**: Multiple parameters
- **Line 507**: channel, preferences parameters
- **Line 520**: Multiple parameters
- **Fix**: Add type annotations to all parameters

#### 6. Generic type Array<T> requires type argument (2314)
- **Line 692**: `Array` used without type argument
- **Fix**: Add `<NotificationType>` or use `any[]`

#### 7. Arithmetic operation type issues (2362, 2363)
- **Line 632**: Date arithmetic
- **Fix**: Explicitly convert to timestamps

#### 8. Unused imports/variables (6133, S1128)
- **Line 16**: `debug` imported but never used
- **Line 405**: `userId` declared but never read
- **Fix**: Remove unused declarations

#### 9. Deprecated API (S1874)
- **Line 252**: `substr` is deprecated
- **Fix**: Use `substring` instead

#### 10. Unexpected await of non-Promise (S4123)
- **Lines 287, 700**: Await of non-Promise value
- **Fix**: Wrap in Promise.resolve() or remove await

## Detailed Fix Plan

### Phase 1: Install Type Definitions
```bash
npm install --save-dev @types/nodemailer
```

### Phase 2: Define TypeScript Interfaces
Add at the top of the file:
```typescript
// Type definitions
interface NotificationData {
  userId: string;
  templateId: string;
  channels?: string[];
  data?: Record<string, any>;
  priority?: string;
  scheduledFor?: string | null;
}

interface Notification {
  id: string;
  userId: string;
  templateId: string;
  templateName: string;
  priority: string;
  channels: string[];
  data: Record<string, any>;
  status: string;
  scheduledFor: string | null;
  createdAt: string;
  deliveryStatus: Record<string, any>;
  sentAt?: string;
}

interface Template {
  id: string;
  name: string;
  channels: string[];
  subject: string;
  emailBody: string;
  smsBody: string;
  pushBody: string;
  priority: string;
}

interface UserPreferences {
  email?: boolean;
  sms?: boolean;
  push?: boolean;
  inApp?: boolean;
  updatedAt?: string;
}

interface ChannelPreferences {
  email: boolean;
  sms: boolean;
  push: boolean;
  inApp: boolean;
}

interface FilterOptions {
  status?: string;
  priority?: string;
  startDate?: string;
  endDate?: string;
  page?: number;
  limit?: number;
}

interface SendResult {
  success: boolean;
  error?: string;
  notificationId?: string;
  deliveryResults?: Record<string, any>;
  timestamp?: string;
}
```

### Phase 3: Fix Async Return Types
- Line 221: `async sendNotification(notificationData: NotificationData): Promise<SendResult>`
- Line 342: `async sendToChannel(channel: string, template: Template, data: Record<string, any>, userId: string): Promise<SendResult>`
- Line 693: `async sendBatchNotifications(notifications: NotificationData[]): Promise<SendResult>`

### Phase 4: Fix Parameter Types
- Line 365: Add types to `updatePreferences(userId: string, preferences: UserPreferences)`
- Line 405: Add types to `getPreferences(userId: string)`
- Line 433: Add types to `getNotificationHistory(userId: string, filters?: FilterOptions)`
- Line 459: Add types to `getNotification(notificationId: string)`
- Line 494: Add types to `sendNotification(notificationData: NotificationData)`
- Line 507: Add types to `isChannelEnabled(channel: string, preferences: ChannelPreferences)`
- Line 520: Add types to `logDelivery(notificationId: string, channel: string, result: SendResult)`

### Phase 5: Fix Property Access
- Lines 226-231: Type the destructured object properly
- Line 314: Add `sentAt?: string` to Notification interface
- Lines 606-637: Type filter parameter as `FilterOptions`

### Phase 6: Fix Dynamic Access
- Lines 293, 299, 305: Add proper type assertions
- Line 514: Add channel type checking

### Phase 7: Fix Array Type
- Line 692: Change `Array` to `Array<NotificationData>` or `NotificationData[]`

### Phase 8: Fix Date Arithmetic
- Line 632: Use explicit Date.getTime() for arithmetic

### Phase 9: Remove Unused Code
- Line 16: Remove unused `debug` import
- Line 405: Either use or remove `userId` parameter

### Phase 10: Fix Deprecated API
- Line 252: Replace `substr(2, 9)` with `substring(2, 11)`

### Phase 11: Fix Promise Issues
- Line 287: Wrap non-promise in Promise.resolve()
- Line 700: Wrap non-promise in Promise.resolve()

## Implementation Strategy

1. First, install `@types/nodemailer` 
2. Then add type definitions at the top of the file as JSDoc comments
3. Add JSDoc type annotations to all functions
4. Fix the specific line errors one by one

## Dependent Files
None required - this is a standalone fix

## Followup Steps
- Run TypeScript compiler to verify fixes
- Test the notification service
