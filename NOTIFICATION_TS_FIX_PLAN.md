<!-- markdownlint-disable MD033 -->

# Notification Service TypeScript Fix Plan

## Overview

Fix TypeScript errors in `services/multiChannelNotificationService.js`

## Errors to Fix

### 1. Line 130 - nodemailer Transport Options (Error 2769)

- **Issue**: 'host' does not exist in type 'Transport<any, TransportOptions> | TransportOptions'
- **Fix**: Add proper type casting or use interface for SMTP config

### 2. Lines 312-322 - notificationData Properties (Error 2339)

- **Issue**: Properties userId, templateId, channels, data, priority, scheduledFor don't exist on type 'Object'
- **Fix**: Add proper JSDoc @param type annotation for notificationData

### 3. Lines 383, 389, 395 - Index Signature (Error 7053)

- **Issue**: Element implicitly has 'any' type because string can't index type '{}'
- **Fix**: Add proper index signature or use Record<string, any>

### 4. Line 404 - sentAt Property (Error 2339)

- **Issue**: 'sentAt' does not exist on notification type
- **Fix**: Add sentAt to notification type definition (it's optional)

### 5. Lines 476, 516 - email/phone Properties (Error 2339)

- **Issue**: 'email' and 'phone' don't exist on type 'Object'
- **Fix**: Add proper typing for data parameter

### 6. Lines 573-821 - Implicit Any Types (Error 7006)

- **Issue**: Multiple parameters have implicit 'any' type
- **Fix**: Add explicit JSDoc @param type annotations

### 7. Line 746 - Arithmetic Operations (Error 2362, 2363)

- **Issue**: Left/right operands must be numeric
- **Fix**: Convert to numbers using Number() or parseInt()

### 8. Line 806 - Array Generic (Error 2314)

- **Issue**: Generic type 'Array<T>' requires type argument
- **Fix**: Add type argument: Array<any> or Array<Notification>

### 9. Line 807 - Promise Return Type (Error 1064)

- **Issue**: Return type must be Promise<T>
- **Fix**: Add explicit Promise<Object> return type

### 10. Line 821 - success Property (Error 2339)

- **Issue**: 'success' doesn't exist on type 'Object'
- **Fix**: Add proper typing for result object

## Implementation Steps

1. Add comprehensive JSDoc type definitions at the top
2. Fix nodemailer transport options with proper typing
3. Add explicit types to all function parameters
4. Fix object property accesses with proper casting
5. Fix arithmetic operations with numeric conversions
6. Add proper return types to all async functions
