import 'express-serve-static-core';
import type { Request, Response, NextFunction } from 'express';

declare module 'express-serve-static-core' {
  interface Request {
    user?: {
      _id: string;
      role?: string;
      tenantId?: string;
      id?: string;
      userId?: string;
    };
    tokenData?: unknown;
    tenantId?: string;
    overrideUser?: {
      username: string;
      role: string;
      timestamp: string;
    };
    method?: string;
    url?: string;
    path?: string;
    originalUrl?: string;
    ip?: string;
    id?: string;
    headers?: Record<string, unknown>;
    connection?: {
      remoteAddress?: string;
    };
  }

  interface Response {
    statusCode?: number;
  }
}

// Extended AppError type for error handler
interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
  timestamp?: string;
  details?: unknown;
  requestId?: string;
  stack?: string;
}

// Export types for use in error handlers
export type { Request, Response, NextFunction };

// Express middleware function type
export type ExpressMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => void;

