import 'express-serve-static-core';

declare module 'express-serve-static-core' {
  interface Request {
    user?: {
      _id: string;
      role?: string;
      tenantId?: string;
    };
    tokenData?: any;
    tenantId?: string;
    overrideUser?: {
      username: string;
      role: string;
      timestamp: string;
    };
  }
}

