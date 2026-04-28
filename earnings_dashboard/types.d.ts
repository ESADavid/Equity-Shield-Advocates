declare module 'cors' {
  import { RequestHandler } from 'express';

  interface CorsOptions {
    origin?:
      | boolean
      | string
      | RegExp
      | (string | RegExp)[]
      | ((
          origin: string | undefined,
          callback: (err: Error | null, allow?: boolean) => void
        ) => void);
    methods?: string | string[];
    allowedHeaders?: string | string[];
    exposedHeaders?: string | string[];
    credentials?: boolean;
    maxAge?: number;
    preflightContinue?: boolean;
    optionsSuccessStatus?: number;
  }

  function cors(options?: CorsOptions): RequestHandler;
  export = cors;
}

declare module 'express-basic-auth' {
  export default function basicAuth(options: any): import('express').RequestHandler;
}

declare module 'morgan' {
  import { RequestHandler } from 'express';

  interface MorganOptions {
    stream?: {
      write: (message: string) => void;
    };
    skip?: (req: any, res: any) => boolean;
    immediate?: boolean;
  }

  function morgan(format: string, options?: MorganOptions): RequestHandler;
  export = morgan;
}

// React JSX Support
declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
}

// Plaid Link / Layer Types
declare module 'react-plaid-link' {
  import { ComponentProps } from 'react';

  interface PlaidLinkProps {
    token: string;
    onSuccess: (publicToken: string, metadata: Record<string, any>) => void;
    onExit: (error: any, metadata: Record<string, any>) => void;
    onEvent: (eventName: string, metadata?: Record<string, any>) => void;
    children?: React.ReactNode;
  }

  export const usePlaidLink: () => {
    open: () => void;
    ready: () => void;
  };

  const PlaidLink: React.FC<PlaidLinkProps>;
  export default PlaidLink;
}

// Plaid.create for Layer
interface PlaidLayerHandler {
  submit: (data: Record<string, string>) => void;
  open: () => void;
}

interface Window {
  layerHandler?: PlaidLayerHandler;
}

declare var Plaid: {
  create: (config: {
    token: string;
    onSuccess: (publicToken: string, metadata: Record<string, any>) => void;
    onExit: (err: unknown, metadata: Record<string, any>) => void;
    onEvent?: (eventName: string, metadata?: Record<string, any>) => void;
  }) => PlaidLayerHandler;
};

