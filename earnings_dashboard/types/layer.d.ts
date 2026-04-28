declare global {
  interface Window {
    Plaid?: {
      create: (config: {
        token: string;
        onSuccess: (publicToken: string, metadata: Record<string, any>) => void;
        onExit: (error: any, metadata: Record<string, any>) => void;
        onEvent: (eventName: string, metadata: Record<string, any>) => void;
      }) => {
        submit: (data: { phone_number?: string; date_of_birth?: string }) => void;
        open: () => void;
      };
    };
    layerHandler?: {
      submit: (data: { date_of_birth?: string }) => void;
      open: () => void;
    };
  }
}

export {};
