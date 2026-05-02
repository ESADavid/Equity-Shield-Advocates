declare module 'response-time' {
  import { RequestHandler } from 'express';

  interface ResponseTimeOptions {
    digits?: number;
    header?: string;
    suffix?: boolean;
  }

  type ResponseTimeCallback = (
    req: any,
    res: any,
    time: number
  ) => void;

  function responseTime(options?: ResponseTimeOptions): RequestHandler;
  function responseTime(
    callback: ResponseTimeCallback
  ): RequestHandler;
  export = responseTime;
}
