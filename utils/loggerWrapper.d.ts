declare module './loggerWrapper.js' {
  export function info(message: string, ...args: any[]): void;
  export function error(message: string, ...args: any[]): void;
  export function warn(message: string, ...args: any[]): void;
  export function debug(message: string, ...args: any[]): void;
}
