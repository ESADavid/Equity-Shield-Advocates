import { redactObject } from './redact.js';

function log(level, message, meta = {}) {
  const entry = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...redactObject(meta)
  };

  const line = JSON.stringify(entry);
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

export const logger = {
  info: (message, meta) => log('info', message, meta),
  warn: (message, meta) => log('warn', message, meta),
  error: (message, meta) => log('error', message, meta),
  debug: (message, meta) => log('debug', message, meta)
};
