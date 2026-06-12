const SENSITIVE_KEYS = ['client_secret', 'authorization', 'access_token', 'refresh_token', 'token'];

function maskValue(value) {
  if (typeof value !== 'string') return '[REDACTED]';
  if (value.length <= 8) return '[REDACTED]';
  return `${value.slice(0, 4)}***${value.slice(-2)}`;
}

export function redactObject(input) {
  if (input === null || input === undefined) return input;
  if (Array.isArray(input)) return input.map(redactObject);
  if (typeof input !== 'object') return input;

  const out = {};
  for (const [key, value] of Object.entries(input)) {
    const lower = key.toLowerCase();
    if (SENSITIVE_KEYS.some((k) => lower.includes(k))) {
      out[key] = maskValue(String(value));
      continue;
    }
    out[key] = redactObject(value);
  }
  return out;
}

export function redactText(text) {
  if (!text || typeof text !== 'string') return text;
  return text
    .replace(/(client_secret=)([^&\s]+)/gi, '$1[REDACTED]')
    .replace(/(authorization:\s*bearer\s+)([a-z0-9\-._~+/]+=*)/gi, '$1[REDACTED]')
    .replace(/("access_token"\s*:\s*")[^"]+(")/gi, '$1[REDACTED]$2');
}
