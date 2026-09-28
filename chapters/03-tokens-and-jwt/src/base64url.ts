/** RFC 7515 base64url: normal base64 with URL-safe characters and no `=` padding. */
export function encodeBase64url(value: string | Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

export function decodeBase64url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('invalid base64url: only A-Z, a-z, 0-9, _ and - are allowed');
  }
  return Buffer.from(value, 'base64url');
}

export function encodeJson(value: unknown): string {
  return encodeBase64url(JSON.stringify(value));
}

export function decodeJson<T = Record<string, unknown>>(value: string): T {
  try {
    return JSON.parse(decodeBase64url(value).toString('utf8')) as T;
  } catch (error) {
    throw new Error(`invalid base64url JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}
