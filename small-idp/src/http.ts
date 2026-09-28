import type { IncomingMessage, ServerResponse } from 'node:http';

const MAX_BODY = 32 * 1024;

export async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY) throw new Error('request body too large');
    chunks.push(buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

export function formObject(form: URLSearchParams): Record<string, string> {
  const out: Record<string, string> = {};
  form.forEach((value, key) => { out[key] = value; });
  return out;
}

export function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

export type Headers = Record<string, string | string[]>;

export function json(res: ServerResponse, status: number, body: unknown, headers: Headers = {}): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    pragma: 'no-cache',
    ...headers,
  });
  res.end(JSON.stringify(body, null, 2));
}

export function html(res: ServerResponse, status: number, body: string, headers: Headers = {}): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:*",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    ...headers,
  });
  res.end(body);
}

export function redirect(res: ServerResponse, location: string, headers: Headers = {}): void {
  res.writeHead(302, { location, 'cache-control': 'no-store', ...headers });
  res.end();
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]!);
}
