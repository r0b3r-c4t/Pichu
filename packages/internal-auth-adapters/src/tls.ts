import { readFileSync } from 'node:fs';
import { request as httpsRequest, type RequestOptions, type ServerOptions } from 'node:https';
import { URL } from 'node:url';

export interface TlsServerConfig {
  certPath: string;
  keyPath: string;
  caPath: string;
}

export interface TlsClientConfig {
  caPath: string;
  servername?: string;
}

export function readTlsServerOptions(config: TlsServerConfig): ServerOptions {
  if (!config.certPath || !config.keyPath || !config.caPath)
    throw new Error('Incomplete TLS configuration');
  const cert = readFileSync(config.certPath);
  const key = readFileSync(config.keyPath);
  const ca = readFileSync(config.caPath);
  if (!cert.length || !key.length || !ca.length) throw new Error('Empty TLS configuration');
  return { cert, key, ca, minVersion: 'TLSv1.2' };
}

export function readTlsClientOptions(
  config: TlsClientConfig,
): Pick<RequestOptions, 'ca' | 'servername'> {
  if (!config.caPath) throw new Error('Incomplete TLS client configuration');
  const ca = readFileSync(config.caPath);
  if (!ca.length) throw new Error('Empty TLS CA configuration');
  return { ca, servername: config.servername };
}

export interface HttpsJsonRequestOptions {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
  signal?: AbortSignal;
  timeoutMs: number;
  tls: TlsClientConfig;
}

export interface HttpsJsonResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export function httpsJsonRequest(options: HttpsJsonRequestOptions): Promise<HttpsJsonResponse> {
  const target = new URL(options.url);
  if (target.protocol !== 'https:') throw new Error('Internal TLS requires HTTPS');
  const tls = readTlsClientOptions(options.tls);
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        method: options.method ?? 'GET',
        headers: options.headers,
        ...tls,
        rejectUnauthorized: true,
        timeout: options.timeoutMs,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let body: unknown = undefined;
          if (raw.length > 0) {
            try {
              body = JSON.parse(raw);
            } catch {
              body = { message: 'Upstream returned an invalid response' };
            }
          }
          const headers: Record<string, string> = {};
          for (const [key, value] of Object.entries(response.headers)) {
            if (typeof value === 'string') headers[key] = value;
            else if (Array.isArray(value)) headers[key] = value.join(', ');
          }
          resolve({ status: response.statusCode ?? 0, headers, body });
        });
      },
    );
    request.once('error', reject);
    request.once('timeout', () => request.destroy(new Error('HTTPS request timed out')));
    const abort = () => request.destroy(new Error('HTTPS request aborted'));
    if (options.signal) {
      if (options.signal.aborted) abort();
      else options.signal.addEventListener('abort', abort, { once: true });
      request.once('close', () => options.signal?.removeEventListener('abort', abort));
    }
    if (options.body) request.write(Buffer.from(options.body));
    request.end();
  });
}

export async function internalJsonRequest(
  options: HttpsJsonRequestOptions,
): Promise<HttpsJsonResponse> {
  if (new URL(options.url).protocol === 'https:') return httpsJsonRequest(options);
  if (new URL(options.url).protocol !== 'http:')
    throw new Error('Internal request requires HTTP(S)');
  const response = await fetch(options.url, {
    method: options.method,
    headers: options.headers,
    body: options.body ? Buffer.from(options.body) : undefined,
    signal: options.signal,
  });
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers),
    body: await response.json().catch(() => undefined),
  };
}
