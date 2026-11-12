export interface ProxyRequestOptions {
  url: string;
  method: string;
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
}

export interface ProxyResponse {
  status: number;
  body: unknown;
  contentType?: string;
  setCookies: string[];
  retryAfter?: string;
}

export class ProxyRequestError extends Error {
  readonly kind: 'timeout' | 'network';

  constructor(kind: 'timeout' | 'network') {
    super(kind === 'timeout' ? 'Upstream request timed out' : 'Upstream request failed');
    this.name = 'ProxyRequestError';
    this.kind = kind;
  }
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

export async function proxyRequest(options: ProxyRequestOptions): Promise<ProxyResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  const fetchImpl = options.fetchImpl ?? fetch;

  try {
    const response = await fetchImpl(options.url, {
      method: options.method,
      headers: options.headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
    });
    const text = await response.text();
    if (text.length === 0) {
      return {
        status: response.status,
        body: undefined,
        contentType: response.headers.get('content-type') ?? undefined,
        setCookies: response.headers.getSetCookie?.() ?? [],
      };
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.toLowerCase().includes('json')) {
      try {
        return {
          status: response.status,
          body: JSON.parse(text),
          retryAfter: response.headers.get('retry-after') ?? undefined,
          contentType,
          setCookies: response.headers.getSetCookie?.() ?? [],
        };
      } catch {
        return {
          status: response.status,
          body: { message: 'Upstream returned an invalid response' },
          contentType,
          setCookies: response.headers.getSetCookie?.() ?? [],
        };
      }
    }

    return {
      status: response.status,
      body: { message: 'Upstream returned an unsupported response' },
      contentType,
      setCookies: response.headers.getSetCookie?.() ?? [],
    };
  } catch (error) {
    throw new ProxyRequestError(isAbortError(error) ? 'timeout' : 'network');
  } finally {
    clearTimeout(timeout);
  }
}
