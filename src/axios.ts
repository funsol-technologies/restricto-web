import { RestrictoError } from './errors';
import type { RestrictoClient } from './types';

/** The slice of axios' config/response we touch; axios itself is not a dependency. */
export interface AxiosLikeConfig {
  url?: string;
  baseURL?: string;
  method?: string;
  headers?: unknown;
  params?: unknown;
  paramsSerializer?: unknown;
  data?: unknown;
  timeout?: number;
  responseType?: string;
  signal?: AbortSignal | null;
  withCredentials?: boolean;
  validateStatus?: ((status: number) => boolean) | null;
}

export interface AxiosLikeResponse {
  data: unknown;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  config: AxiosLikeConfig;
  request: unknown;
}

function headerRecord(h: unknown): Record<string, string> {
  const raw = h && typeof (h as { toJSON?: unknown }).toJSON === 'function' ? (h as { toJSON(): unknown }).toJSON() : h;
  const out: Record<string, string> = {};
  if (raw && typeof raw === 'object')
    for (const [k, v] of Object.entries(raw)) if ((typeof v === 'string' || typeof v === 'number') && k.toLowerCase() !== 'content-length') out[k] = String(v);
  return out;
}

function buildUrl(c: AxiosLikeConfig): string {
  let url = c.url ?? '';
  if (c.baseURL && !/^[a-z][a-z\d+\-.]*:\/\//i.test(url)) url = `${c.baseURL.replace(/\/+$/, '')}/${url.replace(/^\/+/, '')}`;
  const ser = c.paramsSerializer;
  let qs = '';
  if (typeof ser === 'function') qs = String((ser as (p: unknown) => string)(c.params));
  else if (ser && typeof (ser as { serialize?: unknown }).serialize === 'function') qs = String((ser as { serialize(p: unknown): string }).serialize(c.params));
  else if (c.params instanceof URLSearchParams) qs = c.params.toString();
  else if (c.params && typeof c.params === 'object') {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(c.params)) {
      if (v === null || v === undefined) continue;
      for (const item of Array.isArray(v) ? v : [v])
        sp.append(k, item instanceof Date ? item.toISOString() : typeof item === 'object' ? JSON.stringify(item) : String(item));
    }
    qs = sp.toString();
  }
  return qs ? url + (url.includes('?') ? '&' : '?') + qs : url;
}

function axiosError(message: string, code: string, config: AxiosLikeConfig, response?: AxiosLikeResponse): Error {
  return Object.assign(new Error(message), { isAxiosError: true, code, config, response, status: response?.status, name: 'AxiosError' });
}

const isRawBody = (d: object): boolean =>
  d instanceof ArrayBuffer || ArrayBuffer.isView(d) || d instanceof Blob || d instanceof URLSearchParams || (typeof FormData !== 'undefined' && d instanceof FormData);

/**
 * An axios adapter: `axios.create({ adapter: restrictoAxios(client) })`. An adapter (not a request interceptor) because
 * interceptors run before axios serialises the body, and the signature must cover the exact bytes that are sent.
 */
export function restrictoAxios(client: RestrictoClient): (config: AxiosLikeConfig) => Promise<AxiosLikeResponse> {
  return async (config) => {
    const method = (config.method ?? 'get').toUpperCase();
    let data = config.data;
    if (data !== null && typeof data === 'object' && !isRawBody(data)) data = JSON.stringify(data);

    const ac = new AbortController();
    const outer = config.signal;
    if (outer) {
      if (outer.aborted) ac.abort();
      else outer.addEventListener('abort', () => ac.abort(), { once: true });
    }
    let timedOut = false;
    const timer =
      config.timeout && config.timeout > 0
        ? setTimeout(() => {
            timedOut = true;
            ac.abort();
          }, config.timeout)
        : undefined;

    let res: Response;
    try {
      res = await client.fetch(buildUrl(config), {
        method,
        headers: headerRecord(config.headers),
        body: method === 'GET' || method === 'HEAD' ? undefined : (data as BodyInit | null | undefined),
        credentials: config.withCredentials ? 'include' : undefined,
        signal: ac.signal,
      });
    } catch (e) {
      if (timer) clearTimeout(timer);
      if (e instanceof RestrictoError) throw e;
      if (ac.signal.aborted) throw axiosError(timedOut ? 'timeout exceeded' : 'canceled', timedOut ? 'ECONNABORTED' : 'ERR_CANCELED', config);
      throw axiosError((e as Error).message, 'ERR_NETWORK', config);
    }
    if (timer) clearTimeout(timer);

    let body: unknown;
    if (config.responseType === 'arraybuffer') body = await res.arrayBuffer();
    else if (config.responseType === 'blob') body = await res.blob();
    else if (config.responseType === 'stream')
      throw new RestrictoError('unsupported_body', 'responseType "stream" cannot be verified; use arraybuffer or json.');
    else {
      const text = await res.text();
      if (config.responseType === 'text') body = text;
      else {
        try {
          body = text ? JSON.parse(text) : text;
        } catch {
          body = text;
        }
      }
    }
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    const out: AxiosLikeResponse = { data: body, status: res.status, statusText: res.statusText, headers, config, request: {} };
    const ok = (config.validateStatus ?? ((s: number) => s >= 200 && s < 300))(res.status);
    if (!ok)
      throw axiosError(`Request failed with status code ${res.status}`, res.status >= 500 ? 'ERR_BAD_RESPONSE' : 'ERR_BAD_REQUEST', config, out);
    return out;
  };
}
