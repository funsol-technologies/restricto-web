import { RestrictoError } from './errors';

export const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024;

export type SignableBody = string | URLSearchParams | Blob | ArrayBuffer | ArrayBufferView | null | undefined;

export interface PreparedBody {
  /** Exact bytes the server will hash; undefined when there is no body. */
  bytes: Uint8Array | undefined;
  /** What to hand to fetch (the original for string/Blob/params so the browser still sets Content-Type). */
  send: BodyInit | undefined;
}

const UPLOAD_HINT = 'sign uploads by requesting a presigned storage URL through a signed call, then upload to that URL directly';

export async function prepareBody(body: unknown, maxBytes: number): Promise<PreparedBody> {
  let out: PreparedBody;
  if (body === undefined || body === null) return { bytes: undefined, send: undefined };
  if (typeof body === 'string') out = { bytes: new TextEncoder().encode(body), send: body };
  else if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams)
    out = { bytes: new TextEncoder().encode(body.toString()), send: body };
  else if (typeof Blob !== 'undefined' && body instanceof Blob) {
    if (body.size > maxBytes) throw tooLarge(maxBytes);
    out = { bytes: new Uint8Array(await body.arrayBuffer()), send: body };
  } else if (body instanceof ArrayBuffer) out = { bytes: new Uint8Array(body), send: body };
  else if (ArrayBuffer.isView(body)) out = { bytes: new Uint8Array(body.buffer, body.byteOffset, body.byteLength), send: body as unknown as BodyInit };
  else if (typeof FormData !== 'undefined' && body instanceof FormData)
    throw new RestrictoError('unsupported_body', `FormData bodies cannot be signed (the multipart boundary is chosen by the browser); ${UPLOAD_HINT}.`);
  else if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream)
    throw new RestrictoError('unsupported_body', `Streaming bodies cannot be signed (the hash covers the whole body); ${UPLOAD_HINT}.`);
  else throw new RestrictoError('unsupported_body', 'Unsupported body type; pass a string, URLSearchParams, Blob or ArrayBuffer.');
  if (out.bytes && out.bytes.byteLength > maxBytes) throw tooLarge(maxBytes);
  return out;
}

function tooLarge(max: number): RestrictoError {
  return new RestrictoError('body_too_large', `Signed request bodies are limited to ${max} bytes; ${UPLOAD_HINT}.`);
}
