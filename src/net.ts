/**
 * A reply may only be acted upon when it really came from the configured origin without redirects. Synthetic responses (tests, service
 * workers) have an empty `url`; an empty URL cannot be checked and is accepted.
 */
export function fromOrigin(res: Response, origin: string): boolean {
  if (res.redirected || res.type === 'opaqueredirect' || res.type === 'opaque') return false;
  if (!res.url) return true;
  try {
    return new URL(res.url).origin === origin;
  } catch {
    return false;
  }
}
