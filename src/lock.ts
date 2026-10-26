const chains = new Map<string, Promise<unknown>>();

/**
 * Run `fn` exclusively for `name`: across tabs through the Web Locks API, and within this page through a promise chain
 * (the fallback where Web Locks is missing, and also what serialises two clients created for the same app).
 */
export function withLock<T>(name: string, fn: () => Promise<T>, useWebLocks = true): Promise<T> {
  const prev = chains.get(name) ?? Promise.resolve();
  const run = async (): Promise<T> => {
    const locks = useWebLocks && typeof navigator !== 'undefined' ? navigator.locks : undefined;
    return locks ? locks.request(name, fn) : fn();
  };
  const next = prev.then(run, run);
  const tail = next.catch(() => undefined);
  chains.set(name, tail);
  tail.then(() => {
    if (chains.get(name) === tail) chains.delete(name);
  });
  return next;
}
