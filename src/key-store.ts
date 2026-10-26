import { RestrictoError } from './errors';

/** Everything persisted per app. `privateKey` is a non-extractable CryptoKey: it can be stored and used, never read. */
export interface StoredDevice {
  privateKey: CryptoKey;
  /** SPKI DER, base64url - what the server sees as `public_key`. */
  publicKey: string;
  deviceId?: string;
  trustLevel?: number;
  /** unix seconds (server clock) */
  attestedUntil?: number;
}

export interface KeyStore {
  get(namespace: string): Promise<StoredDevice | undefined>;
  put(namespace: string, device: StoredDevice): Promise<void>;
  delete(namespace: string): Promise<void>;
}

export function createMemoryKeyStore(): KeyStore {
  const map = new Map<string, StoredDevice>();
  return {
    get: async (ns) => map.get(ns),
    put: async (ns, d) => void map.set(ns, d),
    delete: async (ns) => void map.delete(ns),
  };
}

const STORE = 'devices';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexedDB request failed'));
  });
}

export function createIndexedDbKeyStore(dbName = 'restricto-web'): KeyStore {
  let opened: Promise<IDBDatabase> | undefined;
  const open = (): Promise<IDBDatabase> => {
    opened ??= new Promise((resolve, reject) => {
      if (typeof indexedDB === 'undefined') return reject(new RestrictoError('unsupported_environment', 'IndexedDB is not available.'));
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('indexedDB open failed'));
    });
    opened.catch(() => (opened = undefined));
    return opened;
  };
  const store = async (mode: IDBTransactionMode): Promise<IDBObjectStore> => (await open()).transaction(STORE, mode).objectStore(STORE);
  return {
    get: async (ns) => (await request((await store('readonly')).get(ns))) as StoredDevice | undefined,
    put: async (ns, d) => void (await request((await store('readwrite')).put(d, ns))),
    delete: async (ns) => void (await request((await store('readwrite')).delete(ns))),
  };
}

/**
 * IndexedDB when the browser offers it, otherwise (SSR, some private modes) a per-page memory store: the device then
 * re-registers on every page load, which costs a proof of work but is never insecure.
 */
export function defaultKeyStore(): KeyStore {
  const memory = createMemoryKeyStore();
  let idb: KeyStore | undefined = typeof indexedDB === 'undefined' ? undefined : createIndexedDbKeyStore();
  const run = async <T>(op: (s: KeyStore) => Promise<T>): Promise<T> => {
    if (!idb) return op(memory);
    try {
      return await op(idb);
    } catch {
      idb = undefined;
      return op(memory);
    }
  };
  return {
    get: (ns) => run((s) => s.get(ns)),
    put: (ns, d) => run((s) => s.put(ns, d)),
    delete: (ns) => run((s) => s.delete(ns)),
  };
}
