import { createRestricto, restrictoAxios, RestrictoError, solvePow } from './index';

/**
 * `<script src="restricto.global.js" data-restricto-global="Restricto">` exposes `window.Restricto = { createRestricto, ... }`.
 * Without the attribute NOTHING is attached to `window`: a global signing factory is a convenience for injected scripts (XSS), so
 * the app must opt in, and may pick an unpredictable name. Prefer the npm package and a bundler.
 */
const api = { createRestricto, restrictoAxios, RestrictoError, solvePow };
const script = typeof document !== 'undefined' ? (document.currentScript as HTMLScriptElement | null) : null;
const name = script?.getAttribute('data-restricto-global');
if (name && /^[A-Za-z_$][\w$]*$/.test(name)) (globalThis as Record<string, unknown>)[name] = api;

export {};
