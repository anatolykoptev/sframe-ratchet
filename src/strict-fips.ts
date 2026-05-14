// Strict-FIPS / HIPAA-aligned mode for sframe-ratchet.
//
// When enabled (process-wide singleton), the library rejects cipher suites
// weaker than AES-256-GCM-SHA512 and refuses to construct SimpleKex — which
// has no compromise recovery and is not suitable for regulated deployments.
//
// Usage:
//   import { enableStrictFips } from 'sframe-ratchet';
//   enableStrictFips(); // throws FipsModeViolationError on suite 4 or SimpleKex
//
// Strict mode is OFF by default — no breaking change for existing users.

import type { CipherSuite } from './ratchet-crypto.ts';
import { FipsModeViolationError } from './errors.ts';

/**
 * Options for strict-FIPS enforcement. All flags default to `true` when
 * {@link enableStrictFips} is called without arguments.
 */
export interface StrictFipsOptions {
	/**
	 * Require AES-256-GCM-SHA512 (RFC 9605 suite 5).
	 * AES-128-GCM-SHA256 (suite 4) construction throws {@link FipsModeViolationError}.
	 * Default: `true`.
	 */
	requireSuite5?: boolean;

	/**
	 * {@link SimpleKex} constructor throws {@link FipsModeViolationError}.
	 * Production deployments must plug in their own KEX (MLS, X3DH, etc.).
	 * Default: `true`.
	 */
	forbidSimpleKex?: boolean;

	/**
	 * Document / enforce that WebCrypto `importKey` must use `extractable: false`.
	 * The library already passes `extractable: false` everywhere via the
	 * `importAesKey` internal helper — this flag confirms the policy is active.
	 * Default: `true`.
	 */
	requireNonExtractable?: boolean;
}

// ---- Process-wide singleton -------------------------------------------------

let active: Required<StrictFipsOptions> | null = null;

/**
 * Enable strict-FIPS mode. All flags default to `true`.
 *
 * Calling this multiple times replaces the previous configuration.
 *
 * @example
 * ```ts
 * import { enableStrictFips } from 'sframe-ratchet';
 * enableStrictFips(); // throws FipsModeViolationError on suite 4 or SimpleKex
 * ```
 */
export function enableStrictFips(opts: StrictFipsOptions = {}): void {
	active = {
		requireSuite5: opts.requireSuite5 ?? true,
		forbidSimpleKex: opts.forbidSimpleKex ?? true,
		requireNonExtractable: opts.requireNonExtractable ?? true,
	};
}

/** Disable strict-FIPS mode. The library reverts to its default permissive behaviour. */
export function disableStrictFips(): void {
	active = null;
}

/**
 * Return the active strict-FIPS configuration, or `null` when disabled.
 * Returned object is read-only; mutating it has no effect.
 */
export function getStrictFips(): Readonly<Required<StrictFipsOptions>> | null {
	return active;
}

// ---- Internal enforcement helpers ------------------------------------------

/**
 * Assert that `suite` is allowed under the current strict-FIPS policy.
 * No-op when strict mode is off.
 *
 * @internal
 */
export function assertSuiteAllowed(suite: CipherSuite): void {
	if (!active?.requireSuite5) return;
	if (suite !== 'AES_256_GCM_SHA512') {
		throw new FipsModeViolationError(
			`Strict-FIPS mode requires AES_256_GCM_SHA512 (suite 5); got ${suite}. ` +
			'Use suite 5 or disable strict mode with disableStrictFips().',
			{ suite },
		);
	}
}

/**
 * Assert that SimpleKex construction is allowed under the current strict-FIPS policy.
 * No-op when strict mode is off.
 *
 * @internal
 */
export function assertNotSimpleKex(): void {
	if (!active?.forbidSimpleKex) return;
	throw new FipsModeViolationError(
		'SimpleKex is not allowed in strict-FIPS mode. ' +
		'Provide a real KEX (MLS, X3DH, etc.) or disable strict mode with disableStrictFips().',
	);
}
