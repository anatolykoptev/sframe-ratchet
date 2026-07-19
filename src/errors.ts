// Typed error hierarchy for sframe-ratchet.
// Callers can branch on error class rather than parsing message strings:
//   if (err instanceof StaleEpochError) { ... err.context.frameEpoch ... }
//
// All domain errors extend SFrameError (abstract base).
// Programmer-mistake / invariant violations stay as generic Error / TypeError.

/**
 * Abstract base for all sframe-ratchet domain errors.
 * `code` is a stable machine-readable identifier; `context` carries structured
 * fields so callers never need to parse `message`.
 */
export abstract class SFrameError extends Error {
	abstract readonly code: string;

	constructor(message: string, public readonly context?: Record<string, unknown>) {
		super(message);
		this.name = this.constructor.name;
		// Restore prototype chain in transpiled environments.
		Object.setPrototypeOf(this, new.target.prototype);
	}
}

/**
 * No key found for the given (epoch, peerIndex) pair.
 * Thrown by the decrypt path when the epoch is missing or the peer is not in
 * the epoch's key table.
 */
export class KeyNotFoundError extends SFrameError {
	readonly code = 'KEY_NOT_FOUND' as const;

	constructor(
		message: string,
		public override readonly context: { kid?: number; epoch?: number; peerIndex?: number },
	) {
		super(message, context);
	}
}

/**
 * Incoming frame carries an epoch older than the receiver's stale-epoch gate
 * (`currentMinValidEpoch`). The frame is discarded without any AEAD attempt.
 * Spec §7.4.
 */
export class StaleEpochError extends SFrameError {
	readonly code = 'STALE_EPOCH' as const;

	constructor(
		message: string,
		public override readonly context: { frameEpoch: number; minValidEpoch: number; kid?: number },
	) {
		super(message, context);
	}
}

/**
 * AES-GCM authentication tag verification failed.
 * Thrown when WebCrypto rejects the ciphertext — key mismatch, corrupted frame,
 * or wrong nonce. The retry window in `tryDecryptWithRatchet` re-throws this
 * after exhausting all ratchet steps.
 */
export class AEADAuthError extends SFrameError {
	readonly code = 'AEAD_AUTH_FAIL' as const;

	constructor(
		message: string,
		public override readonly context: { kid?: number; epoch?: number; peerIndex?: number; ctr?: bigint },
	) {
		super(message, context);
	}
}

/**
 * Forward ratchet retry window exhausted without a matching key.
 * Thrown after `ratchetWindowSize` unsuccessful AEAD attempts within the same epoch.
 */
export class RatchetWindowExhaustedError extends SFrameError {
	readonly code = 'RATCHET_WINDOW_EXHAUSTED' as const;

	constructor(
		message: string,
		public override readonly context: { epoch: number; peerIndex: number; attempts: number },
	) {
		super(message, context);
	}
}

/**
 * SFrame header parse failure — buffer too short, truncated KID/CTR field, or
 * KID value outside safe-integer range.
 */
export class HeaderParseError extends SFrameError {
	readonly code = 'HEADER_PARSE' as const;

	constructor(
		message: string,
		public override readonly context?: { bufferLength?: number },
	) {
		super(message, context);
	}
}

/**
 * Pre-epoch frame queue is full; the oldest queued frame was dropped to make
 * room for the incoming one.
 */
export class QueueFullError extends SFrameError {
	readonly code = 'QUEUE_FULL' as const;

	constructor(
		message: string,
		public override readonly context?: Record<string, unknown>,
	) {
		super(message, context);
	}
}

/**
 * A strict-FIPS policy violation. Thrown when an operation (cipher suite
 * selection, SimpleKex construction, etc.) violates the active
 * {@link enableStrictFips} configuration.
 *
 * Check `err.code === 'FIPS_VIOLATION'` or `err instanceof FipsModeViolationError`.
 */
export class FipsModeViolationError extends SFrameError {
	readonly code = 'FIPS_VIOLATION' as const;

	constructor(
		message: string,
		public override readonly context?: Record<string, unknown>,
	) {
		super(message, context);
	}
}

/**
 * Anti-replay window rejected a frame whose CTR was already seen within the
 * current (epoch, peerIndex) sliding window (RFC 9605 §9.3, issue #10).
 *
 * Thrown by `decodeFrame` / `drainPreEpochQueue` AFTER `parseHeader` succeeds
 * and the stale-epoch gate passes, but BEFORE any AEAD attempt — so a replayed
 * frame never consumes ratchet-retry budget and never touches WebCrypto.
 * `accept(ctr)` is only called after a successful AEAD decrypt, so a replayed
 * frame that fails the window check is never recorded as "seen" again.
 */
export class ReplayError extends SFrameError {
	readonly code = 'REPLAY' as const;

	constructor(
		message: string,
		public override readonly context: { epoch: number; peerIndex: number; ctr: bigint },
	) {
		super(message, context);
	}
}
