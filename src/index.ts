// Public API barrel for sframe-ratchet.
// Conservative export: types, top-level classes, and functions exercised
// by the bundled test suite. Internals (worker-state, worker-frame, buffer)
// are NOT re-exported — they are implementation details.

// ---- Types ----------------------------------------------------------------
export type {
	EpochAnnouncement,
	EpochKey,
	IdentityKeyPair,
	MemberChange,
	PeerIdentity,
	PeerIndex,
	SFrameDecryptEvent,
	SFrameKey,
	SFrameKeyLookup,
	SFrameKeyResolver,
	SFrameSupport,
} from './types.js';

// ---- Typed error hierarchy ------------------------------------------------
export {
	SFrameError,
	KeyNotFoundError,
	StaleEpochError,
	AEADAuthError,
	RatchetWindowExhaustedError,
	HeaderParseError,
	QueueFullError,
	FipsModeViolationError,
} from './errors.js';

// ---- Strict-FIPS mode ----------------------------------------------------
export {
	enableStrictFips,
	disableStrictFips,
	getStrictFips,
} from './strict-fips.js';
export type { StrictFipsOptions } from './strict-fips.js';

// ---- SFrame AEAD ----------------------------------------------------------
export { sframeEncrypt, sframeDecrypt } from './sframe.js';
export { parseHeader, serializeHeader } from './sframe-header.js';
export type { SFrameHeader } from './sframe-header.js';

// ---- Ratchet (epoch / key management) ------------------------------------
export { RoomRatchet } from './ratchet.js';
export type { RoomRatchetOptions } from './ratchet.js';

// ---- Ratchet IDs / KID helpers -------------------------------------------
export {
	makeKid,
	splitKid,
	joinKid,
	newIdentity,
	validatePeerIndexMap,
	buildPeerIndexMap,
	hkdfInfo,
	peerIndexBe16,
	SFRAME_INFO_KEY,
	SFRAME_INFO_SALT,
} from './ratchet-ids.js';
export type { PeerIndexMapValidation } from './ratchet-ids.js';

// ---- Cipher suites (RFC 9605 §4.5) ----------------------------------------
export type { CipherSuite } from './ratchet-crypto.js';
export {
	DEFAULT_CIPHER_SUITE,
	suiteParams,
} from './ratchet-crypto.js';

// ---- Ratchet crypto primitives -------------------------------------------
export {
	deriveSenderKeys,
	deriveEpochKeyTable,
	deriveWrapKey,
	randomChainKey,
	generateX25519Keypair,
	x25519Dh,
	wrapChainKey,
	unwrapChainKey,
	X25519_KEY_BYTES,
	CHAIN_KEY_BYTES,
	SFRAME_SALT_BYTES,
} from './ratchet-crypto.js';

// ---- Frame cryptor (main-thread glue) ------------------------------------
export { FrameCryptor, supportsSFrame } from './frame-cryptor.js';
export type { FrameCryptorOptions, EpochParams } from './frame-cryptor.js';

// ---- Codec-aware partial encryption --------------------------------------
export { getUnencryptedBytes } from './codec-partial.js';
export type { Codec, FrameKind } from './worker-types.js';

// ---- SIF trailer (mixed-room support) ------------------------------------
export { DEFAULT_SIF_TRAILER, getDefaultSifTrailer } from './sif-trailer.js';
export type { SetSifTrailerMsg } from './worker-types.js';

// ---- Telemetry / observability --------------------------------------------
export type { MetricsEvent } from './worker-types.js';

/**
 * Subscribe to telemetry events posted by the sframe worker.
 *
 * The worker must have `set-metrics-enabled` sent with `enabled: true` before
 * events are emitted. This helper adds a `message` listener on `worker` and
 * filters for `data.type === 'metrics'`. It wraps the user handler in a
 * try/catch so a buggy handler cannot suppress subsequent events.
 *
 * @returns An unsubscribe function. Call it to remove the listener.
 *
 * @example
 * ```ts
 * worker.postMessage({ type: 'set-metrics-enabled', enabled: true });
 * const off = onMetrics(worker, (ev) => {
 *   if (ev.kind === 'encrypt') encryptCounter++;
 * });
 * // later:
 * off();
 * ```
 */
export function onMetrics(
	worker: { addEventListener(type: 'message', listener: (ev: MessageEvent) => void): void;
	          removeEventListener(type: 'message', listener: (ev: MessageEvent) => void): void },
	handler: (ev: import('./worker-types.js').MetricsEvent) => void,
): () => void {
	const listener = (ev: MessageEvent): void => {
		if (ev.data?.type !== 'metrics') return;
		try {
			handler(ev.data.event as import('./worker-types.js').MetricsEvent);
		} catch {
			// Swallow — a buggy handler must not break subsequent listeners.
		}
	};
	worker.addEventListener('message', listener);
	return () => worker.removeEventListener('message', listener);
}
