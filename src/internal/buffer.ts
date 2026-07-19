/**
 * Small ArrayBuffer helpers shared across the crypto-touching modules.
 *
 * Extracted from the source app's `$lib/crypto-utils` (oxpulse-chat).
 *
 * Solves two problems at once:
 *
 *  1. Parent-buffer aliasing. `u8.buffer` returns the underlying buffer,
 *     which can be larger than `u8` when the view is a subarray/slice
 *     (`byteOffset > 0`). Passing `u8.buffer` directly to WebCrypto
 *     (`importKey('raw', ...)`, HKDF salt, `digest`, etc.) silently feeds
 *     the full parent buffer — wrong IKM / salt / digest input, no error.
 *
 *  2. SharedArrayBuffer leakage. `u8.buffer.slice(...)` is typed
 *     `ArrayBufferLike` — if the view is over a SharedArrayBuffer the
 *     slice is also a SharedArrayBuffer, and WebCrypto rejects shared
 *     buffers at the validation boundary.
 *
 * Allocating a fresh `new ArrayBuffer(...)` and `set`-ing the bytes into
 * it produces a plain, exclusive, non-shared ArrayBuffer of exactly the
 * right length.
 */
export function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(u8.byteLength);
	new Uint8Array(out).set(u8);
	return out;
}

/**
 * Returns a BufferSource safe to pass to WebCrypto.
 *
 * Skips the copy when the Uint8Array owns its entire underlying buffer
 * (byteOffset === 0 && byteLength === buffer.byteLength) AND the buffer
 * is a plain ArrayBuffer (not SharedArrayBuffer).
 *
 * Use ONLY for buffers known to be freshly allocated by this library
 * (e.g. deriveIv output, serializeHeader output). Do NOT use for
 * caller-supplied buffers where subarray/shared status is unknown —
 * use the existing toArrayBuffer copy for those.
 */
export function bufferSourceOf(u8: Uint8Array): BufferSource {
	if (
		u8.byteOffset === 0 &&
		u8.byteLength === u8.buffer.byteLength &&
		!(typeof SharedArrayBuffer !== 'undefined' && u8.buffer instanceof SharedArrayBuffer)
	) {
		// We've excluded SharedArrayBuffer above; cast is sound.
		return u8.buffer as ArrayBuffer;
	}
	// Subarray or SharedArrayBuffer — fall back to an exclusive copy.
	const out = new ArrayBuffer(u8.byteLength);
	new Uint8Array(out).set(u8);
	return out;
}

/**
 * Zero-fill a Uint8Array in place. Use on sensitive key material (ChainKey,
 * rawKey, DH secrets) before dropping the reference so the bytes don't linger
 * in the JS heap until GC.
 *
 * Mirrors ts-mls's `zeroOutUint8Array` — kept local to avoid pulling ts-mls
 * as a hard dependency of the core ECIES/worker paths.
 */
export function zeroize(u8: Uint8Array): void {
	u8.fill(0);
}

/**
 * Concatenate two Uint8Arrays into a fresh allocation.
 *
 * Replaces the inline 2-arg concat duplicated in `chat/derive.ts` and
 * `ratchet-ids.ts` (repo-review-council NOISE finding).
 */
export function concat2(a: Uint8Array, b: Uint8Array): Uint8Array {
	const out = new Uint8Array(a.byteLength + b.byteLength);
	out.set(a, 0);
	out.set(b, a.byteLength);
	return out;
}

/**
 * Shared TextEncoder for constant-string encoding across modules.
 *
 * `new TextEncoder()` is cheap but not free; reusing one instance avoids
 * repeated construction in hot paths and constant initializers.
 */
export const textEncoder: TextEncoder = new TextEncoder();
