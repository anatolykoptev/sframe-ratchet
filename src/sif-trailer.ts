/**
 * SIF (Secure Interoperable Frame) trailer support.
 *
 * The SIF trailer is a fixed byte sequence appended to every SFrame-encrypted
 * frame. A receiver with the same trailer configured can distinguish E2EE
 * frames from plain frames before attempting AEAD — enabling mixed-room
 * deployments where some participants run E2EE and some do not.
 *
 * SECURITY NOTE: The trailer is NOT a security boundary. It is a routing hint.
 * Any adversary can append the trailer bytes to a plain frame and cause the
 * receiver to attempt AEAD (which will fail — AEAD failure, frame drop, no
 * confidentiality breach). False positives due to plaintext accidentally ending
 * in the trailer pattern are possible; see docs/SECURITY.md for the trade-off.
 */

/**
 * Default 9-byte SIF trailer. Chosen to match LiveKit's `SifTrailerMessage`
 * length for cross-implementation interoperability. These bytes are fixed —
 * they are NOT random per call; callers who need isolation should supply a
 * custom trailer via `set-sif-trailer`.
 *
 * Do NOT mutate this constant. Use `getDefaultSifTrailer()` for a safe copy.
 */
export const DEFAULT_SIF_TRAILER: Readonly<Uint8Array> = new Uint8Array([
	0x53, 0x49, 0x46, 0x54, 0x52, 0x41, 0x49, 0x4c, 0x52,
	// ASCII: S I F T R A I L R
]);

/**
 * Returns a fresh copy of `DEFAULT_SIF_TRAILER` safe to pass to
 * `set-sif-trailer` without risk of the caller mutating the library constant.
 */
export function getDefaultSifTrailer(): Uint8Array {
	return new Uint8Array(DEFAULT_SIF_TRAILER);
}
