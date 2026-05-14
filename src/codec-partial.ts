// Codec-aware partial encryption helper.
// Returns the number of unencrypted prefix bytes that must be left in the
// clear so the SFU can route by frame type and browser decoders can fail
// gracefully (garbage instead of fatal parse error) on key mismatch.
//
// Wire format produced by encodeFrame:
//   [unencrypted prefix (N bytes)] [SFrame header] [AES-GCM ciphertext + tag]
//
// Receiver MUST know the codec out-of-band (same constraint as LiveKit's
// FrameCryptor) to know how many bytes to peel from the front before
// handing the rest to the SFrame decode path.
//
// SECURITY NOTE: the unencrypted prefix bytes are NOT included in AES-GCM
// additional-authenticated-data. An attacker who can modify these bytes can
// corrupt the codec header without detection. This is the documented
// trade-off for SFU compatibility. See docs/SECURITY.md.

import type { Codec, FrameKind } from './worker-types.ts';

/**
 * Returns the number of plaintext bytes at the front of an encoded frame
 * that must remain unencrypted.  N=0 means full encryption (default path).
 *
 * @param codec    Per-track codec, set via StreamsMsg.  Undefined → full encrypt.
 * @param frameKind  'key' or 'inter'; only relevant for VP8.
 */
export function getUnencryptedBytes(codec: Codec | undefined, frameKind: FrameKind | undefined): number {
	switch (codec) {
		case 'vp8':
			return frameKind === 'key' ? 10 : 3;
		case 'h264':
			return 1;
		case 'opus':
			return 1;
		case 'vp9':
		case 'av1':
			return 0;
		default:
			// undefined / unknown — full encryption, preserving current behaviour.
			return 0;
	}
}
