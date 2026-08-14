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
// PHASE 1 SECURITY NOTE: the unencrypted prefix bytes are NOT included in
// AES-GCM additional-authenticated-data in phase 1. The sender emits the
// original format (AAD = header only). An attacker who can modify wire bytes
// can corrupt the codec header without detection by the AEAD layer. This is
// the documented trade-off for SFU compatibility (issue #50), inherited from
// the pre-fix behaviour. Phase 2 will switch the sender to the canonical AAD
// form (be16(prefix.length) || prefix || header), making the prefix
// tamper-evident. Phase 1 receivers already ACCEPT the canonical form so the
// phase 2 switch does not break interop. See docs/SECURITY.md for the full
// staged-rollout plan.

import type { Codec, FrameKind } from './worker-types.ts';

/**
 * Returns the number of plaintext bytes at the front of an encoded frame
 * that must remain unencrypted.  N=0 means full encryption (default path).
 *
 * The exposed prefix is the MINIMUM byte count that lets a depacketizer
 * identify a keyframe — no more, no less. One byte short is a silent no-op
 * (the SFU cannot see the keyframe); one byte long is a gratuitous
 * plaintext leak.
 *
 * Per-codec justification:
 *
 * - VP8 (RFC 6386 §9.1): The first 3 bytes are the frame tag
 *   `frame_tag = key_frame(1b) | version(3b) | show_frame(1b) | first_part_size(19b)`.
 *   Byte 0 bit 7 is the keyframe indicator. For keyframes, bytes 3-9 carry
 *   the start code (0x9d 0x01 0x2a) and width/height — leaving these in the
 *   clear lets the SFU extract resolution for SVC routing and lets decoders
 *   fail gracefully on key mismatch (garbage instead of fatal parse error).
 *   N=10 (key) / 3 (inter).
 *
 * - H.264 (RFC 7798): Byte 0 is the FUA/NALU header. The NAL type (bits 4-0
 *   for single-NAL, or the inner byte for FUA) identifies an IDR slice
 *   (type 5 = keyframe). N=1.
 *
 * - VP9 (draft-ietf-payload-vp9-16 / VP9 bitstream spec §9.1): Byte 0 is the
 *   uncompressed frame header start:
 *     `frame_marker(2b) | profile_low(1b) | profile_high(1b) | show_existing(1b) | frame_type(1b) | ...`
 *   - frame_marker must be 0b10 (bits 7-6, MSB-first)
 *   - frame_type: 0 = KEY_FRAME, 1 = NON_KEY_FRAME. The bit position depends
 *     on profile: bit 2 for profile 0 (profile_low=0, profile_high=0,
 *     show_existing=0), bit 1 for profile 2/3 (profile_low=0, profile_high=1).
 *     Profile 1 (profile_low=1) uses bit 2 as well because the profile_high
 *     bit is 0.
 *   - show_existing_frame = 1 references a previously decoded frame, not a
 *     real keyframe
 *   An observer of byte 0 learns: the frame marker (confirms VP9), the
 *   profile, whether it's a show_existing_frame, and the frame type
 *   (keyframe vs inter).
 *
 *   PHASE 1: N=0 (full encryption). The SFU cannot see VP9 keyframes in
 *   phase 1 — this is the pre-fix behaviour. Phase 2 will set N=1 so byte 0
 *   (frame marker + frame type) is visible to the SFU.
 *
 * - AV1 (AV1 RTP spec v1.0.0 / AV1 spec §6.2): Byte 0 is the first OBU
 *   (Open Bitstream Unit) header:
 *     `obu_forbidden(1b) | obu_type(4b) | obu_extension_flag(1b) | obu_has_size(1b) | obu_reserved(1b)`
 *   A keyframe (new coded video sequence) starts with a SequenceHeader OBU
 *   (obu_type = 1). The RTP aggregation header's N bit is set when the
 *   first OBU is a SequenceHeader. An observer of byte 0 learns: the OBU
 *   type (SequenceHeader = keyframe vs Frame/FrameHeader = inter), whether
 *   there's an extension byte, and whether there's a size field.
 *
 *   PHASE 1: N=0 (full encryption). The SFU cannot see AV1 keyframes in
 *   phase 1 — this is the pre-fix behaviour. Phase 2 will set N=1 so byte 0
 *   (OBU header with obu_type) is visible to the SFU.
 *
 * - Opus (RFC 6716 §3.1): Byte 0 is the TOC (Table of Contents) byte
 *   `config(5b) | s(1b) | c(2b)`. Leaving it unencrypted lets the SFU
 *   route by Opus mode. N=1.
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
			// PHASE 1: N=0 (full encryption). Phase 2 will set N=1 so byte 0
			// (frame_marker + frame_type) is visible to the SFU.
			return 0;
		case 'av1':
			// PHASE 1: N=0 (full encryption). Phase 2 will set N=1 so byte 0
			// (OBU header with obu_type = SequenceHeader for keyframes) is
			// visible to the SFU.
			return 0;
		default:
			// undefined / unknown — full encryption, preserving current behaviour.
			return 0;
	}
}
