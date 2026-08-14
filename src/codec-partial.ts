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
// SECURITY NOTE: the unencrypted prefix bytes ARE included in AES-GCM
// additional-authenticated-data (AAD), alongside the SFrame header. An
// attacker who modifies the prefix bytes will cause an AEAD authentication
// failure — the frame is rejected, not silently corrupted. This closes the
// previously-documented trade-off (issue #50 / oxpulse-partner-edge#618)
// where the prefix was unauthenticated and an on-path attacker could rewrite
// codec metadata undetected. The fix applies to ALL codecs: VP8, H.264,
// VP9, AV1, and Opus.
//
// The prefix is still UNENCRYPTED (visible to the SFU) but now AUTHENTICATED
// (tamper-evident). This is the same property the SFrame header already has:
// visible but integrity-protected.

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
 * Per-codec justification (derived from the spec AND from str0m's
 * depacketizer/packetizer source, not from memory):
 *
 * - VP8 (RFC 6386 §9.1): The first 3 bytes are the frame tag
 *   `frame_tag = key_frame(1b) | version(3b) | show_frame(1b) | first_part_size(19b)`.
 *   Byte 0 bit 7 is the keyframe indicator. For keyframes, bytes 3-9 carry
 *   the start code (0x9d 0x01 0x2a) and width/height — leaving these in the
 *   clear lets the SFU extract resolution for SVC routing and lets decoders
 *   fail gracefully on key mismatch (garbage instead of fatal parse error).
 *   N=10 (key) / 3 (inter). str0m's `detect_vp8_keyframe` reads byte 0.
 *
 * - H.264 (RFC 7798): Byte 0 is the FUA/NALU header. The NAL type (bits 4-0
 *   for single-NAL, or the inner byte for FUA) identifies an IDR slice
 *   (type 5 = keyframe). N=1. str0m's `detect_h264_keyframe` reads byte 0.
 *
 * - VP9 (draft-ietf-payload-vp9-16 / VP9 bitstream spec §9.1): Byte 0 is the
 *   uncompressed frame header start:
 *     `frame_marker(2b) | profile_low(1b) | profile_high(1b) | show_existing(1b) | frame_type(1b) | ...`
 *   - frame_marker must be 0b10 (bits 7-6)
 *   - frame_type: 0 = KEY_FRAME, 1 = NON_KEY_FRAME (bit 2 for profile 0/1,
 *     bit 1 for profile 2/3)
 *   - show_existing_frame = 1 references a previously decoded frame, not a
 *     real keyframe
 *   An observer of byte 0 learns: the frame marker (confirms VP9), the
 *   profile, whether it's a show_existing_frame, and the frame type
 *   (keyframe vs inter). str0m's `detect_vp9_keyframe_bitstream` reads
 *   ONLY byte 0 — confirmed at str0m/src/packet/vp9.rs:133-157.
 *   N=1.
 *
 * - AV1 (AV1 RTP spec v1.0.0 / AV1 spec §6.2): Byte 0 is the first OBU
 *   (Open Bitstream Unit) header:
 *     `obu_forbidden(1b) | obu_type(4b) | obu_extension_flag(1b) | obu_has_size(1b) | obu_reserved(1b)`
 *   A keyframe (new coded video sequence) starts with a SequenceHeader OBU
 *   (obu_type = 1). The RTP aggregation header's N bit is set when the
 *   first OBU is a SequenceHeader. An observer of byte 0 learns: the OBU
 *   type (SequenceHeader = keyframe vs Frame/FrameHeader = inter), whether
 *   there's an extension byte, and whether there's a size field.
 *   str0m's AV1 packetizer `parse_obus` reads byte 0 to extract the OBU
 *   type (str0m/src/packet/av1.rs:603), and `aggregation_header` sets the
 *   N bit based on `obus[0].obu_type() == SequenceHeader` (av1.rs:235).
 *   str0m's `detect_av1_keyframe` reads the N bit from the RTP aggregation
 *   header (av1.rs:21-24), which is set from byte 0 of the raw frame.
 *   N=1.
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
			// Byte 0: frame_marker(2b) | profile(2b) | show_existing(1b) | frame_type(1b) | ...
			// str0m detect_vp9_keyframe_bitstream reads ONLY byte 0.
			return 1;
		case 'av1':
			// Byte 0: OBU header — obu_type(4b) identifies SequenceHeader (keyframe).
			// str0m parse_obus reads byte 0 for OBU type; aggregation_header sets N bit from it.
			return 1;
		default:
			// undefined / unknown — full encryption, preserving current behaviour.
			return 0;
	}
}
