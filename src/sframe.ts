// SFrame AEAD layer per RFC 9605 §4.4.
// The header codec lives in sframe-header.ts; this module handles IV derivation
// and the WebCrypto AES-GCM pipeline. Codec-agnostic: callers supply plaintext
// frame bytes and SFrameKey; the key material is produced by ratchet.ts.
//
// See docs/superpowers/specs/2026-04-21-sframe-protocol.md §2 (cipher suite)
// and §6.3 (AAD = header bytes).
//
// AAD construction — three forms are supported for a staged rollout:
//
//   'header'     — AAD = header.                         (original / phase-1 sender)
//   'prefix'     — AAD = prefix || header.               (intermediate b6ded9d)
//   'canonical'  — AAD = be16(prefix.length) || prefix || header.  (phase-2 target)
//
// The unprefixed `prefix || header` form ('prefix') is ambiguous: two different
// (prefix, header) pairs can produce identical AAD bytes (e.g. prefix=[0x01]
// header=[0x02,0x03] vs prefix=[0x01,0x02] header=[0x03]). Not exploitable
// today, but the 'canonical' form resolves this with a big-endian 16-bit
// length prefix — the parser knows exactly where the prefix ends and the header
// begins, regardless of content. Phase 1 receivers accept all three forms;
// phase 1 senders emit 'header' (the original format). Phase 2 will switch
// senders to 'canonical'.

import type { SFrameKey, SFrameKeyResolver } from './types.ts';
import { parseHeader, serializeHeader } from './sframe-header.ts';
import { FIXED_KID_CODEC, type KidCodec } from './kid-format.ts';
import { toArrayBuffer as asArrayBuffer, bufferSourceOf } from './internal/buffer.js';
import { AEADAuthError, KeyNotFoundError } from './errors.ts';

// Re-export for consumers who want the header API via this module.
export { parseHeader, serializeHeader } from './sframe-header.ts';
export type { SFrameHeader } from './sframe-header.ts';

const AEAD_TAG_BYTES = 16;
const IV_BYTES = 12;

/**
 * AAD construction form. See the file-level comment for the rationale and the
 * staged-rollout plan.
 *
 * - `'header'`    — AAD = header (original format; phase-1 sender).
 * - `'prefix'`    — AAD = prefix || header (intermediate b6ded9d form).
 * - `'canonical'` — AAD = be16(prefix.length) || prefix || header (phase-2 target).
 */
export type AadForm = 'header' | 'prefix' | 'canonical';

/**
 * Build the AES-GCM additional-authenticated-data from the optional codec
 * prefix and the SFrame header, according to the specified `form`.
 *
 * When `aadPrefix` is absent or empty, all forms reduce to just `header`
 * (there is no prefix to authenticate), except `'canonical'` which still
 * prepends `be16(0)` so the encoding is self-describing even with an empty
 * prefix.
 */
export function buildAad(
	aadPrefix: Uint8Array | undefined,
	header: Uint8Array,
	form: AadForm = 'prefix',
): Uint8Array {
	const plen = aadPrefix ? aadPrefix.byteLength : 0;
	switch (form) {
		case 'header':
			return header;
		case 'prefix':
			if (plen === 0) return header;
			const aad = new Uint8Array(plen + header.byteLength);
			aad.set(aadPrefix!, 0);
			aad.set(header, plen);
			return aad;
		case 'canonical': {
			const aad = new Uint8Array(2 + plen + header.byteLength);
			aad[0] = (plen >> 8) & 0xff;
			aad[1] = plen & 0xff;
			if (plen > 0) aad.set(aadPrefix!, 2);
			aad.set(header, 2 + plen);
			return aad;
		}
	}
}

/**
 * Encrypt `plaintext` under `key` at counter `ctr`.
 * Output layout: `[header][AES-GCM ciphertext + 16B tag]`.
 * AAD is the serialised header (RFC 9605 §4.4.2; spec §6.3), optionally
 * prepended with `aadPrefix` (the unencrypted codec prefix) for tamper-evidence.
 * `aadForm` controls the AAD construction (default `'prefix'`).
 */
export async function sframeEncrypt(
	plaintext: Uint8Array,
	key: SFrameKey,
	ctr: bigint,
	aadPrefix?: Uint8Array,
	aadForm: AadForm = 'prefix',
): Promise<Uint8Array> {
	const header = serializeHeader(key.kid, ctr);
	const iv = deriveIv(key.salt, ctr);
	const aad = buildAad(aadPrefix, header, aadForm);
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				// iv and aad are freshly allocated — skip copy via bufferSourceOf.
				// plaintext is caller-supplied and may be a subarray; use the safe copy.
				iv: bufferSourceOf(iv),
				additionalData: bufferSourceOf(aad),
				tagLength: AEAD_TAG_BYTES * 8,
			},
			key.cryptoKey,
			asArrayBuffer(plaintext),
		),
	);
	const out = new Uint8Array(header.length + ct.length);
	out.set(header, 0);
	out.set(ct, header.length);
	return out;
}

/**
 * Decrypt a full SFrame buffer.
 *
 * `resolveKey` is a context-aware callback: it receives `{ kid, epoch,
 * peerIndex, ctr }` so the caller can enforce the stale-epoch gate (spec §7.4)
 * BEFORE any decrypt attempt. Return `null` to reject the frame with
 * "key not found" (caller may log + drop); throwing inside the resolver also
 * rejects the frame and propagates its message. `meta.ctr_hint` is accepted
 * for API parity with out-of-band CTR recovery schemes but unused in v1.
 */
export async function sframeDecrypt(
	sframe: Uint8Array,
	resolveKey: SFrameKeyResolver,
	_meta: { ctr_hint?: bigint; kidCodec?: KidCodec; aadPrefix?: Uint8Array; aadForm?: AadForm } = {},
): Promise<Uint8Array> {
	const kidCodec = _meta.kidCodec ?? FIXED_KID_CODEC;
	const aadForm = _meta.aadForm ?? 'prefix';
	const hdr = parseHeader(sframe);
	if (sframe.length < hdr.bodyOffset + AEAD_TAG_BYTES) {
		throw new AEADAuthError('sframe: frame too short for tag', { kid: hdr.kid, ctr: hdr.ctr });
	}
	const { epoch, peerIndex } = kidCodec.decode(hdr.kid);
	const key = resolveKey({ kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr });
	if (!key) {
		throw new KeyNotFoundError(`sframe: key not found for kid=${hdr.kid}`, { kid: hdr.kid, epoch, peerIndex });
	}

	const header = sframe.subarray(0, hdr.bodyOffset);
	const body = sframe.subarray(hdr.bodyOffset);
	const iv = deriveIv(key.salt, hdr.ctr);
	const aad = buildAad(_meta.aadPrefix, header, aadForm);

	try {
		const pt = await crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				// iv is freshly allocated — skip copy. aad is freshly allocated by
				// buildAad (or is the header subarray when no prefix) so
				// bufferSourceOf handles both; body is also caller-supplied, always copy.
				iv: bufferSourceOf(iv),
				additionalData: bufferSourceOf(aad),
				tagLength: AEAD_TAG_BYTES * 8,
			},
			key.cryptoKey,
			asArrayBuffer(body),
		);
		return new Uint8Array(pt);
	} catch {
		throw new AEADAuthError(
			`sframe: AEAD auth failed for kid=${hdr.kid} ctr=${hdr.ctr}`,
			{ kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr },
		);
	}
}

/**
 * Encrypt `body` directly into a pre-allocated output buffer.
 *
 * This is the hot-path variant of `sframeEncrypt` for `encodeFrame`.
 * The caller pre-serialises the header (via `serializeHeader`), sizes
 * the wire buffer, and passes it in with an offset.  This avoids the
 * extra `new Uint8Array` allocation that `sframeEncrypt` produces for
 * the `[header][ciphertext]` concatenation.
 *
 * Wire layout written starting at `out[offset]`:
 *   [header.length bytes] [AES-GCM ciphertext + 16B tag]
 *
 * Returns the number of bytes written (header.length + body.length + 16).
 *
 * Invariants (not checked — caller guarantees):
 *  - `out` is a freshly allocated exclusive ArrayBuffer view (not a subarray).
 *  - `out.byteLength >= offset + header.length + body.length + AEAD_TAG_BYTES`.
 *  - `header` is the result of `serializeHeader(key.kid, ctr)`.
 *
 * Internal API — not exported from the public barrel.
 */
export async function sframeEncryptInto(
	out: Uint8Array,
	offset: number,
	header: Uint8Array,
	body: Uint8Array,
	key: SFrameKey,
	ctr: bigint,
	aadPrefix?: Uint8Array,
	aadForm: AadForm = 'prefix',
): Promise<number> {
	const iv = deriveIv(key.salt, ctr);
	const aad = buildAad(aadPrefix, header, aadForm);
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv: bufferSourceOf(iv),
				additionalData: bufferSourceOf(aad),
				tagLength: AEAD_TAG_BYTES * 8,
			},
			key.cryptoKey,
			asArrayBuffer(body),
		),
	);
	out.set(header, offset);
	out.set(ct, offset + header.length);
	return header.length + ct.length;
}

/**
 * RFC 9605 §4.4.4 nonce derivation:
 *   IV = salt XOR left-padded-big-endian(CTR, 12 bytes)
 * Salt MUST be 12 bytes.
 */
function deriveIv(salt: Uint8Array, ctr: bigint): Uint8Array {
	if (salt.length !== IV_BYTES) {
		throw new Error(`sframe: salt must be ${IV_BYTES} bytes, got ${salt.length}`);
	}
	const iv = new Uint8Array(IV_BYTES);
	let v = ctr;
	for (let i = IV_BYTES - 1; i >= 0 && v > 0n; i--) {
		iv[i] = Number(v & 0xffn);
		v >>= 8n;
	}
	for (let i = 0; i < IV_BYTES; i++) iv[i] ^= salt[i];
	return iv;
}

