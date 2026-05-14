// SFrame AEAD layer per RFC 9605 §4.4.
// The header codec lives in sframe-header.ts; this module handles IV derivation
// and the WebCrypto AES-GCM pipeline. Codec-agnostic: callers supply plaintext
// frame bytes and SFrameKey; the key material is produced by ratchet.ts.
//
// See docs/superpowers/specs/2026-04-21-sframe-protocol.md §2 (cipher suite)
// and §6.3 (AAD = header bytes).

import type { SFrameKey, SFrameKeyResolver } from './types.ts';
import { parseHeader, serializeHeader } from './sframe-header.ts';
import { splitKid } from './ratchet-ids.ts';
import { toArrayBuffer as asArrayBuffer } from './internal/buffer.js';
import { AEADAuthError, KeyNotFoundError } from './errors.ts';

// Re-export for consumers who want the header API via this module.
export { parseHeader, serializeHeader } from './sframe-header.ts';
export type { SFrameHeader } from './sframe-header.ts';

const AEAD_TAG_BYTES = 16;
const IV_BYTES = 12;

/**
 * Encrypt `plaintext` under `key` at counter `ctr`.
 * Output layout: `[header][AES-GCM ciphertext + 16B tag]`.
 * AAD is exactly the serialised header (RFC 9605 §4.4.2; spec §6.3).
 */
export async function sframeEncrypt(
	plaintext: Uint8Array,
	key: SFrameKey,
	ctr: bigint,
): Promise<Uint8Array> {
	const header = serializeHeader(key.kid, ctr);
	const iv = deriveIv(key.salt, ctr);
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv: asArrayBuffer(iv),
				additionalData: asArrayBuffer(header),
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
	_meta: { ctr_hint?: bigint } = {},
): Promise<Uint8Array> {
	const hdr = parseHeader(sframe);
	if (sframe.length < hdr.bodyOffset + AEAD_TAG_BYTES) {
		throw new AEADAuthError('sframe: frame too short for tag', { kid: hdr.kid, ctr: hdr.ctr });
	}
	const { epoch, peerIndex } = splitKid(hdr.kid);
	const key = resolveKey({ kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr });
	if (!key) {
		throw new KeyNotFoundError(`sframe: key not found for kid=${hdr.kid}`, { kid: hdr.kid, epoch, peerIndex });
	}

	const header = sframe.subarray(0, hdr.bodyOffset);
	const body = sframe.subarray(hdr.bodyOffset);
	const iv = deriveIv(key.salt, hdr.ctr);

	try {
		const pt = await crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv: asArrayBuffer(iv),
				additionalData: asArrayBuffer(header),
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

