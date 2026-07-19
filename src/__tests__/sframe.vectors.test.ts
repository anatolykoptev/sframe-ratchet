// RFC 9605 Appendix C Known-Answer-Test (KAT) vectors.
//
// The RFC publishes test vectors in Appendix C (not §10 as the issue title
// suggests — §10 is "References").  Appendix C has three subsections:
//   C.1  Header Encoding/Decoding
//   C.2  AEAD Encryption/Decryption Using AES-CTR and HMAC
//   C.3  SFrame Encryption/Decryption
//
// These tests exercise the REAL shipped code in:
//   - src/sframe-header.ts  (parseHeader / serializeHeader)
//   - src/sframe.ts         (sframeEncrypt / sframeDecrypt / sframeEncryptInto)
//
// IMPORTANT — key derivation divergence:
// Our implementation uses a ratchet-based key schedule
// (HKDF-Expand(chainKey, "sframe/v1/key" || peer_index_be16, Nk)) rather than
// the RFC 9605 §4.4.2 derivation
// (HKDF-Extract("", base_key) → HKDF-Expand(secret, "SFrame 1.0 Secret key …")).
// The RFC C.3 vectors provide the *derived* sframe_key and sframe_salt
// intermediate values, so we construct SFrameKey objects directly from those
// to test the low-level AEAD layer in isolation.
//
// Additionally, our implementation uses AAD = header only (spec §6.3) whereas
// the RFC uses AAD = header + metadata.  Therefore we cannot assert against
// the RFC C.3 ciphertext bytes directly.  Instead we:
//   1. Golden-test parseHeader against every RFC C.1 header encoding variant.
//   2. Golden-test nonce derivation by encrypting with our sframeEncrypt and
//      decrypting with crypto.subtle.decrypt using the RFC's nonce.
//   3. Round-trip verify sframeEncrypt → sframeDecrypt = original plaintext.
//
// See: https://www.rfc-editor.org/rfc/rfc9605.html Appendix C
// Issue: #13

import { describe, it, expect } from 'vitest';
import {
	parseHeader,
	serializeHeader,
	sframeEncrypt,
	sframeDecrypt,
	sframeEncryptInto,
} from '../sframe.ts';
import { splitKid } from '../ratchet-ids.ts';
import type { SFrameKey } from '../types.ts';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Decode a hex string (whitespace tolerated) into a fresh Uint8Array. */
function fromHex(hex: string): Uint8Array {
	const clean = hex.replace(/\s+/g, '');
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

/** Encode a Uint8Array as a lowercase hex string. */
function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/** Copy a Uint8Array into a fresh, exclusive ArrayBuffer. */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}

/**
 * Construct an SFrameKey directly from raw AES-GCM key bytes and a 12-byte
 * salt, bypassing the ratchet key-derivation path.  This lets us test the
 * low-level AEAD layer against RFC C.3 intermediate values.
 */
async function makeSFrameKey(
	kid: number,
	rawKey: Uint8Array,
	salt: Uint8Array,
): Promise<SFrameKey> {
	if (salt.length !== 12) {
		throw new Error(`salt must be 12 bytes, got ${salt.length}`);
	}
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		toArrayBuffer(rawKey),
		{ name: 'AES-GCM' },
		false,
		['encrypt', 'decrypt'],
	);
	const { epoch, peerIndex } = splitKid(kid);
	return { kid, epoch, peerIndex, cryptoKey, salt };
}

// ---------------------------------------------------------------------------
// RFC 9605 §C.1 Header Encoding/Decoding golden vectors
// ---------------------------------------------------------------------------
//
// Config byte layout: X(1) | K(3) | Y(1) | C(3)
//   X=0 → K field is inline KID (0..7);  X=1 → K field is KLEN (byte count − 1)
//   Y=0 → C field is inline CTR (0..7);  Y=1 → C field is CLEN (byte count − 1)
//
// The table below is a representative subset of the full RFC C.1 table,
// covering every encoding variant (inline/extended × KID/CTR × widths).

interface HeaderVector {
	kid: number;
	ctr: bigint;
	header: string; // hex
}

const RFC_C1_HEADER_VECTORS: HeaderVector[] = [
	// --- inline KID, inline CTR ---
	{ kid: 0x0000, ctr: 0x00n, header: '00' },
	{ kid: 0x0000, ctr: 0x01n, header: '01' },
	{ kid: 0x0001, ctr: 0x00n, header: '10' },
	{ kid: 0x0007, ctr: 0x00n, header: '70' },
	{ kid: 0x0000, ctr: 0x07n, header: '07' },
	{ kid: 0x0001, ctr: 0x01n, header: '11' },
	{ kid: 0x0007, ctr: 0x07n, header: '77' },

	// --- inline KID, extended CTR (1-byte) ---
	{ kid: 0x0000, ctr: 0xffn, header: '08ff' },
	{ kid: 0x0001, ctr: 0xffn, header: '18ff' },

	// --- inline KID, extended CTR (2-byte) ---
	{ kid: 0x0000, ctr: 0x0100n, header: '090100' }, // CTR=256
	{ kid: 0x0000, ctr: 0xffffn, header: '09ffff' },
	{ kid: 0x0001, ctr: 0x0100n, header: '190100' },

	// --- inline KID, extended CTR (3-byte) ---
	{ kid: 0x0000, ctr: 0x010000n, header: '0a010000' },
	{ kid: 0x0000, ctr: 0xffffffn, header: '0affffff' },

	// --- extended KID (1-byte), inline CTR ---
	{ kid: 0x00ff, ctr: 0x00n, header: '80ff' },
	{ kid: 0x00ff, ctr: 0x01n, header: '81ff' },

	// --- extended KID (2-byte), inline CTR ---
	{ kid: 0xffff, ctr: 0x00n, header: '90ffff' },
	{ kid: 0xffff, ctr: 0x01n, header: '91ffff' },

	// --- extended KID (1-byte), extended CTR (2-byte) ---
	{ kid: 0x00ff, ctr: 0x0100n, header: '89ff0100' }, // CTR=256

	// --- extended KID (2-byte), extended CTR (2-byte) ---
	{ kid: 0xffff, ctr: 0x0100n, header: '99ffff0100' }, // CTR=256
	{ kid: 0xffff, ctr: 0xffffn, header: '99ffffffff' },

	// --- extended KID (1-byte), extended CTR (8-byte) — max CTR width ---
	{ kid: 0x00ff, ctr: 0xffffffffffffffffn, header: '8fffffffffffffffffff' },

	// --- extended KID (3-byte), inline CTR ---
	{ kid: 0xffffff, ctr: 0x00n, header: 'a0ffffff' },

	// --- extended KID (4-byte), extended CTR (1-byte) ---
	{ kid: 0x01000000, ctr: 0xffn, header: 'b801000000ff' },

	// --- extended KID (4-byte), extended CTR (8-byte) — max KID + CTR widths ---
	{ kid: 0xffffffff, ctr: 0xffffffffffffffffn, header: 'bfffffffffffffffffffffffff' },
];

// ---------------------------------------------------------------------------
// RFC 9605 §C.3 SFrame Encryption/Decryption vectors (suites 4 & 5)
// ---------------------------------------------------------------------------
//
// cipher_suite 0x0004 = AES_128_GCM_SHA256_128  (our 'AES_128_GCM_SHA256')
// cipher_suite 0x0005 = AES_256_GCM_SHA512_128  (our 'AES_256_GCM_SHA512')
//
// The RFC provides derived sframe_key and sframe_salt for kid=0x0123,
// ctr=0x4567.  We use these to construct SFrameKey objects directly.

interface SFrameVector {
	cipherSuite: number;
	kid: number;
	ctr: bigint;
	baseKey: string;
	sframeKey: string;
	sframeSalt: string;
	metadata: string;
	nonce: string;
	aad: string;
	plaintext: string;
	ciphertext: string; // full SFrame ciphertext (header + ct + tag)
}

const RFC_C3_VECTORS: SFrameVector[] = [
	{
		cipherSuite: 0x0004,
		kid: 0x0123,
		ctr: 0x4567n,
		baseKey: '000102030405060708090a0b0c0d0e0f',
		sframeKey: 'd34f547f4ca4f9a7447006fe7fcbf768',
		sframeSalt: '75234edefe07819026751816',
		metadata: '4945544620534672616d65205747',
		nonce: '75234edefe07819026755d71',
		aad: '99012345674945544620534672616d65205747',
		plaintext: '64726166742d696574662d736672616d652d656e63',
		ciphertext:
			'9901234567b7412c2513a1b66dbb48841bbaf17f598751176ad847681a69c6d0b091c07018ce4adb34eb',
	},
	{
		cipherSuite: 0x0005,
		kid: 0x0123,
		ctr: 0x4567n,
		baseKey: '000102030405060708090a0b0c0d0e0f',
		sframeKey:
			'd3e27b0d4a5ae9e55df01a70e6d4d28d969b246e2936f4b7a5d9b494da6b9633',
		sframeSalt: '84991c167b8cd23c93708ec7',
		metadata: '4945544620534672616d65205747',
		nonce: '84991c167b8cd23c9370cba0',
		aad: '99012345674945544620534672616d65205747',
		plaintext: '64726166742d696574662d736672616d652d656e63',
		ciphertext:
			'990123456794f509d36e9beacb0e261d99c7d1e972f1fed787d4049f17ca21353c1cc24d56ceabced279',
	},
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RFC 9605 §C.1 — parseHeader golden vectors', () => {
	for (const v of RFC_C1_HEADER_VECTORS) {
		const label = `parseHeader(${v.header}) → kid=0x${v.kid.toString(16)}, ctr=${v.ctr}`;
		it(label, () => {
			const buf = fromHex(v.header);
			const parsed = parseHeader(buf);
			expect(parsed.kid).toBe(v.kid);
			expect(parsed.ctr).toBe(v.ctr);
			expect(parsed.bodyOffset).toBe(buf.length);
		});
	}
});

describe('RFC 9605 §C.1 — parseHeader rejects truncated headers', () => {
	it('throws on empty buffer', () => {
		expect(() => parseHeader(new Uint8Array(0))).toThrow();
	});

	it('throws on truncated extended KID', () => {
		// Config byte promises 2-byte KID but buffer ends after 1 byte.
		expect(() => parseHeader(fromHex('90ff'))).toThrow();
	});

	it('throws on truncated extended CTR', () => {
		// Config byte promises 2-byte CTR but buffer ends after 1 byte.
		expect(() => parseHeader(fromHex('99ffff01'))).toThrow();
	});
});

describe('serializeHeader → parseHeader round-trip', () => {
	// Our serializeHeader always uses extended KID (K=1) with a fixed 4-byte
	// big-endian KID per spec §6.1.  CTR uses minimal big-endian encoding.
	// This round-trip verifies our own format is self-consistent.
	const cases: Array<[number, bigint]> = [
		[0x00000000, 0x00n],
		[0x00000000, 0x01n],
		[0x00000000, 0x07n],
		[0x00000000, 0xffn],
		[0x00000000, 0x0100n], // CTR=256
		[0x00000000, 0xffffn],
		[0x00000000, 0x010000n],
		[0x00000000, 0xffffffffffffffffn],
		[0x00000001, 0x00n],
		[0x00000007, 0x00n],
		[0x00000007, 0x0100n],
		[0x00000123, 0x4567n],
		[0x0000ffff, 0x00n],
		[0x0000ffff, 0x0100n], // extended KID + CTR=256
		[0x0000ffff, 0xffffn],
		[0xffffffff, 0x00n],
		[0xffffffff, 0xffffffffffffffffn],
	];

	for (const [kid, ctr] of cases) {
		it(`serializeHeader(0x${kid.toString(16)}, ${ctr}) → parseHeader round-trips`, () => {
			const encoded = serializeHeader(kid, ctr);
			const parsed = parseHeader(encoded);
			expect(parsed.kid).toBe(kid);
			expect(parsed.ctr).toBe(ctr);
			expect(parsed.bodyOffset).toBe(encoded.length);
		});
	}
});

describe('RFC 9605 §C.3 — nonce derivation golden test', () => {
	// Verifies that our internal deriveIv(salt, ctr) produces the same nonce
	// as the RFC's xor(sframe_salt, encode_big_endian(CTR, 12)).
	//
	// Strategy: encrypt with our sframeEncrypt (which calls deriveIv internally),
	// then decrypt the ciphertext body with crypto.subtle.decrypt using the
	// RFC's published nonce.  If the nonce is wrong, AES-GCM auth will fail.
	// Our AAD is header-only (no metadata), so we use our own serialized header
	// as AAD — not the RFC's aad.

	for (const v of RFC_C3_VECTORS) {
		const suiteName = v.cipherSuite === 0x0004 ? 'AES_128_GCM_SHA256' : 'AES_256_GCM_SHA512';

		it(`${suiteName}: deriveIv matches RFC nonce ${v.nonce}`, async () => {
			const sframeKey = fromHex(v.sframeKey);
			const salt = fromHex(v.sframeSalt);
			const plaintext = fromHex(v.plaintext);

			const key = await makeSFrameKey(v.kid, sframeKey, salt);

			// Encrypt with our sframeEncrypt — produces [our_header][ct+tag].
			const sealed = await sframeEncrypt(plaintext, key, v.ctr);

			// Parse our header to find the ciphertext boundary.
			const hdr = parseHeader(sealed);
			const ourHeader = sealed.subarray(0, hdr.bodyOffset);
			const ctBody = sealed.subarray(hdr.bodyOffset);

			// Decrypt with the RFC's nonce and our AAD (header only).
			// If deriveIv produced a different nonce, this will throw.
			const rfcNonce = fromHex(v.nonce);
			const cryptoKey = await crypto.subtle.importKey(
				'raw',
				toArrayBuffer(sframeKey),
				{ name: 'AES-GCM' },
				false,
				['decrypt'],
			);

			const recovered = await crypto.subtle.decrypt(
				{
					name: 'AES-GCM',
					iv: toArrayBuffer(rfcNonce),
					additionalData: toArrayBuffer(ourHeader),
					tagLength: 128,
				},
				cryptoKey,
				toArrayBuffer(ctBody),
			);

			expect(toHex(new Uint8Array(recovered))).toBe(toHex(plaintext));
		});
	}
});

describe('RFC 9605 §C.3 — sframeEncrypt + sframeDecrypt round-trip', () => {
	// Round-trip verification using RFC C.3 derived key material.
	// Our key derivation differs from the RFC, so we construct SFrameKey
	// directly from the RFC's sframe_key and sframe_salt.

	for (const v of RFC_C3_VECTORS) {
		const suiteName = v.cipherSuite === 0x0004 ? 'AES_128_GCM_SHA256' : 'AES_256_GCM_SHA512';

		it(`${suiteName}: encrypt → decrypt = original plaintext (kid=0x${v.kid.toString(16)}, ctr=${v.ctr})`, async () => {
			const sframeKey = fromHex(v.sframeKey);
			const salt = fromHex(v.sframeSalt);
			const plaintext = fromHex(v.plaintext);

			const key = await makeSFrameKey(v.kid, sframeKey, salt);
			const sealed = await sframeEncrypt(plaintext, key, v.ctr);

			// Verify the header carries the correct KID and CTR.
			const hdr = parseHeader(sealed);
			expect(hdr.kid).toBe(v.kid);
			expect(hdr.ctr).toBe(v.ctr);

			const opened = await sframeDecrypt(sealed, ({ kid }) =>
				kid === v.kid ? key : null,
			);
			expect(toHex(opened)).toBe(toHex(plaintext));
		});
	}
});

describe('sframeEncrypt + sframeDecrypt round-trip — all header variants', () => {
	// Test matrix: both cipher suites × multiple KID/CTR combinations
	// covering inline CTR (0, 1, 2), extended KID, and CTR>255 edge case.

	const suiteKeys = [
		{ name: 'AES_128_GCM_SHA256', keyHex: 'd34f547f4ca4f9a7447006fe7fcbf768' },
		{ name: 'AES_256_GCM_SHA512', keyHex: 'd3e27b0d4a5ae9e55df01a70e6d4d28d969b246e2936f4b7a5d9b494da6b9633' },
	];
	const saltHex = '75234edefe07819026751816';
	const plaintext = fromHex('00010203'); // 4 bytes, per task spec

	const headerCases: Array<{ kid: number; ctr: bigint; label: string }> = [
		{ kid: 0x0007, ctr: 0x00n, label: 'CTR=0' },
		{ kid: 0x0007, ctr: 0x01n, label: 'CTR=1' },
		{ kid: 0x0007, ctr: 0x02n, label: 'CTR=2' },
		{ kid: 0xffff, ctr: 0x00n, label: 'extended KID=0xffff, CTR=0' },
		{ kid: 0xffff, ctr: 0x0100n, label: 'extended KID=0xffff, CTR=256 (CTR>255 edge case)' },
	];

	for (const suite of suiteKeys) {
		for (const hc of headerCases) {
			it(`${suite.name}: ${hc.label}`, async () => {
				const rawKey = fromHex(suite.keyHex);
				const salt = fromHex(saltHex);
				const key = await makeSFrameKey(hc.kid, rawKey, salt);

				const sealed = await sframeEncrypt(plaintext, key, hc.ctr);

				// Verify header carries correct KID and CTR.
				const hdr = parseHeader(sealed);
				expect(hdr.kid).toBe(hc.kid);
				expect(hdr.ctr).toBe(hc.ctr);

				// Decrypt and verify plaintext.
				const opened = await sframeDecrypt(sealed, ({ kid }) =>
					kid === hc.kid ? key : null,
				);
				expect(toHex(opened)).toBe(toHex(plaintext));
			});
		}
	}
});

describe('sframeEncryptInto — pre-serialized RFC header round-trip', () => {
	// sframeEncryptInto accepts a pre-serialized header, letting us test
	// with RFC C.1 header bytes directly.  This verifies the low-level
	// encrypt-into-buffer path with RFC-format headers (variable-length KID).

	const suiteKeys = [
		{ name: 'AES_128_GCM_SHA256', keyHex: 'd34f547f4ca4f9a7447006fe7fcbf768' },
		{ name: 'AES_256_GCM_SHA512', keyHex: 'd3e27b0d4a5ae9e55df01a70e6d4d28d969b246e2936f4b7a5d9b494da6b9633' },
	];
	const saltHex = '75234edefe07819026751816';
	const plaintext = fromHex('00010203');

	// RFC C.1 headers with known kid/ctr — we use these as pre-serialized
	// headers for sframeEncryptInto, then verify sframeDecrypt can parse
	// and decrypt the result.
	const rfcHeaders: Array<{ kid: number; ctr: bigint; header: string }> = [
		{ kid: 0x0000, ctr: 0x00n, header: '00' },
		{ kid: 0x0001, ctr: 0x01n, header: '11' },
		{ kid: 0x0000, ctr: 0xffn, header: '08ff' },
		{ kid: 0x0000, ctr: 0x0100n, header: '090100' }, // CTR=256
		{ kid: 0x00ff, ctr: 0x00n, header: '80ff' },
		{ kid: 0xffff, ctr: 0x00n, header: '90ffff' },
		{ kid: 0xffff, ctr: 0x0100n, header: '99ffff0100' }, // CTR=256
	];

	for (const suite of suiteKeys) {
		for (const rh of rfcHeaders) {
			it(`${suite.name}: RFC header ${rh.header} (kid=0x${rh.kid.toString(16)}, ctr=${rh.ctr})`, async () => {
				const rawKey = fromHex(suite.keyHex);
				const salt = fromHex(saltHex);
				const header = fromHex(rh.header);

				// Construct the SFrameKey with the RFC header's KID.
				const key = await makeSFrameKey(rh.kid, rawKey, salt);

				// sframeEncryptInto: [header][ct+tag] written into `out`.
				const out = new Uint8Array(header.length + plaintext.length + 16);
				const written = await sframeEncryptInto(
					out,
					0,
					header,
					plaintext,
					key,
					rh.ctr,
				);
				expect(written).toBe(header.length + plaintext.length + 16);

				// The output should start with the RFC header bytes.
				expect(toHex(out.subarray(0, header.length))).toBe(rh.header);

				// sframeDecrypt should parse the RFC-format header and decrypt.
				const opened = await sframeDecrypt(out, ({ kid }) =>
					kid === rh.kid ? key : null,
				);
				expect(toHex(opened)).toBe(toHex(plaintext));
			});
		}
	}
});

describe('CTR > 255 edge case — variable-width CTR encoding', () => {
	// RFC 9605 uses minimal big-endian CTR encoding: values 0..255 fit in
	// 1 byte (inline or 1-byte extended), 256..65535 need 2 bytes, etc.
	// This test verifies the full chain handles CTR=256 correctly.

	it('parseHeader on RFC header with CTR=256 (2-byte extended)', () => {
		// RFC C.1: kid=0, ctr=0x0100 → header 090100
		const parsed = parseHeader(fromHex('090100'));
		expect(parsed.kid).toBe(0);
		expect(parsed.ctr).toBe(256n);
		expect(parsed.bodyOffset).toBe(3);
	});

	it('parseHeader on RFC header with extended KID + CTR=256', () => {
		// RFC C.1: kid=0xffff, ctr=0x0100 → header 99ffff0100
		const parsed = parseHeader(fromHex('99ffff0100'));
		expect(parsed.kid).toBe(0xffff);
		expect(parsed.ctr).toBe(256n);
		expect(parsed.bodyOffset).toBe(5);
	});

	it('serializeHeader → parseHeader with CTR=256', () => {
		const encoded = serializeHeader(0x0123, 256n);
		const parsed = parseHeader(encoded);
		expect(parsed.kid).toBe(0x0123);
		expect(parsed.ctr).toBe(256n);
	});

	it('sframeEncrypt → sframeDecrypt with CTR=256 (AES-128-GCM)', async () => {
		const rawKey = fromHex('d34f547f4ca4f9a7447006fe7fcbf768');
		const salt = fromHex('75234edefe07819026751816');
		const key = await makeSFrameKey(0x0123, rawKey, salt);
		const plaintext = fromHex('00010203');

		const sealed = await sframeEncrypt(plaintext, key, 256n);
		const hdr = parseHeader(sealed);
		expect(hdr.ctr).toBe(256n);

		const opened = await sframeDecrypt(sealed, ({ kid }) =>
			kid === 0x0123 ? key : null,
		);
		expect(toHex(opened)).toBe(toHex(plaintext));
	});

	it('sframeEncrypt → sframeDecrypt with CTR=256 (AES-256-GCM)', async () => {
		const rawKey = fromHex(
			'd3e27b0d4a5ae9e55df01a70e6d4d28d969b246e2936f4b7a5d9b494da6b9633',
		);
		const salt = fromHex('84991c167b8cd23c93708ec7');
		const key = await makeSFrameKey(0x0123, rawKey, salt);
		const plaintext = fromHex('00010203');

		const sealed = await sframeEncrypt(plaintext, key, 256n);
		const hdr = parseHeader(sealed);
		expect(hdr.ctr).toBe(256n);

		const opened = await sframeDecrypt(sealed, ({ kid }) =>
			kid === 0x0123 ? key : null,
		);
		expect(toHex(opened)).toBe(toHex(plaintext));
	});

	it('CTR=255 vs CTR=256 produce different ciphertexts (nonce uniqueness)', async () => {
		const rawKey = fromHex('d34f547f4ca4f9a7447006fe7fcbf768');
		const salt = fromHex('75234edefe07819026751816');
		const key = await makeSFrameKey(0x0123, rawKey, salt);
		const plaintext = fromHex('00010203');

		const sealed255 = await sframeEncrypt(plaintext, key, 255n);
		const sealed256 = await sframeEncrypt(plaintext, key, 256n);

		// Different CTR → different nonce → different ciphertext.
		expect(toHex(sealed255)).not.toBe(toHex(sealed256));

		// Both should decrypt correctly.
		const opened255 = await sframeDecrypt(sealed255, ({ kid }) =>
			kid === 0x0123 ? key : null,
		);
		const opened256 = await sframeDecrypt(sealed256, ({ kid }) =>
			kid === 0x0123 ? key : null,
		);
		expect(toHex(opened255)).toBe(toHex(plaintext));
		expect(toHex(opened256)).toBe(toHex(plaintext));
	});
});

describe('RFC 9605 §C.3 — cross-key rejection (negative test)', () => {
	// A frame encrypted under one key must not decrypt under a different key.
	// This is a basic AEAD authentication property.

	it('suite 4 frame rejected by suite 5 key', async () => {
		const key4 = fromHex('d34f547f4ca4f9a7447006fe7fcbf768');
		const key5 = fromHex(
			'd3e27b0d4a5ae9e55df01a70e6d4d28d969b246e2936f4b7a5d9b494da6b9633',
		);
		const salt = fromHex('75234edefe07819026751816');
		const plaintext = fromHex('00010203');

		const encKey = await makeSFrameKey(0x0123, key4, salt);
		const sealed = await sframeEncrypt(plaintext, encKey, 42n);

		const wrongKey = await makeSFrameKey(0x0123, key5, salt);
		await expect(
			sframeDecrypt(sealed, ({ kid }) => (kid === 0x0123 ? wrongKey : null)),
		).rejects.toBeDefined();
	});

	it('frame rejected by key with wrong KID (key not found)', async () => {
		const rawKey = fromHex('d34f547f4ca4f9a7447006fe7fcbf768');
		const salt = fromHex('75234edefe07819026751816');
		const plaintext = fromHex('00010203');

		const key = await makeSFrameKey(0x0123, rawKey, salt);
		const sealed = await sframeEncrypt(plaintext, key, 0n);

		// Resolver returns null for any KID → KeyNotFoundError.
		await expect(
			sframeDecrypt(sealed, () => null),
		).rejects.toBeDefined();
	});
});

describe('RFC 9605 §C.3 — raw AES-GCM golden cross-check (vector transcription validation)', () => {
	// This test bypasses our sframeEncrypt/sframeDecrypt and calls
	// crypto.subtle.encrypt directly with the RFC's published key, nonce,
	// AAD (header + metadata), and plaintext.  It verifies that our
	// transcribed RFC C.3 test vectors are byte-accurate by reproducing
	// the RFC's exact ciphertext.  This is NOT a test of our shipped code
	// (the tests above cover that) — it is a KAT data integrity check.

	for (const v of RFC_C3_VECTORS) {
		const suiteName = v.cipherSuite === 0x0004 ? 'AES_128_GCM_SHA256' : 'AES_256_GCM_SHA512';

		it(`${suiteName}: raw AES-GCM(RFC key, RFC nonce, RFC aad, RFC pt) = RFC ct body`, async () => {
			const key = await crypto.subtle.importKey(
				'raw',
				toArrayBuffer(fromHex(v.sframeKey)),
				{ name: 'AES-GCM' },
				false,
				['encrypt'],
			);
			const ct = new Uint8Array(
				await crypto.subtle.encrypt(
					{
						name: 'AES-GCM',
						iv: toArrayBuffer(fromHex(v.nonce)),
						additionalData: toArrayBuffer(fromHex(v.aad)),
						tagLength: 128,
					},
					key,
					toArrayBuffer(fromHex(v.plaintext)),
				),
			);

			// RFC ct = header + ciphertext + tag.  Strip the header to compare bodies.
			const rfcCtFull = fromHex(v.ciphertext);
			const rfcHeader = fromHex('9901234567'); // RFC header for kid=0x0123, ctr=0x4567
			const rfcCtBody = rfcCtFull.subarray(rfcHeader.length);

			expect(toHex(ct)).toBe(toHex(rfcCtBody));
		});
	}
});
