/**
 * Cipher suite tests (RFC 9605 §4.5)
 *
 * Covers:
 *  1. Suite 5 (AES_256_GCM_SHA512) round-trip via sframeEncrypt / sframeDecrypt.
 *  2. Suite 5 with SimpleKex: password → chainKey → senderKey → encrypt/decrypt.
 *  3. Suite isolation: encrypt with suite 4, decrypt attempt with suite 5 → fail.
 *     Encrypt with suite 5, decrypt attempt with suite 4 → fail.
 *  4. Suite 5 deterministic regression vector (fixed seed → fixed ciphertext body).
 *  5. Suite 4 with deriveSenderKeys sanity: 16-byte AEAD key, SHA-256 HKDF.
 *  6. Suite 5 with deriveSenderKeys sanity: 32-byte AEAD key, SHA-512 HKDF.
 *
 * ── Suite 5 regression vector ───────────────────────────────────────────────
 *
 * Derived from fixed inputs using the library's own key schedule. Locked here
 * so any unintended change to HKDF parameters, key sizes, or IV construction
 * is caught immediately.
 *
 * Seed inputs:
 *   chainKey = 0x00 * 64  (zero-filled 64-byte ChainKey for suite 5)
 *   peerIndex = 0
 *   epoch     = 0
 *   plaintext = "suite5-regression-test"
 *   CTR       = 0n
 *
 * Expected ciphertext body (hex) is captured by running the test once and
 * pinning the output.  The value appears in the test below as LOCKED_CT_HEX.
 * Do NOT regenerate unless the cipher suite parameters are intentionally changed.
 */

import { describe, expect, it } from 'vitest';
import { SimpleKex } from '../kex-simple.ts';
import {
	deriveSenderKeys,
	suiteParams,
	type CipherSuite,
} from '../ratchet-crypto.ts';
import { sframeDecrypt, sframeEncrypt } from '../sframe.ts';
import { parseHeader } from '../sframe-header.ts';

// ── helpers ──────────────────────────────────────────────────────────────────

function hex(b: Uint8Array): string {
	return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

const FAST_ITER = 1_000;

// ── 1. Suite parameters sanity ───────────────────────────────────────────────

describe('suiteParams', () => {
	it('suite 4 → AES-128 + SHA-256 + 32-byte chainKey + 16-byte aeadKey', () => {
		const p = suiteParams('AES_128_GCM_SHA256');
		expect(p.hash).toBe('SHA-256');
		expect(p.aeadKeyBytes).toBe(16);
		expect(p.chainKeyBytes).toBe(32);
	});

	it('suite 5 → AES-256 + SHA-512 + 64-byte chainKey + 32-byte aeadKey', () => {
		const p = suiteParams('AES_256_GCM_SHA512');
		expect(p.hash).toBe('SHA-512');
		expect(p.aeadKeyBytes).toBe(32);
		expect(p.chainKeyBytes).toBe(64);
	});
});

// ── 2. deriveSenderKeys — key sizes ──────────────────────────────────────────

describe('deriveSenderKeys — AEAD key size per suite', () => {
	it('suite 4: rawKey is 16 bytes (AES-128)', async () => {
		const ck = new Uint8Array(32).fill(0x42);
		const k = await deriveSenderKeys(ck, 0, 0, 'AES_128_GCM_SHA256');
		expect(k.rawKey.byteLength).toBe(16);
		expect(k.salt.byteLength).toBe(12);
	});

	it('suite 5: rawKey is 32 bytes (AES-256)', async () => {
		const ck = new Uint8Array(64).fill(0x42);
		const k = await deriveSenderKeys(ck, 0, 0, 'AES_256_GCM_SHA512');
		expect(k.rawKey.byteLength).toBe(32);
		expect(k.salt.byteLength).toBe(12);
	});

	it('suite 4: wrong chainKey length → throws', async () => {
		const badCk = new Uint8Array(64).fill(0x01); // 64 bytes for suite 4 = wrong
		await expect(deriveSenderKeys(badCk, 0, 0, 'AES_128_GCM_SHA256')).rejects.toThrow();
	});

	it('suite 5: wrong chainKey length → throws', async () => {
		const badCk = new Uint8Array(32).fill(0x01); // 32 bytes for suite 5 = wrong
		await expect(deriveSenderKeys(badCk, 0, 0, 'AES_256_GCM_SHA512')).rejects.toThrow();
	});
});

// ── 3. Suite 5 round-trip ─────────────────────────────────────────────────────

describe('suite 5 — sframeEncrypt / sframeDecrypt round-trip', () => {
	it('encrypts and decrypts with AES-256 key derived from 64-byte chainKey', async () => {
		const chainKey = new Uint8Array(64).fill(0xaa);
		const senderKey = await deriveSenderKeys(chainKey, 1, 2, 'AES_256_GCM_SHA512');

		const plaintext = new TextEncoder().encode('hello suite 5');
		const sealed = await sframeEncrypt(plaintext, senderKey, 0n);
		const hdr = parseHeader(sealed);
		expect(hdr.kid).toBe(senderKey.kid);

		const recovered = await sframeDecrypt(
			sealed,
			({ kid }) => kid === senderKey.kid ? senderKey : null,
		);
		expect(new TextDecoder().decode(recovered)).toBe('hello suite 5');
	});

	it('multiple CTR values all decrypt correctly', async () => {
		const chainKey = new Uint8Array(64).fill(0xbb);
		const senderKey = await deriveSenderKeys(chainKey, 0, 0, 'AES_256_GCM_SHA512');
		const plaintext = new TextEncoder().encode('counter test');

		for (const ctr of [0n, 1n, 255n, 256n, 65535n]) {
			const sealed = await sframeEncrypt(plaintext, senderKey, ctr);
			const recovered = await sframeDecrypt(
				sealed,
				({ kid }) => kid === senderKey.kid ? senderKey : null,
			);
			expect(new TextDecoder().decode(recovered)).toBe('counter test');
		}
	});

	it('tampered ciphertext is rejected (AES-GCM auth)', async () => {
		const chainKey = new Uint8Array(64).fill(0xcc);
		const senderKey = await deriveSenderKeys(chainKey, 0, 0, 'AES_256_GCM_SHA512');
		const sealed = await sframeEncrypt(new TextEncoder().encode('tamper test'), senderKey, 0n);
		const tampered = new Uint8Array(sealed);
		const hdr = parseHeader(tampered);
		tampered[hdr.bodyOffset] ^= 0xff;
		await expect(
			sframeDecrypt(tampered, ({ kid }) => kid === senderKey.kid ? senderKey : null),
		).rejects.toThrow();
	});
});

// ── 4. Suite isolation ────────────────────────────────────────────────────────

describe('suite isolation — suite 4 and 5 keys are incompatible', () => {
	async function makePair(suite: CipherSuite, seed: number): Promise<{
		sealed: Uint8Array;
		key: Awaited<ReturnType<typeof deriveSenderKeys>>;
	}> {
		const keyBytes = suiteParams(suite).chainKeyBytes;
		const chainKey = new Uint8Array(keyBytes).fill(seed);
		const key = await deriveSenderKeys(chainKey, 0, 0, suite);
		const sealed = await sframeEncrypt(new TextEncoder().encode('isolation test'), key, 0n);
		return { sealed, key };
	}

	it('encrypt suite 4, attempt decrypt with suite 5 key → fail', async () => {
		const { sealed, key: key4 } = await makePair('AES_128_GCM_SHA256', 0x11);
		// Derive a suite 5 key from a DIFFERENT chain-key and try to use it to decrypt.
		const ck5 = new Uint8Array(64).fill(0x11);
		const key5 = await deriveSenderKeys(ck5, 0, 0, 'AES_256_GCM_SHA512');
		// key5 has the same KID as key4 (same epoch=0, peerIndex=0)
		expect(key5.kid).toBe(key4.kid);
		await expect(
			sframeDecrypt(sealed, ({ kid }) => kid === key5.kid ? key5 : null),
		).rejects.toThrow();
	});

	it('encrypt suite 5, attempt decrypt with suite 4 key → fail', async () => {
		const { sealed, key: key5 } = await makePair('AES_256_GCM_SHA512', 0x22);
		const ck4 = new Uint8Array(32).fill(0x22);
		const key4 = await deriveSenderKeys(ck4, 0, 0, 'AES_128_GCM_SHA256');
		expect(key4.kid).toBe(key5.kid);
		await expect(
			sframeDecrypt(sealed, ({ kid }) => kid === key4.kid ? key4 : null),
		).rejects.toThrow();
	});
});

// ── 5. Suite 5 with SimpleKex ─────────────────────────────────────────────────

describe('suite 5 — SimpleKex integration', () => {
	it('initialEpoch produces 64-byte chainKey for suite 5', async () => {
		const kex = new SimpleKex({
			sharedSecret: 'test-suite5',
			iterations: FAST_ITER,
			suite: 'AES_256_GCM_SHA512',
		});
		const ck = await kex.initialEpoch();
		expect(ck.byteLength).toBe(64);
	});

	it('rotateEpoch produces 64-byte chainKey for suite 5', async () => {
		const kex = new SimpleKex({
			sharedSecret: 'test-suite5',
			iterations: FAST_ITER,
			suite: 'AES_256_GCM_SHA512',
		});
		const ck0 = await kex.initialEpoch();
		const ck1 = kex.rotateEpoch(ck0, 1);
		expect(ck1.byteLength).toBe(64);
		expect(ck1).not.toStrictEqual(ck0);
	});

	it('two parties with suite 5 password → encrypt and decrypt', async () => {
		const SALT = new Uint8Array(32).fill(0x55);
		const makeKex5 = () => new SimpleKex({
			sharedSecret: 'suite5-test-password',
			iterations: FAST_ITER,
			salt: SALT,
			suite: 'AES_256_GCM_SHA512',
		});

		const alice = makeKex5();
		const bob = makeKex5();

		const ckAlice = await alice.initialEpoch();
		const ckBob = await bob.initialEpoch();
		expect(ckAlice).toStrictEqual(ckBob);

		const aliceKey = await deriveSenderKeys(ckAlice, 0, 0, 'AES_256_GCM_SHA512');
		const aliceKeyForBob = await deriveSenderKeys(ckBob, 0, 0, 'AES_256_GCM_SHA512');

		const plaintext = new TextEncoder().encode('suite5 simplex message');
		const sealed = await sframeEncrypt(plaintext, aliceKey, 0n);
		const recovered = await sframeDecrypt(
			sealed,
			({ kid }) => kid === aliceKeyForBob.kid ? aliceKeyForBob : null,
		);
		expect(new TextDecoder().decode(recovered)).toBe('suite5 simplex message');
	});

	it('SimpleKex suite 5 rotateEpoch: wrong-length prev key → TypeError', async () => {
		const kex = new SimpleKex({
			sharedSecret: 'test',
			iterations: 1,
			suite: 'AES_256_GCM_SHA512',
		});
		// 32 bytes is the suite 4 size, not suite 5 — should throw TypeError
		expect(() => kex.rotateEpoch(new Uint8Array(32), 1)).toThrow(TypeError);
	});

	it('SimpleKex suite 4 default: initialEpoch produces 32-byte chainKey', async () => {
		const kex = new SimpleKex({ sharedSecret: 'test', iterations: 1 });
		const ck = await kex.initialEpoch();
		expect(ck.byteLength).toBe(32);
	});

	it('SimpleKex suite 4 and 5 with same password produce different chain keys', async () => {
		const opts = { sharedSecret: 'shared', iterations: FAST_ITER, salt: new Uint8Array(16).fill(1) };
		const ck4 = await new SimpleKex({ ...opts, suite: 'AES_128_GCM_SHA256' }).initialEpoch();
		const ck5 = await new SimpleKex({ ...opts, suite: 'AES_256_GCM_SHA512' }).initialEpoch();
		// Different hash + different output length → different material
		expect(ck4.byteLength).toBe(32);
		expect(ck5.byteLength).toBe(64);
		// The first 32 bytes of ck5 are unlikely to match ck4 (different KDF)
		expect(hex(ck4)).not.toBe(hex(ck5.subarray(0, 32)));
	});
});

// ── 6. Suite 5 deterministic regression vector ───────────────────────────────
//
// Generated from:
//   chainKey = new Uint8Array(64).fill(0x00)
//   peerIndex = 0, epoch = 0
//   plaintext = "suite5-regression-test"  (22 bytes)
//   CTR = 0n
//
// The ciphertext body (after the library's fixed-4-byte header) is locked here.
// If this test fails, the HKDF parameters, key size, or IV derivation changed.
// Do NOT update LOCKED_CT_HEX unless the cipher suite definition is intentionally
// changed, and document the reason in CHANGELOG.md.
//
// To regenerate: comment out the expect(hex(ct)).toBe(LOCKED_CT_HEX) line,
// run the test, and print the actual value.

describe('suite 5 — deterministic regression vector', () => {
	// Locked ciphertext body (plaintext + 16-byte GCM tag) for:
	//   chainKey = new Uint8Array(64).fill(0x00)
	//   peerIndex = 0, epoch = 0, CTR = 0n
	//   plaintext = "suite5-regression-test" (22 bytes)
	// Captured after the RFC-compliant HKDF-SHA-512 + AES-256-GCM implementation.
	// Do NOT update unless cipher suite parameters are intentionally changed.
	const LOCKED_CT_HEX = '9cb3645e30867e9f4ab7bf4572d641e52016b34a1ec224e953df564b77e4aca84f75f36d2433';

	it('encrypt with zero chainKey produces expected ciphertext body', async () => {
		const chainKey = new Uint8Array(64); // zero-filled
		const senderKey = await deriveSenderKeys(chainKey, 0, 0, 'AES_256_GCM_SHA512');
		const plaintext = new TextEncoder().encode('suite5-regression-test');
		const sealed = await sframeEncrypt(plaintext, senderKey, 0n);

		// Strip header to get the ciphertext body (ciphertext + 16-byte GCM tag)
		const hdr = parseHeader(sealed);
		const ctBody = sealed.subarray(hdr.bodyOffset);

		// Ciphertext must have the right length: plaintext (22) + GCM tag (16) = 38 bytes.
		expect(ctBody.byteLength).toBe(22 + 16);

		// Locked regression check: any change to HKDF params, key size, or IV
		// derivation will break this assertion.
		expect(hex(ctBody)).toBe(LOCKED_CT_HEX);

		// Decrypt must recover plaintext.
		const recovered = await sframeDecrypt(
			sealed,
			({ kid }) => kid === senderKey.kid ? senderKey : null,
		);
		expect(new TextDecoder().decode(recovered)).toBe('suite5-regression-test');
	});

	it('deterministic: same inputs always produce the same ciphertext', async () => {
		const chainKey = new Uint8Array(64); // zero-filled
		const plaintext = new TextEncoder().encode('suite5-regression-test');

		const senderKey1 = await deriveSenderKeys(chainKey, 0, 0, 'AES_256_GCM_SHA512');
		const senderKey2 = await deriveSenderKeys(chainKey, 0, 0, 'AES_256_GCM_SHA512');
		const sealed1 = await sframeEncrypt(plaintext, senderKey1, 0n);
		const sealed2 = await sframeEncrypt(plaintext, senderKey2, 0n);

		const ctBody1 = sealed1.subarray(parseHeader(sealed1).bodyOffset);
		const ctBody2 = sealed2.subarray(parseHeader(sealed2).bodyOffset);
		expect(hex(ctBody1)).toBe(hex(ctBody2));
		expect(hex(ctBody1)).toBe(LOCKED_CT_HEX);
	});
});
