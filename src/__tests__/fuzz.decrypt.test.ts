// Property-based fuzzing harness for sframeDecrypt (src/sframe.ts).
// Issue #16: catch AEAD edge cases and ensure the decrypt path fails closed
// (AEADAuthError / HeaderParseError / KeyNotFoundError) on attacker-influenced
// input, never panics with an uncaught exception.
//
// SECURITY CONTRACT: fuzzing is test-only; no runtime behavior change. A crash
// found here is a bug to fix, not a fuzzer problem. If a property finds an
// uncaught exception that isn't one of the documented error types, NOTE it in
// the task summary — do NOT fix it in this task unless it's trivially a test
// bug.

import { describe, it, expect, beforeAll } from 'vitest';
import fc from 'fast-check';
import { sframeDecrypt, sframeEncrypt, serializeHeader } from '../sframe.ts';
import { deriveSenderKeys, randomChainKey } from '../ratchet-crypto.ts';
import { AEADAuthError, HeaderParseError, KeyNotFoundError, SFrameError } from '../errors.ts';
import type { SFrameKey } from '../types.ts';

// The set of error classes sframeDecrypt is contracted to throw. Anything
// outside this set is a panic/bug.
function isContractedError(e: unknown): boolean {
	return (
		e instanceof AEADAuthError ||
		e instanceof HeaderParseError ||
		e instanceof KeyNotFoundError
	);
}

describe('sframeDecrypt fuzzing (fast-check)', () => {
	let realKey: SFrameKey & { rawKey: Uint8Array };
	// A second key with a DIFFERENT salt/key material but we can return it from
	// the resolver for any kid — used to exercise the wrong-key AEAD path.
	let wrongKey: SFrameKey & { rawKey: Uint8Array };

	beforeAll(async () => {
		const chainKeyA = randomChainKey();
		realKey = await deriveSenderKeys(chainKeyA, 1, 0);
		const chainKeyB = randomChainKey();
		wrongKey = await deriveSenderKeys(chainKeyB, 99, 7);
		// sanity: different material
		expect(wrongKey.salt).not.toEqual(realKey.salt);
	});

	it('sframeDecrypt with arbitrary ciphertext + arbitrary headers fails closed, never panics', async () => {
		// Generate arbitrary byte sequences as fake encrypted frames and attempt
		// decrypt with a resolver that always returns a real key. The frame will
		// almost never decrypt successfully (random data ≠ valid AES-GCM
		// ciphertext under this key), so we expect a contracted error — never an
		// uncaught panic, never a non-contracted error type.
		const arbFrame = fc.uint8Array({ minLength: 0, maxLength: 64 });
		await fc.assert(
			fc.asyncProperty(arbFrame, async (frame) => {
				try {
					const out = await sframeDecrypt(frame, () => realKey);
					// A successful decrypt with random data is astronomically
					// unlikely; if it happens, the output is just some bytes —
					// nothing to assert beyond "didn't throw".
					expect(out).toBeInstanceOf(Uint8Array);
				} catch (e) {
					if (!isContractedError(e)) {
						// Surface the unexpected throw type clearly in the failure.
						throw new Error(
							`sframeDecrypt threw non-contracted error: ${(e as Error)?.name}: ${(e as Error)?.message}`,
						);
					}
					// Contracted error — expected. Verify it's an SFrameError subclass.
					expect(e).toBeInstanceOf(SFrameError);
				}
			}),
			{ numRuns: 200 },
		);
	});

	it('sframeDecrypt with valid header but wrong key fails with AEADAuthError', async () => {
		// Construct a valid header (parseHeader succeeds), append a random body
		// long enough to look like ciphertext+tag. Decrypt with a key whose
		// material doesn't match → AEAD auth must fail. Must NOT panic.
		const arbCtr = fc.bigInt({ min: 0n, max: 0xffffffffffffffffn });
		const arbBody = fc.uint8Array({ minLength: 16, maxLength: 48 });
		await fc.assert(
			fc.asyncProperty(arbCtr, arbBody, async (ctr, body) => {
				const header = serializeHeader(realKey.kid, ctr);
				const frame = new Uint8Array(header.length + body.length);
				frame.set(header, 0);
				frame.set(body, header.length);
				try {
					await sframeDecrypt(frame, () => wrongKey);
					// Decryption succeeding with random body + wrong key would be a
					// catastrophic AEAD break — flag it loudly.
					throw new Error('sframeDecrypt: UNEXPECTED SUCCESS with wrong key + random body');
				} catch (e) {
					if (!(e instanceof AEADAuthError)) {
						throw new Error(
							`sframeDecrypt wrong-key path threw non-AEADAuthError: ${(e as Error)?.name}: ${(e as Error)?.message}`,
						);
					}
					expect(e).toBeInstanceOf(SFrameError);
				}
			}),
			{ numRuns: 200 },
		);
	});

	it('sframeDecrypt with empty input fails closed', async () => {
		// Empty Uint8Array, single byte, and other tiny inputs must fail closed
		// with a contracted error (HeaderParseError for empty/too-short, or
		// AEADAuthError if the header parses but the body is too short for the
		// tag). Never an uncaught panic.
		const arbTiny = fc.uint8Array({ minLength: 0, maxLength: 5 });
		await fc.assert(
			fc.asyncProperty(arbTiny, async (frame) => {
				try {
					await sframeDecrypt(frame, () => realKey);
					throw new Error('sframeDecrypt: UNEXPECTED SUCCESS on tiny input');
				} catch (e) {
					if (!isContractedError(e)) {
						throw new Error(
							`sframeDecrypt tiny-input path threw non-contracted error: ${(e as Error)?.name}: ${(e as Error)?.message}`,
						);
					}
					expect(e).toBeInstanceOf(SFrameError);
				}
			}),
			{ numRuns: 500 },
		);
	});

	it('sframeDecrypt with valid header + real ciphertext round-trips (control)', async () => {
		// Control property: a genuinely encrypted frame MUST decrypt back to the
		// original plaintext. Guards against the fuzz properties above being
		// vacuously green (e.g. if sframeDecrypt always threw).
		const arbPlain = fc.uint8Array({ minLength: 0, maxLength: 64 });
		const arbCtr = fc.bigInt({ min: 0n, max: 0xffffffffffffffffn });
		await fc.assert(
			fc.asyncProperty(arbPlain, arbCtr, async (plain, ctr) => {
				const sealed = await sframeEncrypt(plain, realKey, ctr);
				const opened = await sframeDecrypt(sealed, ({ kid }) =>
					kid === realKey.kid ? realKey : null,
				);
				expect(opened).toEqual(plain);
			}),
			{ numRuns: 100 },
		);
	});
});
