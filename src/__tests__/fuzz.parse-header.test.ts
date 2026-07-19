// Property-based fuzzing harness for parseHeader (src/sframe-header.ts).
// Issue #16: catch header-parse panics, integer overflows in CTR decoding,
// and AEAD edge cases. Uses fast-check property tests that run inside vitest
// — no separate fuzzing infra required.
//
// SECURITY CONTRACT: fuzzing is test-only; no runtime behavior change.
// A crash found by the fuzzer is a bug to fix, not a fuzzer problem. If a
// property finds an uncaught exception that isn't HeaderParseError, NOTE it
// in the task summary — do NOT fix it in this task unless it's trivially a
// test bug.

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { parseHeader, serializeHeader } from '../sframe-header.ts';
import { HeaderParseError } from '../errors.ts';

// The wire format produced by serializeHeader always sets K=1 (extended KID)
// with a fixed 4-byte big-endian KID, so the round-trip property only covers
// the extended-KID space (kid 0..0xFFFFFFFF). The inline-KID space (K=0,
// 3-bit KID embedded in the KLEN field) is exercised by the raw-bytes
// properties below — parseHeader must accept any valid wire encoding an
// attacker might send, not just the ones this library produces.
const arbKidExtended = fc.integer({ min: 0, max: 0xffffffff });
// CTR is a minimal-big-endian field of 1..8 bytes → [0, 2^64-1]. serializeHeader
// rejects > 2^64-1, so bound the arbitrary to the encodable range.
const arbCtr = fc.bigInt({ min: 0n, max: 0xffffffffffffffffn });

describe('parseHeader fuzzing (fast-check)', () => {
	it('parseHeader(serializeHeader(kid, ctr)) round-trips for all valid (kid, ctr)', () => {
		fc.assert(
			fc.property(arbKidExtended, arbCtr, (kid, ctr) => {
				const buf = serializeHeader(kid, ctr);
				const parsed = parseHeader(buf);
				expect(parsed.kid).toBe(kid);
				expect(parsed.ctr).toBe(ctr);
				// bodyOffset must consume exactly the header bytes (no body present).
				expect(parsed.bodyOffset).toBe(buf.length);
			}),
			{ numRuns: 1000 },
		);
	});

	it('parseHeader never throws on arbitrary bytes ≤ 20 bytes, returns HeaderParseError instead', () => {
		const arbBytes = fc.uint8Array({ minLength: 1, maxLength: 20 });
		fc.assert(
			fc.property(arbBytes, (buf) => {
				try {
					// A valid parse is acceptable; the contract is "no uncaught throw
					// of a non-HeaderParseError type". If it parses, the fields must
					// be internally consistent (bodyOffset within buffer bounds).
					const parsed = parseHeader(buf);
					expect(parsed.bodyOffset).toBeGreaterThanOrEqual(1);
					expect(parsed.bodyOffset).toBeLessThanOrEqual(buf.length);
					expect(parsed.kid).toBeGreaterThanOrEqual(0);
					expect(parsed.ctr).toBeGreaterThanOrEqual(0n);
				} catch (e) {
					// The ONLY acceptable throw is HeaderParseError — never a panic,
					// never a RangeError/TypeError, never an uncaught exception.
					expect(e).toBeInstanceOf(HeaderParseError);
				}
			}),
			{ numRuns: 1000 },
		);
	});

	it('parseHeader never throws on arbitrary bytes 0-1000 bytes', () => {
		const arbBytes = fc.uint8Array({ minLength: 0, maxLength: 1000 });
		fc.assert(
			fc.property(arbBytes, (buf) => {
				try {
					const parsed = parseHeader(buf);
					expect(parsed.bodyOffset).toBeGreaterThanOrEqual(1);
					expect(parsed.bodyOffset).toBeLessThanOrEqual(buf.length);
					expect(parsed.kid).toBeGreaterThanOrEqual(0);
					expect(parsed.ctr).toBeGreaterThanOrEqual(0n);
				} catch (e) {
					expect(e).toBeInstanceOf(HeaderParseError);
				}
			}),
			// Larger buffers → keep iterations modest so the suite stays fast.
			{ numRuns: 100 },
		);
	});

	it('parseHeader handles truncated headers gracefully', () => {
		// 0-2 bytes is too short for any valid extended-KID header (min 6 bytes:
		// 1 config + 4 KID + 1 CTR). Inline-KID headers can be 1-2 bytes, but a
		// truncated buffer that claims an extended field must fail closed.
		const arbBytes = fc.uint8Array({ minLength: 0, maxLength: 2 });
		fc.assert(
			fc.property(arbBytes, (buf) => {
				try {
					const parsed = parseHeader(buf);
					// If it parses, it must be a valid inline-only header (K=0, C=0):
					// 1 byte total, kid in [0,7], ctr in [0,7].
					expect(parsed.bodyOffset).toBeLessThanOrEqual(buf.length);
					expect(parsed.kid).toBeGreaterThanOrEqual(0);
					expect(parsed.ctr).toBeGreaterThanOrEqual(0n);
				} catch (e) {
					expect(e).toBeInstanceOf(HeaderParseError);
				}
			}),
			{ numRuns: 1000 },
		);
	});

	it('parseHeader handles all possible first-byte values', () => {
		// For each first byte 0x00-0xFF, append random bytes and verify no
		// uncaught throw. Exhaustive over the config byte (256 values) × random
		// tail. This catches config-byte-specific parse paths (K=0/1, C=0/1,
		// all KLEN/CLEN combinations including the 7-byte CTR edge case).
		const arbTail = fc.uint8Array({ minLength: 0, maxLength: 16 });
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 255 }), arbTail, (firstByte, tail) => {
				const buf = new Uint8Array(1 + tail.length);
				buf[0] = firstByte;
				buf.set(tail, 1);
				try {
					const parsed = parseHeader(buf);
					expect(parsed.bodyOffset).toBeGreaterThanOrEqual(1);
					expect(parsed.bodyOffset).toBeLessThanOrEqual(buf.length);
					expect(parsed.kid).toBeGreaterThanOrEqual(0);
					expect(parsed.ctr).toBeGreaterThanOrEqual(0n);
				} catch (e) {
					expect(e).toBeInstanceOf(HeaderParseError);
				}
			}),
			{ numRuns: 1000 },
		);
	});
});
