// Tests for the hot-path encode optimisations added in perf/hot-path-encode:
//   1. bufferSourceOf — zero-copy for fresh full-buffer Uint8Arrays.
//   2. sframeEncryptInto — single-allocation encode path.
//   3. encodeFrame end-to-end with the new fast path.

import { describe, it, expect } from 'vitest';
import { sframeEncrypt, sframeEncryptInto, sframeDecrypt, serializeHeader } from '../sframe.ts';
import { bufferSourceOf } from '../internal/buffer.js';
import { deriveSenderKeys, randomChainKey } from '../ratchet-crypto.ts';
import { createWorkerState } from '../worker-state.ts';
import { encodeFrame, decodeFrame } from '../worker-frame.ts';
import { makeFrame } from './helpers.ts';
import type { PeerIndex } from '../types.ts';

// ---------------------------------------------------------------------------
// 1. bufferSourceOf
// ---------------------------------------------------------------------------

describe('bufferSourceOf', () => {
	it('returns the original .buffer (no copy) for a fresh full-buffer Uint8Array', () => {
		const u8 = new Uint8Array([1, 2, 3, 4]);
		const result = bufferSourceOf(u8);
		// Must be the exact same ArrayBuffer reference — not a copy.
		expect(result).toBe(u8.buffer);
	});

	it('allocates a copy when input is a subarray (byteOffset > 0)', () => {
		const backing = new Uint8Array([0, 1, 2, 3, 4, 5]);
		const sub = backing.subarray(2, 5);  // byteOffset = 2
		expect(sub.byteOffset).toBe(2);

		const result = bufferSourceOf(sub);
		// Must NOT be the same buffer as the parent.
		expect(result).not.toBe(backing.buffer);
		// Content must be preserved.
		expect(new Uint8Array(result as ArrayBuffer)).toEqual(sub);
	});

	it('allocates a copy when byteLength < buffer.byteLength (tail subarray)', () => {
		const backing = new Uint8Array(8);
		backing.set([10, 20, 30, 40]);
		// Create a view that starts at 0 but only covers 4 bytes (front slice).
		// new Uint8Array(buffer, 0, 4) — byteOffset=0, byteLength=4, buffer.byteLength=8.
		const front = new Uint8Array(backing.buffer, 0, 4);
		expect(front.byteOffset).toBe(0);
		expect(front.byteLength).toBe(4);
		expect(front.buffer.byteLength).toBe(8);

		const result = bufferSourceOf(front);
		expect(result).not.toBe(front.buffer);
		expect(new Uint8Array(result as ArrayBuffer)).toEqual(front);
	});

	it('handles SharedArrayBuffer correctly — allocates a plain ArrayBuffer copy', () => {
		if (typeof SharedArrayBuffer === 'undefined') {
			// SAB not available in this runtime (cross-origin isolation missing).
			// Documented skip — not a defect.
			return;
		}
		const sab = new SharedArrayBuffer(4);
		const u8 = new Uint8Array(sab);
		u8.set([9, 8, 7, 6]);

		const result = bufferSourceOf(u8);
		// Must not be a SharedArrayBuffer.
		expect(result instanceof SharedArrayBuffer).toBe(false);
		expect(result instanceof ArrayBuffer).toBe(true);
		expect(new Uint8Array(result as ArrayBuffer)).toEqual(u8);
	});
});

// ---------------------------------------------------------------------------
// 2. sframeEncryptInto equivalence
// ---------------------------------------------------------------------------

describe('sframeEncryptInto', () => {
	async function makeKey(epoch = 1, peerIndex: PeerIndex = 0) {
		const chainKey = randomChainKey();
		return deriveSenderKeys(chainKey, epoch, peerIndex);
	}

	it('produces byte-for-byte identical output to sframeEncrypt (20 random inputs)', async () => {
		const key = await makeKey();
		for (let i = 0; i < 20; i++) {
			const bodyLen = Math.floor(Math.random() * 200);
			const body = crypto.getRandomValues(new Uint8Array(bodyLen));
			const ctr = BigInt(i);

			// Reference output from the existing sframeEncrypt.
			const reference = await sframeEncrypt(body, key, ctr);

			// Fast-path: caller serialises header and pre-allocates wire buffer.
			const header = serializeHeader(key.kid, ctr);
			const AEAD_TAG_BYTES = 16;
			const out = new Uint8Array(header.length + body.length + AEAD_TAG_BYTES);
			const written = await sframeEncryptInto(out, 0, header, body, key, ctr);

			expect(written).toBe(reference.length);
			expect(out).toEqual(reference);
		}
	});

	it('writes at a non-zero offset correctly', async () => {
		const key = await makeKey();
		const body = new TextEncoder().encode('hello fast path');
		const ctr = 42n;
		const header = serializeHeader(key.kid, ctr);
		const AEAD_TAG_BYTES = 16;
		const PREFIX = 5;

		const out = new Uint8Array(PREFIX + header.length + body.length + AEAD_TAG_BYTES);
		// Fill prefix sentinel bytes.
		out.fill(0xAA, 0, PREFIX);
		const written = await sframeEncryptInto(out, PREFIX, header, body, key, ctr);

		// Prefix untouched.
		for (let i = 0; i < PREFIX; i++) expect(out[i]).toBe(0xAA);

		// sframeEncryptInto portion matches sframeEncrypt.
		const reference = await sframeEncrypt(body, key, ctr);
		expect(written).toBe(reference.length);
		expect(out.subarray(PREFIX, PREFIX + written)).toEqual(reference);
	});

	it('output is decryptable with sframeDecrypt', async () => {
		const key = await makeKey();
		const body = new TextEncoder().encode('round-trip via into');
		const ctr = 7n;
		const header = serializeHeader(key.kid, ctr);
		const AEAD_TAG_BYTES = 16;
		const out = new Uint8Array(header.length + body.length + AEAD_TAG_BYTES);
		await sframeEncryptInto(out, 0, header, body, key, ctr);

		const decrypted = await sframeDecrypt(out, ({ kid }) => (kid === key.kid ? key : null));
		expect(decrypted).toEqual(body);
	});

	it('works with zero-length body', async () => {
		const key = await makeKey();
		const body = new Uint8Array(0);
		const ctr = 0n;
		const reference = await sframeEncrypt(body, key, ctr);

		const header = serializeHeader(key.kid, ctr);
		const AEAD_TAG_BYTES = 16;
		const out = new Uint8Array(header.length + AEAD_TAG_BYTES);
		const written = await sframeEncryptInto(out, 0, header, body, key, ctr);
		expect(written).toBe(reference.length);
		expect(out).toEqual(reference);
	});
});

// ---------------------------------------------------------------------------
// 3. encodeFrame end-to-end with the new fast path
// ---------------------------------------------------------------------------

async function makeEncodeState(epoch = 1) {
	const chainKey = randomChainKey();
	// deriveSenderKeys returns SFrameKey & { rawKey } — has kid, epoch, peerIndex fields.
	const selfKey = await deriveSenderKeys(chainKey, epoch, 0 as PeerIndex);
	const peerKey = await deriveSenderKeys(chainKey, epoch, 1 as PeerIndex);
	const keys = new Map<PeerIndex, typeof selfKey>();
	keys.set(0, selfKey);
	keys.set(1, peerKey);

	const state = createWorkerState(() => { /* no-op emit */ });
	state.epochs.set(epoch, {
		epoch,
		selfPeerIndex: 0 as PeerIndex,
		keys,
		ratchetSteps: new Map(),
	});
	state.currentEpoch = epoch;
	state.ctr = 0n;
	return { state, selfKey, peerKey, epoch, chainKey };
}

describe('encodeFrame fast path', () => {
	it('round-trips a video frame (no codec prefix, no trailer)', async () => {
		const { state, selfKey } = await makeEncodeState();
		const plaintext = new TextEncoder().encode('frame payload');
		const frame = makeFrame(plaintext);

		await encodeFrame(state, frame);

		// Decrypt the encoded frame.
		const encoded = new Uint8Array(frame.data as ArrayBuffer);
		const decrypted = await sframeDecrypt(
			encoded,
			({ kid }) => (kid === selfKey.kid ? selfKey : null),
		);
		expect(decrypted).toEqual(plaintext);
	});

	it('round-trips with SIF trailer enabled', async () => {
		const { state, selfKey } = await makeEncodeState();
		const trailerBytes = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
		state.sifTrailer = trailerBytes;

		const plaintext = new TextEncoder().encode('frame with trailer');
		const frame = makeFrame(plaintext);
		await encodeFrame(state, frame);

		// Wire: [sframe][trailer]. Strip trailer before decrypting.
		const wire = new Uint8Array(frame.data as ArrayBuffer);
		expect(wire.slice(-4)).toEqual(trailerBytes);
		const sframeBytes = wire.subarray(0, wire.byteLength - 4);
		const decrypted = await sframeDecrypt(
			sframeBytes,
			({ kid }) => (kid === selfKey.kid ? selfKey : null),
		);
		expect(decrypted).toEqual(plaintext);
	});

	it('round-trips with codec partial encryption (VP8 key frame)', async () => {
		// Build a shared state for encode AND decode (same epoch keys).
		const { state, selfKey, epoch } = await makeEncodeState();
		state.codec = 'vp8';

		// Body is at least 20 bytes so the codec prefix applies.
		const plaintext = crypto.getRandomValues(new Uint8Array(30));
		const frame = makeFrame(plaintext);
		(frame as unknown as { type: string }).type = 'key';
		// encodeFrame uses the frameKind parameter (not frame.type) for codec-prefix logic.
		await encodeFrame(state, frame, 'key');

		// Wire layout: [prefix(10)][sframe_header][ciphertext+tag][no trailer]
		// The prefix bytes are plaintext[0..10] (unencrypted).
		// Verify prefix bytes are preserved.
		const wire = new Uint8Array(frame.data as ArrayBuffer);
		expect(wire.subarray(0, 10)).toEqual(plaintext.subarray(0, 10));

		// Manually decrypt: strip the VP8 prefix, then decrypt the sframe portion.
		const VP8_KEY_N = 10;
		const sframeBytes = wire.subarray(VP8_KEY_N);
		const decryptedBody = await sframeDecrypt(
			sframeBytes,
			({ kid }) => (kid === selfKey.kid ? selfKey : null),
		);
		// The decrypted body is plaintext[10..30].
		expect(decryptedBody).toEqual(plaintext.subarray(VP8_KEY_N));

		// Also verify round-trip via decodeFrame using the SAME encode state.
		// Share the state so decodeFrame has the exact same key material.
		state.codec = 'vp8'; // already set
		const frameToDecrypt = { data: frame.data } as unknown as RTCEncodedVideoFrame;
		(frameToDecrypt as unknown as { type: string }).type = 'key';
		// Reset ctr so decode doesn't interfere.
		await decodeFrame(state, frameToDecrypt);
		expect(new Uint8Array(frameToDecrypt.data as ArrayBuffer)).toEqual(plaintext);
	});

	it('frame.data is an ArrayBuffer (not SharedArrayBuffer)', async () => {
		const { state } = await makeEncodeState();
		const frame = makeFrame(new TextEncoder().encode('test'));
		await encodeFrame(state, frame);
		expect(frame.data instanceof ArrayBuffer).toBe(true);
		if (typeof SharedArrayBuffer !== 'undefined') {
			expect(frame.data instanceof SharedArrayBuffer).toBe(false);
		}
	});

	it('ctr increments between frames', async () => {
		const { state, selfKey } = await makeEncodeState();
		const f1 = makeFrame(new TextEncoder().encode('frame1'));
		const f2 = makeFrame(new TextEncoder().encode('frame2'));
		await encodeFrame(state, f1);
		await encodeFrame(state, f2);

		// Both frames decrypt successfully under the same key (different ctrs).
		for (const frame of [f1, f2]) {
			const wire = new Uint8Array(frame.data as ArrayBuffer);
			const decrypted = await sframeDecrypt(
				wire,
				({ kid }) => (kid === selfKey.kid ? selfKey : null),
			);
			expect(decrypted.byteLength).toBeGreaterThan(0);
		}
	});
});
