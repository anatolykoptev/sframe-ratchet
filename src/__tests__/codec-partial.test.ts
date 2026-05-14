// Tests for codec-aware partial encryption.
// Covers: getUnencryptedBytes table, round-trip per codec/frameKind, wire-format
// invariants (unencrypted prefix intact, AEAD fails on ciphertext flip, no AEAD
// fail on prefix flip), and default (no codec) full-encrypt path.

import { describe, it, expect } from 'vitest';
import { getUnencryptedBytes } from '../codec-partial.ts';
import { createWorkerState } from '../worker-state.ts';
import { encodeFrame, decodeFrame } from '../worker-frame.ts';
import { randomChainKey } from '../ratchet-crypto.ts';
import { sframeEncrypt, sframeDecrypt } from '../sframe.ts';
import { parseHeader } from '../sframe-header.ts';
import type { Codec, FrameKind } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { installEpoch } from '../worker-state.ts';
import { makeBundles } from './helpers.ts';

function makeVideoFrame(body: Uint8Array, type: 'key' | 'delta' = 'key'): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf, type } as unknown as RTCEncodedVideoFrame;
}

function makeAudioFrame(body: Uint8Array): RTCEncodedAudioFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedAudioFrame;
}

async function makeStatePair(codec: Codec | undefined): Promise<{
	enc: ReturnType<typeof createWorkerState>;
	dec: ReturnType<typeof createWorkerState>;
}> {
	const chainKey = randomChainKey();
	const peerIndexMap: Record<string, PeerIndex> = { alice: 0 };
	const bundles = await makeBundles(chainKey, 0, peerIndexMap);

	const enc = createWorkerState(() => {});
	installEpoch(enc, 0, 0, bundles);
	if (codec !== undefined) enc.codec = codec;

	const dec = createWorkerState(() => {});
	installEpoch(dec, 0, 0, bundles);
	if (codec !== undefined) dec.codec = codec;

	return { enc, dec };
}

async function makeStateWithCodec(codec: Codec | undefined): Promise<ReturnType<typeof createWorkerState>> {
	const { enc } = await makeStatePair(codec);
	return enc;
}

// ---------------------------------------------------------------------------
// 1. getUnencryptedBytes table
// ---------------------------------------------------------------------------

describe('getUnencryptedBytes', () => {
	const cases: Array<{ codec: Codec | undefined; frameKind: FrameKind | undefined; expected: number }> = [
		{ codec: 'vp8',     frameKind: 'key',   expected: 10 },
		{ codec: 'vp8',     frameKind: 'inter', expected: 3  },
		{ codec: 'vp8',     frameKind: undefined, expected: 3 }, // undefined frameKind → inter path
		{ codec: 'h264',    frameKind: 'key',   expected: 1  },
		{ codec: 'h264',    frameKind: 'inter', expected: 1  },
		{ codec: 'h264',    frameKind: undefined, expected: 1 },
		{ codec: 'vp9',     frameKind: 'key',   expected: 0  },
		{ codec: 'vp9',     frameKind: 'inter', expected: 0  },
		{ codec: 'av1',     frameKind: 'key',   expected: 0  },
		{ codec: 'av1',     frameKind: 'inter', expected: 0  },
		{ codec: 'opus',    frameKind: undefined, expected: 1 },
		{ codec: undefined, frameKind: undefined, expected: 0 },
		{ codec: undefined, frameKind: 'key',   expected: 0  },
		{ codec: undefined, frameKind: 'inter', expected: 0  },
	];

	for (const { codec, frameKind, expected } of cases) {
		it(`codec=${String(codec)} frameKind=${String(frameKind)} → ${expected}`, () => {
			expect(getUnencryptedBytes(codec, frameKind)).toBe(expected);
		});
	}
});

// ---------------------------------------------------------------------------
// 2. Round-trip per codec + frameKind
// ---------------------------------------------------------------------------

describe('encode/decode round-trip per codec', () => {
	// Plaintext large enough that every prefix fits within it.
	const PLAINTEXT = new Uint8Array(64).fill(0xab);
	for (let i = 0; i < PLAINTEXT.length; i++) PLAINTEXT[i] = i;

	const cases: Array<{ codec: Codec | undefined; frameKind: FrameKind | undefined; frameType: 'key' | 'delta' }> = [
		{ codec: 'vp8',  frameKind: 'key',   frameType: 'key'   },
		{ codec: 'vp8',  frameKind: 'inter', frameType: 'delta' },
		{ codec: 'h264', frameKind: 'key',   frameType: 'key'   },
		{ codec: 'vp9',  frameKind: 'key',   frameType: 'key'   },
		{ codec: 'av1',  frameKind: 'key',   frameType: 'key'   },
		{ codec: undefined, frameKind: undefined, frameType: 'key' },
	];

	for (const { codec, frameType } of cases) {
		it(`round-trip: codec=${String(codec)} frameType=${frameType}`, async () => {
			const { enc: encState, dec: decState } = await makeStatePair(codec);

			const encFrame = makeVideoFrame(PLAINTEXT, frameType);
			await encodeFrame(encState, encFrame, frameType === 'key' ? 'key' : 'inter');

			const decFrame = makeVideoFrame(new Uint8Array(encFrame.data), frameType);
			await decodeFrame(decState, decFrame);

			expect(new Uint8Array(decFrame.data)).toEqual(PLAINTEXT);
		});
	}

	it('round-trip: codec=opus (audio frame)', async () => {
		const { enc: encState, dec: decState } = await makeStatePair('opus');

		const encFrame = makeAudioFrame(PLAINTEXT);
		await encodeFrame(encState, encFrame, undefined);

		const decFrame = makeAudioFrame(new Uint8Array(encFrame.data));
		await decodeFrame(decState, decFrame);

		expect(new Uint8Array(decFrame.data)).toEqual(PLAINTEXT);
	});
});

// ---------------------------------------------------------------------------
// 3. Unencrypted prefix is byte-identical before and after encode
// ---------------------------------------------------------------------------

describe('unencrypted prefix preserved in wire bytes', () => {
	const PLAINTEXT = new Uint8Array(64);
	for (let i = 0; i < PLAINTEXT.length; i++) PLAINTEXT[i] = i;

	const prefixCases: Array<{ codec: Codec; frameType: 'key' | 'delta'; N: number }> = [
		{ codec: 'vp8',  frameType: 'key',   N: 10 },
		{ codec: 'vp8',  frameType: 'delta', N: 3  },
		{ codec: 'h264', frameType: 'key',   N: 1  },
		{ codec: 'opus', frameType: 'key',   N: 1  },
	];

	for (const { codec, frameType, N } of prefixCases) {
		it(`codec=${codec} frameType=${frameType}: first ${N} wire bytes equal plaintext prefix`, async () => {
			const state = await makeStateWithCodec(codec);
			const frame = makeVideoFrame(PLAINTEXT, frameType);
			await encodeFrame(state, frame, frameType === 'key' ? 'key' : 'inter');

			const wire = new Uint8Array(frame.data);
			expect(wire.subarray(0, N)).toEqual(PLAINTEXT.subarray(0, N));
		});
	}
});

// ---------------------------------------------------------------------------
// 4. Flipping a byte in the encrypted region causes AEAD auth failure
// ---------------------------------------------------------------------------

describe('AEAD failure on ciphertext flip', () => {
	it('flip a byte in ciphertext region → decrypt throws', async () => {
		const codec: Codec = 'vp8';
		const frameType = 'key'; // N = 10
		const PLAINTEXT = new Uint8Array(64);
		for (let i = 0; i < PLAINTEXT.length; i++) PLAINTEXT[i] = i;

		const { enc: encState, dec: decState } = await makeStatePair(codec);
		const encFrame = makeVideoFrame(PLAINTEXT, frameType);
		await encodeFrame(encState, encFrame, 'key');

		// Find where the SFrame header ends so we can flip a ciphertext byte.
		// Wire: [10 prefix bytes] [header] [ciphertext + tag]
		const N = 10;
		const wire = new Uint8Array(encFrame.data.slice(0)); // copy
		const hdr = parseHeader(wire.subarray(N));
		const ctStart = N + hdr.bodyOffset; // first ciphertext byte
		wire[ctStart] ^= 0xff; // corrupt

		const decFrame = makeVideoFrame(wire, frameType);
		await expect(decodeFrame(decState, decFrame)).rejects.toBeDefined();
	});
});

// ---------------------------------------------------------------------------
// 5. Flipping a byte in the unencrypted prefix does NOT cause AEAD failure
// ---------------------------------------------------------------------------

describe('no AEAD failure on prefix flip', () => {
	it('flip a byte in the unencrypted prefix → decode does NOT throw (AEAD unaffected)', async () => {
		// NOTE: this is the documented trade-off — prefix is not authenticated.
		// A corrupt prefix may produce garbage decoded frame content, but it
		// does NOT trigger an AES-GCM authentication failure.
		const codec: Codec = 'vp8';
		const frameType = 'key'; // N = 10
		const PLAINTEXT = new Uint8Array(64);
		for (let i = 0; i < PLAINTEXT.length; i++) PLAINTEXT[i] = i;

		const { enc: encState, dec: decState } = await makeStatePair(codec);
		const encFrame = makeVideoFrame(PLAINTEXT, frameType);
		await encodeFrame(encState, encFrame, 'key');

		const wire = new Uint8Array(encFrame.data.slice(0));
		wire[5] ^= 0xff; // flip byte 5 (inside the 10-byte vp8 keyframe prefix)

		const decFrame = makeVideoFrame(wire, frameType);
		// Should NOT throw — AEAD covers only the post-prefix body.
		await expect(decodeFrame(decState, decFrame)).resolves.toBeUndefined();

		// Decrypted content has the flipped prefix but correct encrypted region.
		const result = new Uint8Array(decFrame.data);
		expect(result[5]).toBe(PLAINTEXT[5] ^ 0xff); // prefix byte is flipped
		expect(result[10]).toBe(PLAINTEXT[10]);        // encrypted region is intact
	});
});

// ---------------------------------------------------------------------------
// 6. Default path (no codec) unchanged
// ---------------------------------------------------------------------------

describe('default path (codec=undefined) unchanged', () => {
	it('no codec set → full encryption, wire format identical to current behavior', async () => {
		// Encode a frame without codec setting.
		const state = await makeStateWithCodec(undefined);
		const PLAINTEXT = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
		const frame = makeVideoFrame(PLAINTEXT);
		await encodeFrame(state, frame, undefined);

		const wire = new Uint8Array(frame.data);

		// The first byte of the wire should be the SFrame header — NOT a plaintext byte.
		// Verify by parsing the header starting at offset 0.
		expect(() => parseHeader(wire)).not.toThrow();

		// The plaintext bytes must not appear verbatim at offset 0 (they're encrypted).
		// With no codec, N=0 so there's no unencrypted prefix.
		expect(wire.subarray(0, 4)).not.toEqual(PLAINTEXT.subarray(0, 4));
	});

	it('no codec set → round-trip restores exact plaintext', async () => {
		const { enc: encState, dec: decState } = await makeStatePair(undefined);

		const PLAINTEXT = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
		const encFrame = makeVideoFrame(PLAINTEXT);
		await encodeFrame(encState, encFrame, undefined);

		const decFrame = makeVideoFrame(new Uint8Array(encFrame.data));
		await decodeFrame(decState, decFrame);

		expect(new Uint8Array(decFrame.data)).toEqual(PLAINTEXT);
	});

	it('vp9 and av1 also produce N=0 — indistinguishable from no-codec path', async () => {
		for (const codec of ['vp9', 'av1'] as Codec[]) {
			const { enc: encState, dec: decState } = await makeStatePair(codec);

			const PLAINTEXT = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
			const encFrame = makeVideoFrame(PLAINTEXT, 'key');
			await encodeFrame(encState, encFrame, 'key');

			// Wire starts with SFrame header (no prefix).
			const wire = new Uint8Array(encFrame.data);
			expect(() => parseHeader(wire)).not.toThrow();

			const decFrame = makeVideoFrame(wire, 'key');
			await decodeFrame(decState, decFrame);
			expect(new Uint8Array(decFrame.data)).toEqual(PLAINTEXT);
		}
	});
});

// ---------------------------------------------------------------------------
// 7. Prefix-only reference test: direct sframeEncrypt with subarray body
// ---------------------------------------------------------------------------

describe('sframeEncrypt with partial body (unit verification)', () => {
	it('encrypt only body[N:] and prepend prefix manually — round-trips', async () => {
		const chainKey = randomChainKey();
		const { deriveEpochKeyTable: _ } = await import('../ratchet-crypto.ts');
		const { deriveSenderKeys } = await import('../ratchet-crypto.ts');
		const key = await deriveSenderKeys(chainKey, 0, 0);

		const plaintext = new Uint8Array(20);
		for (let i = 0; i < 20; i++) plaintext[i] = i;
		const N = 3;
		const prefix = plaintext.subarray(0, N);
		const body = plaintext.subarray(N);

		const sealed = await sframeEncrypt(body, key, 0n);
		const wire = new Uint8Array(N + sealed.byteLength);
		wire.set(prefix, 0);
		wire.set(sealed, N);

		// Peel prefix and decrypt.
		const sealedBack = wire.subarray(N);
		const opened = await sframeDecrypt(sealedBack, ({ kid }) => kid === key.kid ? key : null);

		const restored = new Uint8Array(N + opened.byteLength);
		restored.set(wire.subarray(0, N), 0);
		restored.set(opened, N);

		expect(restored).toEqual(plaintext);
	});
});
