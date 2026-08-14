// Falsification tests F1-F5 for the three defects fixed in
// oxpulse-partner-edge#618:
//   F1 — VP9 keyframe prefix is visible (N=1, not N=0)
//   F2 — AV1 keyframe prefix is visible (N=1, not N=0)
//   F3 — Pre-epoch queue preserves the keyframe (tail eviction, not head)
//   F4 — Encode-side rethrow does NOT kill the pipe (drop+count, not rethrow)
//   F5 — Unencrypted prefix is authenticated (AEAD rejects prefix tamper)
//
// Each test is structured as a falsification: it asserts the FIXED behavior.
// To verify the test is not vacuous, mutate the fix back to the broken state
// and confirm the test FAILS (RED). Mutation instructions are in each test's
// comment.

import { describe, it, expect } from 'vitest';
import { createWorkerState, installEpoch } from '../worker-state.ts';
import { encodeFrame, decodeFrame, drainPreEpochQueue, pipe } from '../worker-frame.ts';
import { getUnencryptedBytes } from '../codec-partial.ts';
import { sframeEncrypt, sframeDecrypt } from '../sframe.ts';
import { randomChainKey, deriveSenderKeys } from '../ratchet-crypto.ts';
import { makeBundles } from './helpers.ts';
import type { Codec, OutMsg, MetricsEvent } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';

// --- helpers ---

function makeVideoFrame(body: Uint8Array, type: 'key' | 'delta'): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf, type } as unknown as RTCEncodedVideoFrame;
}

function makeEncryptedFrame(body: Uint8Array): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}

async function makeEncState(codec: Codec) {
	const emitted: OutMsg[] = [];
	const state = createWorkerState((m) => emitted.push(m));
	state.codec = codec;
	const chainKey = randomChainKey();
	const peerIndexMap = { alice: 0 as PeerIndex };
	const bundles = await makeBundles(chainKey, 0, peerIndexMap);
	installEpoch(state, 0, 0, bundles);
	return { state, emitted, chainKey };
}

async function makeDecState(codec: Codec, chainKey: Uint8Array) {
	const emitted: OutMsg[] = [];
	const state = createWorkerState((m) => emitted.push(m));
	state.codec = codec;
	const peerIndexMap = { alice: 0 as PeerIndex };
	const bundles = await makeBundles(chainKey, 0, peerIndexMap);
	installEpoch(state, 0, 0, bundles);
	return { state, emitted };
}

// --- F1: VP9 keyframe prefix visible ---

describe('F1 — VP9 keyframe prefix is visible to the SFU (N=1)', () => {
	it('getUnencryptedBytes(vp9, key) returns 1, not 0', () => {
		// Mutation: revert vp9 case to `return 0` → this test FAILS.
		expect(getUnencryptedBytes('vp9', 'key')).toBe(1);
	});

	it('encoded VP9 keyframe has byte 0 in the clear (keyframe indicator visible)', async () => {
		// Mutation: revert vp9 case to `return 0` → wire[0] is SFrame header,
		// not the plaintext keyframe byte → assertion fails.
		const { state } = await makeEncState('vp9');
		// VP9 keyframe: frame_marker=0b10, profile=0, show_existing=0, frame_type=0 (KEY)
		// byte 0 = 0b10_0_0_0_0_0_0 = 0x80
		const plaintext = new Uint8Array([0x80, 0x01, 0x02, 0x03, 0x04, 0x05]);
		const frame = makeVideoFrame(plaintext, 'key');
		await encodeFrame(state, frame, 'key');

		const wire = new Uint8Array(frame.data);
		expect(wire[0]).toBe(0x80); // VP9 keyframe indicator byte is in the clear
	});
});

// --- F2: AV1 keyframe prefix visible ---

describe('F2 — AV1 keyframe prefix is visible to the SFU (N=1)', () => {
	it('getUnencryptedBytes(av1, key) returns 1, not 0', () => {
		// Mutation: revert av1 case to `return 0` → this test FAILS.
		expect(getUnencryptedBytes('av1', 'key')).toBe(1);
	});

	it('encoded AV1 keyframe has byte 0 in the clear (OBU type visible)', async () => {
		// Mutation: revert av1 case to `return 0` → wire[0] is SFrame header,
		// not the plaintext OBU header → assertion fails.
		const { state } = await makeEncState('av1');
		// AV1 keyframe: OBU header with obu_type=1 (SequenceHeader)
		// byte 0 = 0b0_0001_0_0_0 = 0x08 (forbidden=0, type=1, ext=0, size=0, reserved=0)
		const plaintext = new Uint8Array([0x08, 0x01, 0x02, 0x03, 0x04, 0x05]);
		const frame = makeVideoFrame(plaintext, 'key');
		await encodeFrame(state, frame, 'key');

		const wire = new Uint8Array(frame.data);
		expect(wire[0]).toBe(0x08); // AV1 SequenceHeader OBU type is in the clear
	});
});

// --- F3: Pre-epoch queue preserves keyframe (tail eviction) ---

describe('F3 — Pre-epoch queue preserves the keyframe at the head', () => {
	it('overflow drops newest (tail), not oldest (head) — keyframe survives', async () => {
		// Mutation: change `state.preEpochQueue.pop()` back to
		// `state.preEpochQueue.shift()` → head eviction returns, frame 0
		// (the keyframe) is dropped, assertion `frame0 decoded` FAILS.
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		// Frame 0 is the keyframe (head of the stream).
		// Frames 1-59 are inter frames.
		const frames: RTCEncodedVideoFrame[] = [];
		for (let i = 0; i < 60; i++) {
			const ct = await sframeEncrypt(new TextEncoder().encode(`f${i}`), key, BigInt(i));
			frames.push(makeEncryptedFrame(ct));
			await decodeFrame(state, frames[i]);
		}

		// 10 overflow events (queue cap = 50, 10 frames dropped from tail).
		const overflowEvents = emitted.filter(
			(m) => m.type === 'decrypt_failure' && (m as { type: string; reason: string }).reason === 'queue_overflow',
		);
		expect(overflowEvents).toHaveLength(10);

		// Install epoch and drain.
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);
		await drainPreEpochQueue(state);

		// CRITICAL: frame 0 (the keyframe) must have survived and decoded.
		// Under head eviction (the bug), frame 0 would have been the first
		// frame dropped, and this assertion would fail.
		expect(new TextDecoder().decode(new Uint8Array(frames[0].data))).toBe('f0');
	});
});

// --- F4: Encode-side rethrow does NOT kill the pipe ---

describe('F4 — Encode-side frame failure drops the frame, does NOT kill the pipe', () => {
	it('a failing encode frame is dropped; subsequent frames still flow', async () => {
		// Mutation: add `if (side === 'encode') throw err;` back to the catch
		// block in pipe() → the pipeTo rejects, the second frame never
		// arrives at the writable, and `received.length` is 0 → FAILS.
		//
		// Setup: pipe with 'encode' side, no epoch installed → every
		// encodeFrame throws "no active send epoch". The first frame
		// should be dropped (not rethrown). Then install an epoch and
		// send a second frame — it should arrive at the writable.
		const emitted: OutMsg[] = [];
		const metrics: MetricsEvent[] = [];
		const state = createWorkerState((m) => {
			emitted.push(m);
			if (m.type === 'metrics') metrics.push(m.event);
		});
		state.metricsEnabled = true;

		const received: RTCEncodedVideoFrame[] = [];
		const readable = new ReadableStream<RTCEncodedVideoFrame>({
			start(controller) {
				// Frame 1: no epoch → encodeFrame throws → dropped.
				controller.enqueue(makeVideoFrame(new Uint8Array([1, 2, 3]), 'key'));
				// Install epoch between frames (async, but enqueue is sync).
				// We'll install it after pipe starts via a microtask.
				queueMicrotask(async () => {
					const chainKey = randomChainKey();
					const peerIndexMap = { alice: 0 as PeerIndex };
					const bundles = await makeBundles(chainKey, 0, peerIndexMap);
					installEpoch(state, 0, 0, bundles);
					// Frame 2: epoch is installed → encodeFrame succeeds.
					controller.enqueue(makeVideoFrame(new Uint8Array([4, 5, 6]), 'key'));
					controller.close();
				});
			},
		});
		const writable = new WritableStream<RTCEncodedVideoFrame>({
			write(frame) { received.push(frame); },
		});

		pipe(state, 'encode', readable, writable);

		// Wait for the pipe to settle.
		await new Promise((resolve) => setTimeout(resolve, 200));

		// The second frame must have arrived — the pipe survived the first
		// frame's encode failure. Under the rethrow bug, pipeTo would have
		// rejected after the first frame and the second frame would never
		// arrive.
		expect(received.length).toBeGreaterThanOrEqual(1);

		// An encrypt_failure event and an encode_drop metric must have been
		// emitted for the first frame.
		const encryptFailures = emitted.filter((m) => m.type === 'encrypt_failure');
		expect(encryptFailures.length).toBeGreaterThanOrEqual(1);
		const encodeDrops = metrics.filter((m) => m.kind === 'encode_drop');
		expect(encodeDrops.length).toBeGreaterThanOrEqual(1);
	});
});

// --- F5: Unencrypted prefix is authenticated (AEAD rejects tamper) ---

describe('F5 — Unencrypted prefix is authenticated via AAD', () => {
	it('flipping a prefix byte causes AEAD auth failure on decrypt', async () => {
		// Mutation: remove `aadPrefix` from the sframeEncryptInto call in
		// encodeFrame (pass `undefined` instead of `prefix`) → the prefix
		// is no longer in AAD, the flip doesn't affect the tag, and
		// decodeFrame succeeds → `rejects.toBeDefined()` FAILS.
		const { state: encState, chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		// VP8 keyframe: N=10 prefix bytes.
		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;
		const encFrame = makeVideoFrame(plaintext, 'key');
		await encodeFrame(encState, encFrame, 'key');

		// Flip a byte in the unencrypted prefix.
		const wire = new Uint8Array(encFrame.data.slice(0));
		wire[3] ^= 0xff; // flip byte 3 (inside the 10-byte VP8 keyframe prefix)

		const decFrame = makeVideoFrame(wire, 'key');
		// Under the old code (prefix not in AAD), this would succeed.
		// With the fix (prefix in AAD), the AEAD tag doesn't verify → rejects.
		await expect(decodeFrame(decState, decFrame)).rejects.toBeDefined();
	});

	it('sframeEncrypt/sframeDecrypt round-trip with aadPrefix succeeds', async () => {
		// Positive control: with the correct aadPrefix, round-trip works.
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([0x80, 0x01, 0x02, 0x03, 0x04]);
		const prefix = plaintext.subarray(0, 1);
		const body = plaintext.subarray(1);

		const sealed = await sframeEncrypt(body, key, 0n, prefix);
		const opened = await sframeDecrypt(sealed, ({ kid }) => (kid === key.kid ? key : null), { aadPrefix: prefix });
		expect(opened).toEqual(body);
	});

	it('sframeDecrypt with wrong aadPrefix fails (AEAD auth)', async () => {
		// Encrypt with prefix A, decrypt with prefix B → AEAD fails.
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const body = new Uint8Array([0x01, 0x02, 0x03]);
		const prefixA = new Uint8Array([0x80]);
		const prefixB = new Uint8Array([0x81]);

		const sealed = await sframeEncrypt(body, key, 0n, prefixA);
		await expect(
			sframeDecrypt(sealed, ({ kid }) => (kid === key.kid ? key : null), { aadPrefix: prefixB }),
		).rejects.toBeDefined();
	});
});
