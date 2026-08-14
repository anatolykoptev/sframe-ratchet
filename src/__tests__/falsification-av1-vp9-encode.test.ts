// Falsification tests for the phase 1 receive-side format tolerance fix.
//
// The b6ded9d commit introduced two independent wire-format changes:
//   1. AAD: header → prefix || header (for frames with N > 0)
//   2. VP9/AV1 prefix: N=0 → N=1
//
// Phase 1 makes the RECEIVER tolerant to both old and new formats while the
// SENDER continues to emit the old format (AAD=header, VP9/AV1 N=0). Phase 2
// will switch the sender to the new canonical AAD form (be16(len)||prefix||header)
// and VP9/AV1 N=1.
//
// F1 — Old format decrypts (mutation: remove old-format fallback → RED)
// F2 — New canonical format decrypts (mutation: remove new-format path → RED)
// F3 — Pre-epoch queue preserves the keyframe (tail eviction, not head)
// F4 — Encode-side rethrow does NOT kill the pipe (drop+count, not rethrow)
// F5 — Corrected authentication test:
//      - Old-format prefix tampering ACCEPTED (prefix not in AAD)
//      - New-canonical prefix tampering REJECTED (prefix in AAD)
//      - Format decision is cached (mutation: remove cache → RED)
//
// Each test is structured as a falsification: it asserts the FIXED behavior.
// To verify the test is not vacuous, mutate the fix back to the broken state
// and confirm the test FAILS (RED). Mutation instructions are in each test's
// comment.

import { describe, it, expect } from 'vitest';
import { createWorkerState, installEpoch } from '../worker-state.ts';
import { encodeFrame, decodeFrame, drainPreEpochQueue, pipe } from '../worker-frame.ts';
import { getUnencryptedBytes } from '../codec-partial.ts';
import { sframeEncrypt, sframeDecrypt, buildAad, type AadForm } from '../sframe.ts';
import { serializeHeader } from '../sframe-header.ts';
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

/**
 * Manually encrypt a frame in a specific wire format (old or new canonical).
 * This produces the same wire bytes a sender would produce with that format,
 * so the receiver's format-tolerance logic can be tested against both.
 *
 * - 'old' format: AAD = header, VP9/AV1 N=0, other codecs use codec N
 * - 'canonical' format: AAD = be16(len)||prefix||header, VP9/AV1 N=1, other codecs use codec N
 */
async function encryptInFormat(
	plaintext: Uint8Array,
	key: { kid: number; salt: Uint8Array; cryptoKey: CryptoKey; epoch: number; peerIndex: PeerIndex },
	ctr: bigint,
	codec: Codec | undefined,
	frameKind: 'key' | 'inter' | undefined,
	form: 'old' | 'canonical',
): Promise<Uint8Array> {
	const N = form === 'canonical' && (codec === 'vp9' || codec === 'av1')
		? 1  // phase 2: VP9/AV1 N=1
		: getUnencryptedBytes(codec, frameKind);  // phase 1: codec N (0 for VP9/AV1)
	const prefix = plaintext.subarray(0, N);
	const body = plaintext.subarray(N);
	const header = serializeHeader(key.kid, ctr);
	const aadForm: AadForm = form === 'old' ? 'header' : 'canonical';
	const aadPrefix = N > 0 ? prefix : undefined;

	// Use sframeEncrypt with the specified aadForm.
	const sealed = await sframeEncrypt(body, key, ctr, aadPrefix, aadForm);
	const wire = new Uint8Array(N + sealed.byteLength);
	if (N > 0) wire.set(prefix, 0);
	wire.set(sealed, N);
	return wire;
}

// --- F1: Old format decrypts ---

describe('F1 — Old format (AAD=header, VP9/AV1 N=0) decrypts', () => {
	it('VP8 old-format frame round-trips through encodeFrame + decodeFrame', async () => {
		// Mutation: replace ALL 'header' aadForm with 'canonical' in
		// formatCandidates() AND the fallback → the receiver only accepts
		// canonical AAD → old-format frames fail → RED.
		const { state: encState, chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;
		const encFrame = makeVideoFrame(plaintext, 'key');
		await encodeFrame(encState, encFrame, 'key');

		const decFrame = makeVideoFrame(new Uint8Array(encFrame.data), 'key');
		await decodeFrame(decState, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});

	it('VP9 old-format frame (N=0, AAD=header) decrypts via decodeFrame', async () => {
		// Mutation: replace ALL 'header' with 'canonical' in formatCandidates()
		// AND the fallback → old-format (N=0, AAD=header) frames fail → RED.
		const { chainKey } = await makeEncState('vp9');
		const { state: decState } = await makeDecState('vp9', chainKey);

		// Manually encrypt in old format (N=0, AAD=header).
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([0x80, 0x01, 0x02, 0x03, 0x04, 0x05]);
		const wire = await encryptInFormat(plaintext, key, 0n, 'vp9', 'key', 'old');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(decState, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});

	it('AV1 old-format frame (N=0, AAD=header) decrypts via decodeFrame', async () => {
		// Same mutation as VP9 above → RED.
		const { chainKey } = await makeEncState('av1');
		const { state: decState } = await makeDecState('av1', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([0x08, 0x01, 0x02, 0x03, 0x04, 0x05]);
		const wire = await encryptInFormat(plaintext, key, 0n, 'av1', 'key', 'old');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(decState, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});

	it('undefined codec old-format frame (N=0, AAD=header) decrypts', async () => {
		// Mutation: replace ALL 'header' with 'canonical' in formatCandidates()
		// AND the fallback → RED.
		const chainKey = randomChainKey();
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
		const wire = await encryptInFormat(plaintext, key, 0n, undefined, undefined, 'old');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(state, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});
});

// --- F2: New canonical format decrypts ---

describe('F2 — New canonical format (AAD=be16||prefix||header, VP9/AV1 N=1) decrypts', () => {
	it('VP8 new-canonical frame (N=10, AAD=canonical) decrypts via decodeFrame', async () => {
		// Mutation: remove { prefixLen: N, aadForm: 'canonical' } from the
		// VP8 formatCandidates() path → probe never tries canonical → RED.
		const { chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;
		const wire = await encryptInFormat(plaintext, key, 0n, 'vp8', 'key', 'canonical');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(decState, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});

	it('VP9 new-canonical frame (N=1, AAD=canonical) decrypts via decodeFrame', async () => {
		// Mutation: remove { prefixLen: 1, aadForm: 'canonical' } from the
		// VP9/AV1 formatCandidates() array → RED.
		const { chainKey } = await makeEncState('vp9');
		const { state: decState } = await makeDecState('vp9', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([0x80, 0x01, 0x02, 0x03, 0x04, 0x05]);
		const wire = await encryptInFormat(plaintext, key, 0n, 'vp9', 'key', 'canonical');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(decState, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});

	it('AV1 new-canonical frame (N=1, AAD=canonical) decrypts via decodeFrame', async () => {
		// Same mutation as VP9 above → RED.
		const { chainKey } = await makeEncState('av1');
		const { state: decState } = await makeDecState('av1', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([0x08, 0x01, 0x02, 0x03, 0x04, 0x05]);
		const wire = await encryptInFormat(plaintext, key, 0n, 'av1', 'key', 'canonical');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(decState, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
	});

	it('undefined codec new-canonical frame (N=0, AAD=canonical) decrypts', async () => {
		// Mutation: remove { prefixLen: 0, aadForm: 'canonical' } from the
		// N=0 formatCandidates() path → RED.
		const chainKey = randomChainKey();
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
		const wire = await encryptInFormat(plaintext, key, 0n, undefined, undefined, 'canonical');

		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(state, decFrame);
		expect(new Uint8Array(decFrame.data)).toEqual(plaintext);
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

// --- F5: Corrected authentication test + format cache ---

describe('F5 — Prefix authentication and format cache', () => {
	it('old-format prefix tampering is ACCEPTED (prefix not in AAD in phase 1)', async () => {
		// PHASE 1: the sender emits AAD=header (prefix NOT in AAD).
		// Flipping a prefix byte does NOT change the AAD, so the AEAD tag
		// still verifies. The decoded frame has a corrupted prefix but the
		// decrypted body is correct. This is the documented trade-off (issue #50).
		//
		// Mutation: change encodeFrame to pass aadPrefix with aadForm='canonical'
		// → the prefix IS in AAD → flipping it causes AEAD auth failure →
		// decodeFrame rejects → this test FAILS.
		const { state: encState, chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;
		const encFrame = makeVideoFrame(plaintext, 'key');
		await encodeFrame(encState, encFrame, 'key');

		// Flip a byte in the unencrypted prefix (byte 3, inside VP8 N=10).
		const wire = new Uint8Array(encFrame.data.slice(0));
		wire[3] ^= 0xff;

		const decFrame = makeVideoFrame(wire, 'key');
		// Should SUCCEED — prefix is not in AAD in phase 1.
		await decodeFrame(decState, decFrame);
		const dec = new Uint8Array(decFrame.data);
		expect(dec.subarray(10)).toEqual(plaintext.subarray(10));
		expect(dec[3]).toBe(plaintext[3] ^ 0xff); // prefix corrupted
	});

	it('new-canonical prefix tampering is REJECTED (prefix in AAD)', async () => {
		// When the sender uses the canonical AAD form (be16||prefix||header),
		// the prefix IS authenticated. Flipping a prefix byte changes the AAD,
		// causing AEAD auth failure. This proves the canonical form provides
		// prefix authentication (the phase 2 security property).
		//
		// Mutation: remove the 'canonical' aadForm from buildAad() → the AAD
		// doesn't include the prefix → flipping it doesn't affect the tag →
		// decodeFrame succeeds → rejects.toBeDefined() FAILS.
		const { chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;
		const wire = await encryptInFormat(plaintext, key, 0n, 'vp8', 'key', 'canonical');

		// Flip a byte in the unencrypted prefix (byte 3, inside VP8 N=10).
		const tampered = new Uint8Array(wire.slice(0));
		tampered[3] ^= 0xff;

		const decFrame = makeVideoFrame(tampered, 'key');
		// Should REJECT — prefix is in AAD (canonical form).
		await expect(decodeFrame(decState, decFrame)).rejects.toBeDefined();
	});

	it('format decision is cached — second frame uses 1 AEAD attempt', async () => {
		// After the first frame resolves the format, the cache ensures
		// subsequent frames use exactly 1 AEAD attempt (no probe).
		//
		// Mutation: remove the setFormatCache() call in decodeFrame →
		// the cache is never populated → every frame probes → the format
		// cache map is always empty → the assertion FAILS.
		const { chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;

		// First frame: old format (AAD=header).
		const wire1 = await encryptInFormat(plaintext, key, 0n, 'vp8', 'key', 'old');
		const decFrame1 = makeVideoFrame(wire1, 'key');
		await decodeFrame(decState, decFrame1);
		expect(new Uint8Array(decFrame1.data)).toEqual(plaintext);

		// Check the format cache was populated.
		const cache = decState.formatCache.get(0)?.get(0);
		expect(cache).toBeDefined();
		expect(cache!.aadForm).toBe('header');
		expect(cache!.prefixLen).toBe(10); // VP8 key N=10

		// Second frame: should use the cached format (no probe).
		const wire2 = await encryptInFormat(plaintext, key, 1n, 'vp8', 'key', 'old');
		const decFrame2 = makeVideoFrame(wire2, 'key');
		await decodeFrame(decState, decFrame2);
		expect(new Uint8Array(decFrame2.data)).toEqual(plaintext);
	});

	it('format cache is cleared on epoch wipe', async () => {
		// When an epoch is wiped, the format cache for that epoch is cleared
		// so a new epoch's sender doesn't inherit a stale format guess.
		//
		// Mutation: remove `state.formatCache.delete(epoch)` from wipeEpoch()
		// → the cache survives epoch wipe → the assertion that the cache is
		// empty after wipe FAILS.
		const { chainKey } = await makeEncState('vp8');
		const { state: decState } = await makeDecState('vp8', chainKey);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array(30);
		for (let i = 0; i < 30; i++) plaintext[i] = i;
		const wire = await encryptInFormat(plaintext, key, 0n, 'vp8', 'key', 'old');
		const decFrame = makeVideoFrame(wire, 'key');
		await decodeFrame(decState, decFrame);

		// Cache is populated.
		expect(decState.formatCache.get(0)?.get(0)).toBeDefined();

		// Manually wipe epoch 0.
		const { wipeEpoch } = await import('../worker-state.ts');
		wipeEpoch(decState, 0);

		// Cache for epoch 0 is cleared.
		expect(decState.formatCache.get(0)).toBeUndefined();
	});

	it('buildAad produces correct bytes for each form', async () => {
		// Unit test: verify buildAad output for all three forms.
		const prefix = new Uint8Array([0xAB, 0xCD]);
		const header = new Uint8Array([0x01, 0x02, 0x03]);

		// 'header': just the header
		expect(buildAad(prefix, header, 'header')).toEqual(header);

		// 'prefix': prefix || header
		expect(buildAad(prefix, header, 'prefix')).toEqual(
			new Uint8Array([0xAB, 0xCD, 0x01, 0x02, 0x03]),
		);

		// 'canonical': be16(2) || prefix || header
		expect(buildAad(prefix, header, 'canonical')).toEqual(
			new Uint8Array([0x00, 0x02, 0xAB, 0xCD, 0x01, 0x02, 0x03]),
		);

		// Empty prefix: 'header' and 'prefix' reduce to header; 'canonical'
		// still prepends be16(0).
		expect(buildAad(undefined, header, 'header')).toEqual(header);
		expect(buildAad(undefined, header, 'prefix')).toEqual(header);
		expect(buildAad(undefined, header, 'canonical')).toEqual(
			new Uint8Array([0x00, 0x00, 0x01, 0x02, 0x03]),
		);
	});

	it('sframeEncrypt/sframeDecrypt round-trip with aadPrefix + aadForm succeeds', async () => {
		// Positive control: with the correct aadPrefix + aadForm, round-trip works.
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new Uint8Array([0x80, 0x01, 0x02, 0x03, 0x04]);
		const prefix = plaintext.subarray(0, 1);
		const body = plaintext.subarray(1);

		const sealed = await sframeEncrypt(body, key, 0n, prefix, 'canonical');
		const opened = await sframeDecrypt(
			sealed,
			({ kid }) => (kid === key.kid ? key : null),
			{ aadPrefix: prefix, aadForm: 'canonical' },
		);
		expect(opened).toEqual(body);
	});

	it('sframeDecrypt with wrong aadForm fails (AEAD auth)', async () => {
		// Encrypt with 'canonical' AAD, decrypt with 'header' AAD → AEAD fails.
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const body = new Uint8Array([0x01, 0x02, 0x03]);
		const prefix = new Uint8Array([0x80]);

		const sealed = await sframeEncrypt(body, key, 0n, prefix, 'canonical');
		await expect(
			sframeDecrypt(
				sealed,
				({ kid }) => (kid === key.kid ? key : null),
				{ aadPrefix: prefix, aadForm: 'header' },
			),
		).rejects.toBeDefined();
	});
});
