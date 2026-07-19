// Concurrent ratchet dedup tests (issue #15, pattern from livekit
// ParticipantKeyHandler.ts:26 ratchetPromiseMap).
//
// When multiple frames fail AEAD simultaneously for the same (epoch,
// peerIndex), only ONE retry loop should run at a time — concurrent callers
// await the in-flight promise (stored in state.ratchetPromises) instead of
// starting parallel HKDF derivations.
//
// These tests exercise the REAL decodeFrame → tryDecryptWithRatchet path in
// src/worker-frame.ts. Each test encrypts real SFrame frames and feeds them
// through the actual decode pipeline concurrently via Promise.all.
//
// The suite goes RED if the dedup logic is removed from tryDecryptWithRatchet:
//   - Test 1 would see 2 ratchet_retry events instead of 1 (two parallel
//     derivation chains).
//   - Test 2 would see the second caller start its own retry loop.
//   - Test 3 would see only 1 ratchet_retry event (the second caller wouldn't
//     start its own loop after the rejection).
//   - Test 4 would see a leaked entry in ratchetPromises.

import { describe, it, expect, vi } from 'vitest';
import { createWorkerState, installEpoch } from '../worker-state.ts';
import { decodeFrame } from '../worker-frame.ts';
import { deriveSenderKeys, deriveNextSenderKey, randomChainKey } from '../ratchet-crypto.ts';
import * as ratchetCrypto from '../ratchet-crypto.ts';
import { sframeEncrypt } from '../sframe.ts';
import { makeKid } from '../ratchet-ids.ts';
import type { MetricsEvent, OutMsg, PerSenderKeyBundle } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { makeFrame, makeBundles } from './helpers.ts';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Advance exactly `steps` times from the given raw key and return the key AT
 * step `steps`. For steps>=1 it chains that many times via deriveNextSenderKey.
 */
async function advanceSenderKeyFrom(
	rawKey: Uint8Array,
	salt: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	steps: number,
): Promise<{ cryptoKey: CryptoKey; salt: Uint8Array; rawKey: Uint8Array }> {
	let r = rawKey;
	let s = salt;
	let last: { cryptoKey: CryptoKey; salt: Uint8Array; rawKey: Uint8Array } | null = null;
	for (let i = 0; i < steps; i++) {
		const next = await deriveNextSenderKey(r, s, epoch, peerIndex);
		r = next.rawKey;
		s = next.salt;
		last = { cryptoKey: next.cryptoKey, salt: next.salt, rawKey: next.rawKey };
	}
	if (!last) throw new Error('steps must be >= 1');
	return last;
}

/**
 * Build an SFrame key shape suitable for sframeEncrypt from a derived key.
 */
function makeSFrameKey(
	epoch: number,
	peerIndex: PeerIndex,
	key: { cryptoKey: CryptoKey; salt: Uint8Array },
) {
	return {
		kid: makeKid(epoch, peerIndex),
		epoch,
		peerIndex,
		cryptoKey: key.cryptoKey,
		salt: key.salt,
	};
}

/**
 * Encrypt `plaintext` under (epoch, peerIndex) at a specific ratchet step and
 * wrap in a frame mock. Uses the real sframeEncrypt so the wire format is
 * authentic and exercises the real decrypt path.
 */
async function encryptAtStep(
	chainKey: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	step: number,
	ctr: bigint,
	plaintext: Uint8Array,
): Promise<RTCEncodedVideoFrame> {
	const step0 = await deriveSenderKeys(chainKey, epoch, peerIndex);
	if (step === 0) {
		const ciphertext = await sframeEncrypt(plaintext, makeSFrameKey(epoch, peerIndex, step0), ctr);
		return makeFrame(ciphertext);
	}
	const advanced = await advanceSenderKeyFrom(step0.rawKey, step0.salt, epoch, peerIndex, step);
	const ciphertext = await sframeEncrypt(plaintext, makeSFrameKey(epoch, peerIndex, advanced), ctr);
	return makeFrame(ciphertext);
}

/** Extract MetricsEvent[] from the collected OutMsg[] stream. */
function metricsOf(msgs: OutMsg[]): MetricsEvent[] {
	return msgs
		.filter((m): m is { type: 'metrics'; event: MetricsEvent } => m.type === 'metrics')
		.map((m) => m.event);
}

/** Count ratchet_retry metric events (each corresponds to one retry loop). */
function ratchetRetryCount(events: MetricsEvent[]): number {
	return events.filter((e) => e.kind === 'ratchet_retry').length;
}

// ---------------------------------------------------------------------------
// Test 1: two concurrent decodeFrame calls trigger only ONE ratchet derivation
// ---------------------------------------------------------------------------

describe('concurrent ratchet dedup — single derivation chain', () => {
	it('two concurrent frames at step 1 trigger only ONE ratchet_retry event', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const msgs: OutMsg[] = [];
		const receiver = createWorkerState((m) => msgs.push(m));
		receiver.metricsEnabled = true;
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Both frames encrypted at step 1 (receiver is at step 0 → needs ratchet).
		const frame1 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 0n, new Uint8Array([1, 2, 3]));
		const frame2 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 1n, new Uint8Array([4, 5, 6]));

		// Fire both concurrently — the dedup should ensure only one retry loop runs.
		await Promise.all([decodeFrame(receiver, frame1), decodeFrame(receiver, frame2)]);

		expect(new Uint8Array(frame1.data)).toEqual(new Uint8Array([1, 2, 3]));
		expect(new Uint8Array(frame2.data)).toEqual(new Uint8Array([4, 5, 6]));

		const events = metricsOf(msgs);
		const retryCount = ratchetRetryCount(events);
		// Without dedup, both callers would run their own retry loops → 2 events.
		// With dedup, only the first caller runs the loop; the second awaits and
		// finds the advanced cached key on step-0 retry → 1 event.
		expect(retryCount).toBe(1);

		// The single ratchet_retry event should be a success at step 1.
		const retryEvent = events.find((e) => e.kind === 'ratchet_retry');
		expect(retryEvent).toBeDefined();
		expect((retryEvent as { succeeded: boolean }).succeeded).toBe(true);
		expect((retryEvent as { steps: number }).steps).toBe(1);

		// Cached key should now be at step 1.
		const entry = receiver.epochs.get(epoch);
		expect(entry!.ratchetSteps.get(senderPeerIndex)).toBe(1);
	});

	it('verifies deriveNextSenderKey call count is halved via spy', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const msgs: OutMsg[] = [];
		const receiver = createWorkerState((m) => msgs.push(m));
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		const frame1 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 0n, new Uint8Array([1]));
		const frame2 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 1n, new Uint8Array([2]));

		// Spy installed AFTER frame creation so it only counts derivations
		// during the decode path (not the test's own frame encryption).
		const spy = vi.spyOn(ratchetCrypto, 'deriveNextSenderKey');

		await Promise.all([decodeFrame(receiver, frame1), decodeFrame(receiver, frame2)]);

		// With dedup: only 1 derivation (step 1) for the first caller's loop.
		// The second caller awaits and finds the advanced key on step-0 retry.
		// Without dedup: 2 derivations (both callers derive step 1 independently).
		expect(spy.mock.calls.length).toBe(1);

		spy.mockRestore();
	});
});

// ---------------------------------------------------------------------------
// Test 2: concurrent caller's step-0 retry succeeds with the advanced key
// ---------------------------------------------------------------------------

describe('concurrent ratchet dedup — step-0 retry after await', () => {
	it('second caller decrypts via step-0 after awaiting the in-flight promise (no second loop)', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const msgs: OutMsg[] = [];
		const receiver = createWorkerState((m) => msgs.push(m));
		receiver.metricsEnabled = true;
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Both frames at step 2 — the first caller's loop will derive steps 1, 2
		// and succeed at step 2, advancing the cached key. The second caller
		// awaits, then step-0 with the step-2 key succeeds immediately.
		const frame1 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 2, 0n, new Uint8Array([10, 20]));
		const frame2 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 2, 1n, new Uint8Array([30, 40]));

		await Promise.all([decodeFrame(receiver, frame1), decodeFrame(receiver, frame2)]);

		expect(new Uint8Array(frame1.data)).toEqual(new Uint8Array([10, 20]));
		expect(new Uint8Array(frame2.data)).toEqual(new Uint8Array([30, 40]));

		const events = metricsOf(msgs);
		// Only ONE ratchet_retry event — the second caller didn't need a loop.
		expect(ratchetRetryCount(events)).toBe(1);

		// The retry event succeeded at step 2.
		const retryEvent = events.find((e) => e.kind === 'ratchet_retry');
		expect((retryEvent as { steps: number }).steps).toBe(2);
		expect((retryEvent as { succeeded: boolean }).succeeded).toBe(true);

		// Cached key advanced to step 2.
		const entry = receiver.epochs.get(epoch);
		expect(entry!.ratchetSteps.get(senderPeerIndex)).toBe(2);

		// No decrypt_failure events.
		expect(msgs.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// Test 3: in-flight promise rejects → concurrent caller starts its own loop
// ---------------------------------------------------------------------------

describe('concurrent ratchet dedup — rejection triggers own loop', () => {
	it('when the in-flight promise rejects (window exhausted), the concurrent caller starts its own retry loop', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const msgs: OutMsg[] = [];
		const receiver = createWorkerState((m) => msgs.push(m));
		receiver.metricsEnabled = true;
		// Window of 8 — step 9 is beyond the window, step 3 is within.
		expect(receiver.ratchetWindowSize).toBe(8);
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Frame 1 at step 12 (beyond window 8 from any starting point) → caller's
		// loop exhausts regardless of ordering. Step 12 ensures that even if
		// frame 2 runs first and advances the cached key to step 3, frame 1's
		// retry loop (steps 4-11) still can't reach step 12.
		// Frame 2 at step 3 (within window 8) → succeeds via its own retry loop.
		const frame1 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 12, 0n, new Uint8Array([12]));
		const frame2 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 3, 1n, new Uint8Array([3]));

		// Use allSettled — frame1 is expected to reject (window exhausted).
		const results = await Promise.allSettled([
			decodeFrame(receiver, frame1),
			decodeFrame(receiver, frame2),
		]);

		// Frame 1 should have failed (window exhausted).
		expect(results[0].status).toBe('rejected');
		// Frame 2 should have succeeded (its own retry loop found step 3).
		expect(results[1].status).toBe('fulfilled');
		if (results[1].status === 'fulfilled') {
			expect(new Uint8Array(frame2.data)).toEqual(new Uint8Array([3]));
		}

		const events = metricsOf(msgs);
		// TWO ratchet_retry events:
		//   1. First caller's loop — exhausted (succeeded=false, steps=8).
		//   2. Second caller's loop — succeeded at step 3 (succeeded=true, steps=3).
		expect(ratchetRetryCount(events)).toBe(2);

		const retryEvents = events.filter((e) => e.kind === 'ratchet_retry');
		const exhausted = retryEvents.find((e) => !(e as { succeeded: boolean }).succeeded);
		const succeeded = retryEvents.find((e) => (e as { succeeded: boolean }).succeeded);
		expect(exhausted).toBeDefined();
		expect((exhausted as { steps: number }).steps).toBe(8);
		expect(succeeded).toBeDefined();
		expect((succeeded as { steps: number }).steps).toBe(3);

		// Cached key advanced to step 3 by the second caller.
		const entry = receiver.epochs.get(epoch);
		expect(entry!.ratchetSteps.get(senderPeerIndex)).toBe(3);
	});
});

// ---------------------------------------------------------------------------
// Test 4: ratchetPromises map is cleaned up after resolution/rejection
// ---------------------------------------------------------------------------

describe('concurrent ratchet dedup — no promise leak', () => {
	it('ratchetPromises is empty after a successful ratchet resolution', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState((m) => {});
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		const frame = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 0n, new Uint8Array([1]));
		await decodeFrame(receiver, frame);

		// The promise must have been deleted in the finally block.
		expect(receiver.ratchetPromises.size).toBe(0);
	});

	it('ratchetPromises is empty after a ratchet rejection (window exhausted)', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState((m) => {});
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Step 9 beyond window 8 → rejection.
		const frame = await encryptAtStep(chainKey, epoch, senderPeerIndex, 9, 0n, new Uint8Array([1]));
		await expect(decodeFrame(receiver, frame)).rejects.toThrow();

		// The promise must have been deleted even on rejection.
		expect(receiver.ratchetPromises.size).toBe(0);
	});

	it('ratchetPromises is empty after concurrent resolution', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState((m) => {});
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		const frame1 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 0n, new Uint8Array([1]));
		const frame2 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 1, 1n, new Uint8Array([2]));
		await Promise.all([decodeFrame(receiver, frame1), decodeFrame(receiver, frame2)]);

		// No leaked promises after concurrent resolution.
		expect(receiver.ratchetPromises.size).toBe(0);
	});

	it('ratchetPromises is empty after concurrent mixed resolve/reject', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState((m) => {});
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Frame 1 exhausts (step 9), frame 2 succeeds (step 3).
		const frame1 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 9, 0n, new Uint8Array([1]));
		const frame2 = await encryptAtStep(chainKey, epoch, senderPeerIndex, 3, 1n, new Uint8Array([2]));
		await Promise.allSettled([decodeFrame(receiver, frame1), decodeFrame(receiver, frame2)]);

		// No leaked promises after mixed concurrent settle.
		expect(receiver.ratchetPromises.size).toBe(0);
	});
});
