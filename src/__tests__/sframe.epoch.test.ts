// SFrame epoch-lifecycle integration tests — M3.4 (Phase 4 Rooms).
//
// Scenario 3 — Ratchet forward: epoch-0 frames decrypt within grace window;
//              rejected with stale_epoch after grace expiry. Epoch-1 frames
//              decrypt before and after grace.
// Scenario 4 — Epoch invalidation: currentMinValidEpoch advances correctly
//              after multi-epoch rotation.
// Scenario 5 — drainPreEpochQueue re-entrancy guard.
//
// Uses vi.useFakeTimers() + advanceTimersByTimeAsync(2001) to drive the 2 s
// grace-window wipe (spec §7.4, GRACE_WINDOW_MS = 2000). Always reset in
// try/finally to avoid cross-test contamination.
//
// HARNESS: Direct encodeFrame / decodeFrame on WorkerState (stream-pipeline
// fallback per preamble in sframe.integration.test.ts — fake timers and
// TransformStream backpressure interact poorly).

import { describe, it, expect, vi, afterEach } from 'vitest';
import { randomChainKey } from '../ratchet-crypto.ts';
import { createWorkerState, handleMessage, installEpoch } from '../worker-state.ts';
import { encodeFrame, decodeFrame, drainPreEpochQueue } from '../worker-frame.ts';
import type { OutMsg } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { StaleEpochError } from '../errors.ts';
import { makeFrame, makeBundles } from './helpers.ts';

const PEER_MAP: Record<string, PeerIndex> = { alice: 0, bob: 1 };

// ---------------------------------------------------------------------------
// Scenario 3: Ratchet forward preserves decrypt within grace; rejects after
// ---------------------------------------------------------------------------

describe('Scenario 3: ratchet forward + grace window', () => {
	afterEach(() => { vi.useRealTimers(); });

	it('epoch-0 frame decrypts within grace window after rotating to epoch 1', async () => {
		vi.useFakeTimers();
		try {
			const emitted: OutMsg[] = [];
			const sender = createWorkerState((_m) => {});
			const receiver = createWorkerState((m) => emitted.push(m));
			const ck0 = randomChainKey();
			const ck1 = randomChainKey();

			const b0 = await makeBundles(ck0, 0, PEER_MAP);
			await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b0 });
			await handleMessage(receiver, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b0 });

			const txA = makeFrame(new TextEncoder().encode('frame A — epoch 0'));
			await encodeFrame(sender, txA);

			const b1 = await makeBundles(ck1, 1, PEER_MAP);
			await handleMessage(sender, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b1 });
			await handleMessage(receiver, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b1 });

			const txB = makeFrame(new TextEncoder().encode('frame B — epoch 1'));
			await encodeFrame(sender, txB);

			// Within grace: epoch-0 frame A still decrypts
			const rxA = makeFrame(new Uint8Array(txA.data));
			await decodeFrame(receiver, rxA);
			expect(new Uint8Array(rxA.data)).toEqual(new TextEncoder().encode('frame A — epoch 0'));

			// Epoch-1 frame B also decrypts within grace
			const rxB = makeFrame(new Uint8Array(txB.data));
			await decodeFrame(receiver, rxB);
			expect(new Uint8Array(rxB.data)).toEqual(new TextEncoder().encode('frame B — epoch 1'));

			expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
		} finally {
			vi.useRealTimers();
		}
	});

	it('epoch-0 frame rejected with stale_epoch after grace window expires', async () => {
		vi.useFakeTimers();
		try {
			const emitted: OutMsg[] = [];
			const sender = createWorkerState((_m) => {});
			const receiver = createWorkerState((m) => emitted.push(m));
			const ck0 = randomChainKey();
			const ck1 = randomChainKey();

			const b0 = await makeBundles(ck0, 0, PEER_MAP);
			await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b0 });
			await handleMessage(receiver, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b0 });

			// Encrypt frame A BEFORE epoch advance (sender CTR at 0)
			const txA = makeFrame(new TextEncoder().encode('stale payload'));
			await encodeFrame(sender, txA);

			const b1 = await makeBundles(ck1, 1, PEER_MAP);
			await handleMessage(receiver, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b1 });

			expect(receiver.currentMinValidEpoch).toBe(0);
			await vi.advanceTimersByTimeAsync(2001);
			expect(receiver.currentMinValidEpoch).toBe(1);

			const rxA = makeFrame(new Uint8Array(txA.data));
			await expect(decodeFrame(receiver, rxA)).rejects.toThrow(StaleEpochError);
			expect(
				emitted.some((m) => m.type === 'decrypt_failure' && m.reason === 'stale_epoch'),
			).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it('epoch-1 frame decrypts correctly before AND after grace window expiry', async () => {
		vi.useFakeTimers();
		try {
			const emitted: OutMsg[] = [];
			const sender = createWorkerState((_m) => {});
			const receiver = createWorkerState((m) => emitted.push(m));
			const ck0 = randomChainKey();
			const ck1 = randomChainKey();

			const b0 = await makeBundles(ck0, 0, PEER_MAP);
			await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b0 });
			await handleMessage(receiver, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b0 });

			const b1 = await makeBundles(ck1, 1, PEER_MAP);
			await handleMessage(sender, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b1 });
			await handleMessage(receiver, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b1 });

			const txB = makeFrame(new TextEncoder().encode('frame B epoch 1'));
			await encodeFrame(sender, txB);

			await vi.advanceTimersByTimeAsync(2001);
			expect(receiver.currentMinValidEpoch).toBe(1);

			const rxB = makeFrame(new Uint8Array(txB.data));
			await decodeFrame(receiver, rxB);
			expect(new Uint8Array(rxB.data)).toEqual(new TextEncoder().encode('frame B epoch 1'));
			expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
		} finally {
			vi.useRealTimers();
		}
	});
});

// ---------------------------------------------------------------------------
// Scenario 4: Epoch invalidation — currentMinValidEpoch advancement
// ---------------------------------------------------------------------------

describe('Scenario 4: epoch invalidation', () => {
	afterEach(() => { vi.useRealTimers(); });

	it('install epoch 0 then 1: epoch-0 frames rejected after grace', async () => {
		vi.useFakeTimers();
		try {
			const emitted: OutMsg[] = [];
			const sender = createWorkerState((_m) => {});
			const receiver = createWorkerState((m) => emitted.push(m));
			const ck0 = randomChainKey();
			const ck1 = randomChainKey();

			const b0 = await makeBundles(ck0, 0, PEER_MAP);
			await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b0 });
			await handleMessage(receiver, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b0 });

			const txE0 = makeFrame(new TextEncoder().encode('epoch 0 frame'));
			await encodeFrame(sender, txE0);
			const sealedE0 = new Uint8Array(txE0.data);

			const b1 = await makeBundles(ck1, 1, PEER_MAP);
			await handleMessage(receiver, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b1 });

			expect(receiver.currentMinValidEpoch).toBe(0);
			await vi.advanceTimersByTimeAsync(2001);
			expect(receiver.currentMinValidEpoch).toBe(1);

			const rxE0 = makeFrame(sealedE0);
			await expect(decodeFrame(receiver, rxE0)).rejects.toThrow(StaleEpochError);
			expect(
				emitted.some((m) => m.type === 'decrypt_failure' && m.reason === 'stale_epoch'),
			).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it('currentMinValidEpoch advances to highest wiped epoch + 1', async () => {
		vi.useFakeTimers();
		try {
			const receiver = createWorkerState((_m) => {});
			for (const epoch of [0, 1, 2]) {
				const b = await makeBundles(randomChainKey(), epoch, PEER_MAP);
				await handleMessage(receiver, { type: 'epoch', epoch, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b });
			}
			expect(receiver.currentMinValidEpoch).toBe(0);
			await vi.advanceTimersByTimeAsync(2001);
			expect(receiver.currentMinValidEpoch).toBe(2);
		} finally {
			vi.useRealTimers();
		}
	});

	it('epoch 0+1 rejected, epoch 2 accepted after two rotations', async () => {
		vi.useFakeTimers();
		try {
			const emitted: OutMsg[] = [];
			// Use a fresh sender per epoch so installEpoch always advances
			// currentEpoch (re-installing a lower epoch on an existing sender is a no-op).
			const ck0 = randomChainKey();
			const ck1 = randomChainKey();
			const ck2 = randomChainKey();
			const b0 = await makeBundles(ck0, 0, PEER_MAP);
			const b1 = await makeBundles(ck1, 1, PEER_MAP);
			const b2 = await makeBundles(ck2, 2, PEER_MAP);

			// Encrypt one frame per epoch with a dedicated sender at that epoch
			const sender0 = createWorkerState((_m) => {});
			await handleMessage(sender0, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b0 });
			const txE0 = makeFrame(new TextEncoder().encode('payload e0'));
			await encodeFrame(sender0, txE0);
			const sealedE0 = new Uint8Array(txE0.data);

			const sender1 = createWorkerState((_m) => {});
			await handleMessage(sender1, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b1 });
			const txE1 = makeFrame(new TextEncoder().encode('payload e1'));
			await encodeFrame(sender1, txE1);
			const sealedE1 = new Uint8Array(txE1.data);

			const sender2 = createWorkerState((_m) => {});
			await handleMessage(sender2, { type: 'epoch', epoch: 2, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b2 });
			const txE2 = makeFrame(new TextEncoder().encode('payload e2'));
			await encodeFrame(sender2, txE2);
			const sealedE2 = new Uint8Array(txE2.data);

			// Install all three epochs on receiver in order
			const receiver = createWorkerState((m) => emitted.push(m));
			await handleMessage(receiver, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b0 });
			await handleMessage(receiver, { type: 'epoch', epoch: 1, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b1 });
			await handleMessage(receiver, { type: 'epoch', epoch: 2, peerIndexMap: PEER_MAP, selfPeerIndex: 1, keys: b2 });

			// Expire grace (wipes epochs 0 and 1)
			await vi.advanceTimersByTimeAsync(2001);
			expect(receiver.currentMinValidEpoch).toBe(2);

			// Epoch 0 and 1 rejected
			await expect(decodeFrame(receiver, makeFrame(sealedE0))).rejects.toThrow(StaleEpochError);
			await expect(decodeFrame(receiver, makeFrame(sealedE1))).rejects.toThrow(StaleEpochError);

			// Epoch 2 accepted
			const rxE2 = makeFrame(sealedE2);
			await decodeFrame(receiver, rxE2);
			expect(new Uint8Array(rxE2.data)).toEqual(new TextEncoder().encode('payload e2'));

			const failures = emitted.filter((m) => m.type === 'decrypt_failure');
			expect(failures.every((m) => m.type === 'decrypt_failure' && m.reason === 'stale_epoch')).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});
});

// ---------------------------------------------------------------------------
// Scenario 5: drainPreEpochQueue re-entrancy guard
// ---------------------------------------------------------------------------

describe('Scenario 5: drainPreEpochQueue re-entrant drain guard', () => {
	it('WorkerState exposes draining flag, initialised false', () => {
		// RED: WorkerState must have a `draining: boolean` field, set to false
		// on creation. This field is the re-entrancy guard; without it the type
		// check below will fail to compile.
		const state = createWorkerState((_m) => {});
		expect(state.draining).toBe(false);
	});

	it('draining flag is true while drain is in progress, false after', async () => {
		// Verify the flag is set during execution and cleared in the finally block.
		const sender = createWorkerState((_m) => {});
		const receiver = createWorkerState((_m) => {});

		const ck = randomChainKey();
		const b = await makeBundles(ck, 0, PEER_MAP);
		await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b });
		installEpoch(receiver, 0, 1, b);

		const frame = makeFrame(new TextEncoder().encode('drain-flag-test'));
		await encodeFrame(sender, frame);
		receiver.preEpochQueue.push({ frame: makeFrame(new Uint8Array(frame.data)) });

		expect(receiver.draining).toBe(false);
		const drainPromise = drainPreEpochQueue(receiver);
		// On the microtask after the synchronous part of drainPreEpochQueue
		// starts, draining is true.
		expect(receiver.draining).toBe(true);
		await drainPromise;
		expect(receiver.draining).toBe(false);
	});

	it('concurrent second drain call returns early without re-entering', async () => {
		// With the draining guard: if drain1 starts and drain2 is called before
		// drain1 awaits, drain2 must return immediately (draining === true).
		// Observable: drain2 resolves in the same microtask tick as it is called,
		// before drain1 has finished. We verify by checking that draining is still
		// true when drain2 resolves (drain1 holds the lock).
		const sender = createWorkerState((_m) => {});
		const receiver = createWorkerState((_m) => {});

		const ck = randomChainKey();
		const b = await makeBundles(ck, 0, PEER_MAP);
		await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b });
		installEpoch(receiver, 0, 1, b);

		const frame = makeFrame(new TextEncoder().encode('guard-test'));
		await encodeFrame(sender, frame);
		receiver.preEpochQueue.push({ frame: makeFrame(new Uint8Array(frame.data)) });

		let drain2SeenDraining = false;
		const drain1 = drainPreEpochQueue(receiver);
		// drain1 is now in progress (draining === true). drain2 must return early.
		const drain2 = drainPreEpochQueue(receiver).then(() => {
			// If guard works, draining is still true (drain1 still running).
			drain2SeenDraining = receiver.draining;
		});

		await Promise.all([drain1, drain2]);

		// drain2 resolved while drain1 was still running → draining was true.
		expect(drain2SeenDraining).toBe(true);
		// Everything still cleared after both settle.
		expect(receiver.preEpochQueue).toHaveLength(0);
		expect(receiver.draining).toBe(false);
	});

	it('frame pushed mid-drain stays in queue until next installEpoch drain (single-pass contract)', async () => {
		// Single-pass drain: frames pushed to preEpochQueue during an active drain
		// are NOT consumed in the same drain call — they wait for the next
		// installEpoch-triggered drain. This eliminates the livelock where
		// re-enqueued frames (no key yet) kept the while-loop spinning forever.
		const emitted: OutMsg[] = [];
		const sender = createWorkerState((_m) => {});
		const receiver = createWorkerState((m) => emitted.push(m));

		const ck = randomChainKey();
		const b = await makeBundles(ck, 0, PEER_MAP);
		await handleMessage(sender, { type: 'epoch', epoch: 0, peerIndexMap: PEER_MAP, selfPeerIndex: 0, keys: b });
		installEpoch(receiver, 0, 1, b);

		const fa = makeFrame(new TextEncoder().encode('mid-drain-a'));
		const fb = makeFrame(new TextEncoder().encode('mid-drain-b'));
		await encodeFrame(sender, fa);
		await encodeFrame(sender, fb);

		// Load frame A into the pre-epoch queue.
		receiver.preEpochQueue.push({ frame: makeFrame(new Uint8Array(fa.data)) });

		// Start drain. The single-pass snapshots only frame A.
		const drainPromise = drainPreEpochQueue(receiver);
		// Push B while drain is running (draining === true) — it lands in queue
		// but is NOT in the snapshot already taken by this drain call.
		receiver.preEpochQueue.push({ frame: makeFrame(new Uint8Array(fb.data)) });

		await drainPromise;

		// Single-pass: drain consumed A, B remains for the next drain call.
		expect(receiver.preEpochQueue).toHaveLength(1);
		expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);

		// A second drain (e.g. triggered by next installEpoch) picks up B.
		await drainPreEpochQueue(receiver);
		expect(receiver.preEpochQueue).toHaveLength(0);
	});
});
