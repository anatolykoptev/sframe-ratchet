// Tests for pre-epoch frame queue in worker-frame.ts.
// Spec: when decodeFrame fails because epoch is missing (no entry in state.epochs),
// the frame is queued in a bounded ring buffer (cap 50/peer) instead of dropped.
// When setEpoch drains the queue, frames are retried in FIFO order.
// Overflow (>50) drops oldest and bumps client.frame_decode_queue_overflow counter.
//
// These tests drive decodeFrame + drainQueue directly (no DOM / no real Worker).
// RED before implementation.

import { describe, it, expect } from 'vitest';
import { createWorkerState } from '../worker-state.ts';
import { decodeFrame, drainPreEpochQueue } from '../worker-frame.ts';
import { randomChainKey, deriveSenderKeys } from '../ratchet-crypto.ts';
import { sframeEncrypt } from '../sframe.ts';
import type { OutMsg } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { installEpoch } from '../worker-state.ts';
import { makeBundles } from './helpers.ts';

function makeEncryptedFrame(body: Uint8Array): RTCEncodedVideoFrame {
	// body is already an SFrame ciphertext — wrap in ArrayBuffer
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}

// --- tests -------------------------------------------------------------------

describe('pre-epoch frame queue', () => {
	it('frame arrives before epoch → queued, not thrown', async () => {
		// State has NO epoch installed.
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const ciphertext = await sframeEncrypt(new TextEncoder().encode('hello'), key, 0n);
		const frame = makeEncryptedFrame(ciphertext);

		// decodeFrame must NOT throw — it should queue the frame instead.
		await expect(decodeFrame(state, frame)).resolves.toBeUndefined();

		// No decrypt_failure should be emitted for epoch-missing frames.
		expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});

	it('setEpoch drains queue → frame decoded successfully', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const peerIndexMap = { alice: 0 as PeerIndex };
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		const plaintext = new TextEncoder().encode('hello-queued');
		const ciphertext = await sframeEncrypt(plaintext, key, 0n);
		const frame = makeEncryptedFrame(ciphertext);

		// Queue the frame (no epoch yet).
		await decodeFrame(state, frame);

		// Install epoch → drain.
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);
		await drainPreEpochQueue(state);

		// Frame data should now be the decrypted plaintext.
		expect(new TextDecoder().decode(new Uint8Array(frame.data))).toBe('hello-queued');
		expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});

	it('queue drains in FIFO order', async () => {
		const state = createWorkerState(() => {});

		const peerIndexMap = { alice: 0 as PeerIndex };
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		const frames: RTCEncodedVideoFrame[] = [];
		for (let i = 0; i < 3; i++) {
			const pt = new TextEncoder().encode(`frame-${i}`);
			const ct = await sframeEncrypt(pt, key, BigInt(i));
			frames.push(makeEncryptedFrame(ct));
		}

		// Queue all 3 in order.
		for (const f of frames) await decodeFrame(state, f);

		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);
		await drainPreEpochQueue(state);

		// After drain, each frame.data contains its own decrypted plaintext.
		const decoded = frames.map((f) => new TextDecoder().decode(new Uint8Array(f.data)));
		expect(decoded).toEqual(['frame-0', 'frame-1', 'frame-2']);
	});

	it('overflow: 60 frames queued → 50 kept (oldest dropped), counter bumped', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const peerIndexMap = { alice: 0 as PeerIndex };
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		const frames: RTCEncodedVideoFrame[] = [];
		for (let i = 0; i < 60; i++) {
			const pt = new TextEncoder().encode(`f${i}`);
			const ct = await sframeEncrypt(pt, key, BigInt(i));
			const frame = makeEncryptedFrame(ct);
			frames.push(frame);
			await decodeFrame(state, frame);
		}

		// 10 frames were dropped (oldest 0-9), counter emitted once per drop.
		const overflowEvents = emitted.filter(
			(m) => m.type === 'decrypt_failure' && (m as { type: string; reason: string }).reason === 'queue_overflow',
		);
		expect(overflowEvents).toHaveLength(10);

		// After drain, frames 10-59 (the 50 kept) should be decryptable.
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);
		await drainPreEpochQueue(state);

		// Frames 10-59 now have decrypted data; frames 0-9 were dropped (data unchanged = ciphertext).
		// We verify that frame 10 (first kept) decoded correctly.
		const frame10 = frames[10];
		expect(new TextDecoder().decode(new Uint8Array(frame10.data))).toBe('f10');

		const frame59 = frames[59];
		expect(new TextDecoder().decode(new Uint8Array(frame59.data))).toBe('f59');
	});

	// --- Round 2: drain re-enqueue cap + drain decrypt error emit ---

	it('drain re-enqueue respects cap: full queue re-enqueued via drain never exceeds cap', async () => {
		// Scenario: queue is at cap (50), epoch installed but wrong (epoch=1, frames are epoch=0).
		// Drain re-enqueues all 50. Without the fix, pushes bypass the cap check and
		// queue.length grows past 50.
		//
		// To verify overflow enforcement we overfill intentionally:
		//  1. Fill a fresh state to 60 epoch=0 frames (10 dropped, 50 kept).
		//  2. Reset state and directly push 55 entries into preEpochQueue bypassing cap
		//     (simulating the broken state), then verify drain re-enqueue via pushToQueue
		//     does NOT occur on a second partial drain.
		//
		// Simpler approach: fill to 50, drain with wrong epoch, confirm queue ≤ 50.
		// Then manually inject 10 more into preEpochQueue to exceed cap, drain again,
		// and confirm queue ≤ 50 + overflow events fired.
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		// Fill to cap.
		for (let i = 0; i < 50; i++) {
			const ct = await sframeEncrypt(new TextEncoder().encode(`f${i}`), key, BigInt(i));
			await decodeFrame(state, makeEncryptedFrame(ct));
		}
		expect(state.preEpochQueue.length).toBe(50);

		// Manually inject 10 more entries directly (simulates the buggy path where
		// re-enqueue bypassed cap — confirms pushToQueue enforces cap during drain).
		for (let i = 50; i < 60; i++) {
			const ct = await sframeEncrypt(new TextEncoder().encode(`f${i}`), key, BigInt(i));
			const frame = makeEncryptedFrame(ct);
			// Bypass enqueuePreEpoch to directly stuff queue past cap (regression setup).
			state.preEpochQueue.push({ frame });
		}
		expect(state.preEpochQueue.length).toBe(60); // deliberately over cap

		// Now drain with epoch=1 (still no epoch=0 key) → all 60 re-enqueued via pushToQueue.
		const bundles1 = await makeBundles(chainKey, 1, { alice: 0 as PeerIndex });
		installEpoch(state, 1, 1, bundles1);
		await drainPreEpochQueue(state);

		// Queue must be capped at 50; 10 overflow events fired.
		expect(state.preEpochQueue.length).toBeLessThanOrEqual(50);
		const overflowEvents = emitted.filter(
			(m) => m.type === 'decrypt_failure' && (m as { type: string; reason: string }).reason === 'queue_overflow',
		);
		expect(overflowEvents.length).toBeGreaterThanOrEqual(10);
	});

	it('drain emits decrypt_failure when decryption fails after epoch installed', async () => {
		// Frame encrypted with epoch=0/chainKeyA queued, then epoch=0 installed with
		// chainKeyB (wrong key) → decrypt fails → must emit decrypt_failure{reason:'decrypt_failed_after_epoch'}.
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKeyA = randomChainKey();
		const chainKeyB = randomChainKey();

		const keyA = await deriveSenderKeys(chainKeyA, 0, 0);
		const ct = await sframeEncrypt(new TextEncoder().encode('secret'), keyA, 0n);
		const frame = makeEncryptedFrame(ct);

		// Queue the frame (no epoch yet).
		await decodeFrame(state, frame);
		expect(state.preEpochQueue.length).toBe(1);

		// Install epoch=0 with the WRONG chain key → decrypt will fail.
		const wrongBundles = await makeBundles(chainKeyB, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0, wrongBundles);
		await drainPreEpochQueue(state);

		// Must emit decrypt_failure with reason 'decrypt_failed_after_epoch'.
		const failures = emitted.filter(
			(m) =>
				m.type === 'decrypt_failure' &&
				(m as { type: string; reason: string }).reason === 'decrypt_failed_after_epoch',
		);
		expect(failures).toHaveLength(1);
	});

	// --- Round 4: single-pass drain (livelock fix) ---

	it('drain exits after single pass even when no key arrives (no livelock)', async () => {
		// Scenario: frames queued for epoch=0, but only epoch=1 is ever installed.
		// With the old while-loop, re-enqueued frames keep the queue non-empty →
		// infinite spin. Single-pass fix must return, leaving frames in queue for
		// the next installEpoch to drain.
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		// Queue 3 epoch=0 frames.
		for (let i = 0; i < 3; i++) {
			const ct = await sframeEncrypt(new TextEncoder().encode(`f${i}`), key, BigInt(i));
			await decodeFrame(state, makeEncryptedFrame(ct));
		}
		expect(state.preEpochQueue.length).toBe(3);

		// Install epoch=1 (wrong — no epoch=0 key available).
		const bundles1 = await makeBundles(chainKey, 1, { alice: 0 as PeerIndex });
		installEpoch(state, 1, 1, bundles1);

		// Must resolve — must NOT spin forever.
		await drainPreEpochQueue(state);

		// Frames still in queue (epoch=0 key never arrived) — drain didn't discard them.
		expect(state.preEpochQueue.length).toBe(3);
		// No decrypt_failure emitted — frames were re-queued, not decrypt-failed.
		const failures = emitted.filter(
			(m) => m.type === 'decrypt_failure' && (m as { type: string; reason: string }).reason === 'decrypt_failed_after_epoch',
		);
		expect(failures).toHaveLength(0);
	});

	it('drain: re-queued frames are picked up by subsequent installEpoch drain', async () => {
		// After single-pass drain leaves frames in queue, a later installEpoch with
		// the correct epoch key must drain and decrypt them successfully.
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		const plaintext = new TextEncoder().encode('delayed');
		const ct = await sframeEncrypt(plaintext, key, 0n);
		const frame = makeEncryptedFrame(ct);

		await decodeFrame(state, frame);

		// First installEpoch with wrong epoch → drain should exit without decrypting.
		const bundles1 = await makeBundles(chainKey, 1, { alice: 0 as PeerIndex });
		installEpoch(state, 1, 1, bundles1);
		await drainPreEpochQueue(state);
		expect(state.preEpochQueue.length).toBe(1); // still waiting

		// Now correct epoch=0 arrives → drain succeeds.
		const bundles0 = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0, bundles0);
		await drainPreEpochQueue(state);

		expect(new TextDecoder().decode(new Uint8Array(frame.data))).toBe('delayed');
		expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});
});
