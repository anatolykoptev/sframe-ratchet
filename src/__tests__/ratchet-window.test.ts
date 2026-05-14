// Tests for the within-epoch ratchet retry window on the decode path.
//
// When a sender advances their per-sender key by N steps (e.g. after a
// forward-secrecy step within an epoch) and in-flight frames carry the OLD key
// index, the receiver's window tries up to ratchetWindowSize derivation steps
// before declaring failure. This is a liveness feature — see SECURITY.md for
// why it does NOT widen attacker decryptability.
//
// Distinct from:
//   - preEpochQueue (handles "no epoch yet" — covered in worker-frame-queue.test.ts)
//   - epoch rotation (covers join/leave — covered in sframe.epoch.test.ts)

import { describe, it, expect } from 'vitest';
import { createWorkerState, installEpoch, handleMessage } from '../worker-state.ts';
import { encodeFrame, decodeFrame } from '../worker-frame.ts';
import { deriveSenderKeys, deriveNextSenderKey, randomChainKey, deriveEpochKeyTable } from '../ratchet-crypto.ts';
import { sframeEncrypt } from '../sframe.ts';
import type { OutMsg, PerSenderKeyBundle } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Build a PerSenderKeyBundle for a single sender at the INITIAL ratchet step.
 * rawKey is returned so callers can advance the sender-side key independently.
 */
async function makeBundle(
	chainKey: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
): Promise<PerSenderKeyBundle & { rawKey: Uint8Array }> {
	const k = await deriveSenderKeys(chainKey, epoch, peerIndex);
	return { cryptoKey: k.cryptoKey, salt: k.salt, rawKey: k.rawKey };
}

async function makeBundles(
	chainKey: Uint8Array,
	epoch: number,
	peerIndexMap: Record<string, PeerIndex>,
): Promise<Map<PeerIndex, PerSenderKeyBundle>> {
	const table = await deriveEpochKeyTable(chainKey, epoch, peerIndexMap);
	const out = new Map<PeerIndex, PerSenderKeyBundle>();
	for (const [pi, k] of table) out.set(pi, { cryptoKey: k.cryptoKey, salt: k.salt, rawKey: k.rawKey });
	return out;
}

/**
 * Advance exactly `steps` times from the given raw key and return the key AT step `steps`.
 * For steps=0 this reconstructs the current key (shouldn't be needed; for steps>=1 it
 * chains that many times).
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

function makeFrame(body: Uint8Array): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}

function collectErrors(state: ReturnType<typeof createWorkerState>): OutMsg[] {
	const collected: OutMsg[] = [];
	const originalEmit = state.emit;
	(state as unknown as Record<string, unknown>).emit = (msg: OutMsg) => {
		collected.push(msg);
		originalEmit(msg);
	};
	return collected;
}

// ---------------------------------------------------------------------------
// Scenario 1: sender advances 1 step; in-flight frame at step 0 decrypts via retry
// ---------------------------------------------------------------------------

describe('ratchet window — 1-step advance', () => {
	it('decrypts a frame encrypted with step-0 key after sender advanced to step 1', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		// Build the initial bundle (step 0) for both sender and receiver.
		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		// Receiver: install epoch with step-0 keys.
		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		installEpoch(receiver, epoch, senderPeerIndex, bundles);
		// Receiver state is now at step 0.

		// Sender: advance 1 step (the sender's side — they have a newer key).
		// But the in-flight frame was encrypted with step-0 key (initialBundle).
		// We simulate an in-flight frame: encrypt with the step-0 key.
		const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
		const sframeKey = await deriveSenderKeys(chainKey, epoch, senderPeerIndex);
		const ciphertext = await sframeEncrypt(plaintext, sframeKey, 0n);
		const frame = makeFrame(ciphertext);

		// Receiver is still at step 0 → direct decrypt succeeds (no retry needed).
		await decodeFrame(receiver, frame);
		const decoded = new Uint8Array(frame.data);
		expect(decoded).toEqual(plaintext);
		expect(errors).toHaveLength(0);
	});

	it('decrypts when receiver has MISSED a key advance — sender is at step 1, receiver at step 0', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		installEpoch(receiver, epoch, senderPeerIndex, bundles);
		// Receiver is at step 0.

		// Sender advanced to step 1 and now encrypts a frame with step-1 key.
		const step1key = await advanceSenderKeyFrom(initialBundle.rawKey, initialBundle.salt, epoch, senderPeerIndex, 1);
		const plaintext = new Uint8Array([10, 20, 30]);
		// Use a minimal SFrameKey shape for encryption.
		const { makeKid } = await import('../ratchet-ids.ts');
		const senderSFrameKey = {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step1key.cryptoKey,
			salt: step1key.salt,
		};
		const ciphertext = await sframeEncrypt(plaintext, senderSFrameKey, 0n);
		const frame = makeFrame(ciphertext);

		// decodeFrame: step-0 key fails, retry finds step 1, succeeds.
		await decodeFrame(receiver, frame);
		const decoded = new Uint8Array(frame.data);
		expect(decoded).toEqual(plaintext);
		expect(errors).toHaveLength(0);

		// Receiver's cached key should now be at step 1.
		const entry = receiver.epochs.get(epoch);
		expect(entry).toBeDefined();
		const ratchetStep = entry!.ratchetSteps.get(senderPeerIndex) ?? 0;
		expect(ratchetStep).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// Scenario 2: sender advances 3 steps; receiver catches up; subsequent frames
//             at step 3 decrypt immediately (cached step advanced)
// ---------------------------------------------------------------------------

describe('ratchet window — 3-step advance + caching', () => {
	it('catches up to step 3 and subsequent frames hit the cached key directly', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Sender is at step 3.
		const step3key = await advanceSenderKeyFrom(initialBundle.rawKey, initialBundle.salt, epoch, senderPeerIndex, 3);
		const { makeKid } = await import('../ratchet-ids.ts');
		const makeSFrameKey = (key: typeof step3key) => ({
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: key.cryptoKey,
			salt: key.salt,
		});

		const plaintext1 = new Uint8Array([1, 1, 1]);
		const ct1 = await sframeEncrypt(plaintext1, makeSFrameKey(step3key), 0n);
		const frame1 = makeFrame(ct1);

		// First frame at step 3: receiver retries 1, 2, 3 before succeeding.
		await decodeFrame(receiver, frame1);
		expect(new Uint8Array(frame1.data)).toEqual(plaintext1);
		expect(errors).toHaveLength(0);

		// Cached step should now be 3.
		const entry = receiver.epochs.get(epoch);
		expect(entry!.ratchetSteps.get(senderPeerIndex)).toBe(3);

		// Second frame also at step 3: cached key used, no retry loop.
		const plaintext2 = new Uint8Array([2, 2, 2]);
		const ct2 = await sframeEncrypt(plaintext2, makeSFrameKey(step3key), 1n);
		const frame2 = makeFrame(ct2);
		await decodeFrame(receiver, frame2);
		expect(new Uint8Array(frame2.data)).toEqual(plaintext2);
		expect(errors).toHaveLength(0);
		// Step cursor unchanged — still 3.
		expect(entry!.ratchetSteps.get(senderPeerIndex)).toBe(3);
	});
});

// ---------------------------------------------------------------------------
// Scenario 3: sender advances 9 steps with window=8 → failure, error surfaced
// ---------------------------------------------------------------------------

describe('ratchet window — exhaustion', () => {
	it('surfaces decrypt_failed when sender is 9 steps ahead and window=8', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		// Default window = 8.
		expect(receiver.ratchetWindowSize).toBe(8);
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Sender at step 9 (1 beyond the window).
		const step9key = await advanceSenderKeyFrom(initialBundle.rawKey, initialBundle.salt, epoch, senderPeerIndex, 9);
		const { makeKid } = await import('../ratchet-ids.ts');
		const sFrameKey = {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step9key.cryptoKey,
			salt: step9key.salt,
		};
		const ciphertext = await sframeEncrypt(new Uint8Array([9, 9, 9]), sFrameKey, 0n);
		const frame = makeFrame(ciphertext);

		await expect(decodeFrame(receiver, frame)).rejects.toThrow();
		// decrypt_failure event must have been emitted.
		const failure = errors.find((e) => e.type === 'decrypt_failure');
		expect(failure).toBeDefined();
		expect((failure as { reason: string }).reason).toBe('decrypt_failed');
	});
});

// ---------------------------------------------------------------------------
// Scenario 4: window=0 → any mismatch fails immediately, no retry
// ---------------------------------------------------------------------------

describe('ratchet window — disabled (size=0)', () => {
	it('fails immediately with no retry when ratchetWindowSize=0', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		receiver.ratchetWindowSize = 0;
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Sender at step 1 — even a 1-step mismatch fails immediately when window=0.
		const step1key = await advanceSenderKeyFrom(initialBundle.rawKey, initialBundle.salt, epoch, senderPeerIndex, 1);
		const { makeKid } = await import('../ratchet-ids.ts');
		const sFrameKey = {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step1key.cryptoKey,
			salt: step1key.salt,
		};
		const ciphertext = await sframeEncrypt(new Uint8Array([1, 2]), sFrameKey, 0n);
		const frame = makeFrame(ciphertext);

		await expect(decodeFrame(receiver, frame)).rejects.toThrow();
		// Error must have been emitted.
		expect(errors.some((e) => e.type === 'decrypt_failure')).toBe(true);
		// Cached ratchet step must stay at 0 (no advances were tried).
		const entry = receiver.epochs.get(epoch);
		const step = entry?.ratchetSteps.get(senderPeerIndex) ?? 0;
		expect(step).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// Scenario 5: set-ratchet-window control message changes behaviour mid-stream
// ---------------------------------------------------------------------------

describe('set-ratchet-window control message', () => {
	it('adjusts ratchetWindowSize at runtime', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const state = createWorkerState((m) => errors.push(m));
		installEpoch(state, epoch, senderPeerIndex, bundles);
		expect(state.ratchetWindowSize).toBe(8); // default

		// Reduce window to 1 via control message.
		await handleMessage(state, { type: 'set-ratchet-window', size: 1 });
		expect(state.ratchetWindowSize).toBe(1);

		// Sender at step 2 — should fail with window=1.
		const step2key = await advanceSenderKeyFrom(initialBundle.rawKey, initialBundle.salt, epoch, senderPeerIndex, 2);
		const { makeKid } = await import('../ratchet-ids.ts');
		const sFrameKey2 = {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step2key.cryptoKey,
			salt: step2key.salt,
		};
		const ct2 = await sframeEncrypt(new Uint8Array([2, 2]), sFrameKey2, 0n);
		await expect(decodeFrame(state, makeFrame(ct2))).rejects.toThrow();
		const fail2 = errors.find((e) => e.type === 'decrypt_failure');
		expect(fail2).toBeDefined();

		errors.length = 0;

		// Expand window to 3 via control message.
		await handleMessage(state, { type: 'set-ratchet-window', size: 3 });
		expect(state.ratchetWindowSize).toBe(3);

		// Re-install epoch so ratchetSteps resets (simulate fresh frame stream).
		installEpoch(state, epoch, senderPeerIndex, bundles);

		// Sender at step 2 — should now succeed with window=3.
		const ct2b = await sframeEncrypt(new Uint8Array([2, 2]), sFrameKey2, 1n);
		const frame2b = makeFrame(ct2b);
		await decodeFrame(state, frame2b);
		expect(new Uint8Array(frame2b.data)).toEqual(new Uint8Array([2, 2]));
		expect(errors.filter((e) => e.type === 'decrypt_failure')).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// Scenario 6: retry does NOT cross epoch boundaries
// ---------------------------------------------------------------------------

describe('ratchet window — no cross-epoch retry', () => {
	it('a frame from a different epoch fails normally without consuming retry budget', async () => {
		const chainKey0 = randomChainKey();
		const chainKey1 = randomChainKey();
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		// Receiver only knows epoch 0.
		const bundles0 = await makeBundles(chainKey0, 0, peerIndexMap);
		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		installEpoch(receiver, 0, senderPeerIndex, bundles0);

		// Frame encrypted under epoch 1 (receiver has no epoch-1 key).
		const key1 = await deriveSenderKeys(chainKey1, 1, senderPeerIndex);
		const { makeKid } = await import('../ratchet-ids.ts');
		const sFrameKey1 = {
			kid: makeKid(1, senderPeerIndex),
			epoch: 1,
			peerIndex: senderPeerIndex,
			cryptoKey: key1.cryptoKey,
			salt: key1.salt,
		};
		const ciphertext = await sframeEncrypt(new Uint8Array([7, 8, 9]), sFrameKey1, 0n);
		const frame = makeFrame(ciphertext);

		await expect(decodeFrame(receiver, frame)).rejects.toThrow();
		// Failure should be decrypt_failed (key not found for epoch 1).
		const fail = errors.find((e) => e.type === 'decrypt_failure');
		expect(fail).toBeDefined();
		// Epoch 0's ratchet step cursor must be unaffected.
		const entry0 = receiver.epochs.get(0);
		const step0 = entry0?.ratchetSteps.get(senderPeerIndex) ?? 0;
		expect(step0).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// Scenario 7: pathological — older frame after advance fails without breakage
// ---------------------------------------------------------------------------

describe('ratchet window — pathological older frame', () => {
	it('an out-of-order frame from before the advance fails gracefully; state intact', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const initialBundle = await makeBundle(chainKey, epoch, senderPeerIndex);
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Simulate receiver already caught up to step 2 (a previous successful decode advanced it).
		const step2key = await advanceSenderKeyFrom(initialBundle.rawKey, initialBundle.salt, epoch, senderPeerIndex, 2);
		const { makeKid } = await import('../ratchet-ids.ts');
		const step2SFrameKey = {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step2key.cryptoKey,
			salt: step2key.salt,
		};
		// Manually advance receiver's cached key to step 2 to simulate prior catch-up.
		const entry = receiver.epochs.get(epoch)!;
		entry.keys.set(senderPeerIndex, {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step2key.cryptoKey,
			salt: step2key.salt,
			rawKey: step2key.rawKey,
		});
		entry.ratchetSteps.set(senderPeerIndex, 2);

		// Now an OLD frame encrypted at step 0 arrives (out-of-order / reordered).
		// The step-0 key is no longer in cache. Retry tries steps 3..10 — none match.
		const step0key = await deriveSenderKeys(chainKey, epoch, senderPeerIndex);
		const step0SFrameKey = {
			kid: makeKid(epoch, senderPeerIndex),
			epoch,
			peerIndex: senderPeerIndex,
			cryptoKey: step0key.cryptoKey,
			salt: step0key.salt,
		};
		const oldCiphertext = await sframeEncrypt(new Uint8Array([0, 0, 0]), step0SFrameKey, 0n);
		const oldFrame = makeFrame(oldCiphertext);

		// Must fail without throwing an unhandled error and without corrupting state.
		await expect(decodeFrame(receiver, oldFrame)).rejects.toThrow();
		// decrypt_failed event emitted.
		expect(errors.some((e) => e.type === 'decrypt_failure')).toBe(true);
		// Ratchet step must remain at 2 (not advanced by the failed retry).
		// Note: the retry DID try steps 3..10 which further advances `currentRaw` internally,
		// but since none succeeded, the entry.ratchetSteps cursor is NOT bumped.
		expect(entry.ratchetSteps.get(senderPeerIndex)).toBe(2);

		// State is intact: a fresh valid frame at step 2 still decrypts.
		errors.length = 0;
		const ct2 = await sframeEncrypt(new Uint8Array([2, 2, 2]), step2SFrameKey, 1n);
		const frame2 = makeFrame(ct2);
		await decodeFrame(receiver, frame2);
		expect(new Uint8Array(frame2.data)).toEqual(new Uint8Array([2, 2, 2]));
		expect(errors.filter((e) => e.type === 'decrypt_failure')).toHaveLength(0);
	});
});
