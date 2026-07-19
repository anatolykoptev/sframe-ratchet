// Decryption-failure-driven key invalidation tests (issue #14, pattern from
// livekit/client-sdk-js ParticipantKeyHandler.ts:58).
//
// These tests exercise the REAL decodeFrame / drainPreEpochQueue paths in
// src/worker-frame.ts — no hand-copied function-under-test. Each test encrypts
// a real SFrame frame (or a corrupt one to force an AEAD failure) and feeds it
// through the actual decode pipeline so the failure-invalidation gate runs in
// its true location (after parseHeader + stale-epoch gate + replay check,
// before tryDecryptWithRatchet).
//
// The suite goes RED if the failure-invalidation logic is removed from
// decodeFrame / drainPreEpochQueue:
//   - Test 1 (tolerance=0 → first failure invalidates) would attempt AEAD on
//     the second frame instead of dropping it with KeyInvalidError.
//   - Test 3 (tolerance=-1 → never invalidated) would throw KeyInvalidError.

import { describe, it, expect } from 'vitest';
import { createWorkerState, installEpoch, handleMessage } from '../worker-state.ts';
import { encodeFrame, decodeFrame, drainPreEpochQueue } from '../worker-frame.ts';
import { sframeEncrypt } from '../sframe.ts';
import { deriveSenderKeys, randomChainKey } from '../ratchet-crypto.ts';
import { makeKid } from '../ratchet-ids.ts';
import { serializeHeader } from '../sframe-header.ts';
import { AEADAuthError, KeyInvalidError, RatchetWindowExhaustedError } from '../errors.ts';
import type { OutMsg, PerSenderKeyBundle } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { makeFrame, makeBundle, makeBundles } from './helpers.ts';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Encrypt `plaintext` under (epoch, peerIndex) at the given CTR and wrap in a
 * frame mock. Uses the real sframeEncrypt so the wire format is authentic.
 */
async function encryptFrame(
	chainKey: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	ctr: bigint,
	plaintext: Uint8Array,
): Promise<RTCEncodedVideoFrame> {
	const k = await deriveSenderKeys(chainKey, epoch, peerIndex);
	const sFrameKey = {
		kid: makeKid(epoch, peerIndex),
		epoch,
		peerIndex,
		cryptoKey: k.cryptoKey,
		salt: k.salt,
	};
	const ciphertext = await sframeEncrypt(plaintext, sFrameKey, ctr);
	return makeFrame(ciphertext);
}

/**
 * Build a frame whose SFrame header is valid (correct epoch/peerIndex/ctr) but
 * whose ciphertext body is garbage — guaranteed to fail AEAD authentication
 * with the installed key. This exercises the real AEAD-failure path.
 */
async function corruptFrame(
	chainKey: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	ctr: bigint,
): Promise<RTCEncodedVideoFrame> {
	const k = await deriveSenderKeys(chainKey, epoch, peerIndex);
	const kid = makeKid(epoch, peerIndex);
	const header = serializeHeader(kid, ctr);
	// 32 bytes of garbage ciphertext + 16-byte tag region — all random. The
	// header is valid so parseHeader succeeds; the AEAD tag will not verify.
	const garbage = new Uint8Array(header.length + 48);
	garbage.set(header, 0);
	// Fill the body with non-zero bytes (crypto.getRandomValues not needed —
	// any bytes will fail auth since the key never encrypted them).
	for (let i = header.length; i < garbage.length; i++) garbage[i] = (i * 7) & 0xff;
	// Reference k to avoid unused-var lint; the key derivation is what makes
	// the header's epoch/peerIndex match the installed key table.
	void k;
	return makeFrame(garbage);
}

function collectMessages(state: ReturnType<typeof createWorkerState>): OutMsg[] {
	const collected: OutMsg[] = [];
	const originalEmit = state.emit;
	(state as unknown as Record<string, unknown>).emit = (msg: OutMsg) => {
		collected.push(msg);
		originalEmit(msg);
	};
	return collected;
}

function failureReasons(msgs: OutMsg[]): string[] {
	return msgs
		.filter((m) => m.type === 'decrypt_failure')
		.map((m) => (m as { reason: string }).reason);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('decryption-failure-driven key invalidation (issue #14)', () => {
	it('Test 1: tolerance=0 — first AEAD failure marks key invalid; next frame dropped without AEAD', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		// tolerance=0 → invalidate on the first AEAD failure.
		receiver.failureTolerance = 0;
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// First frame: corrupt ciphertext → AEAD failure → key marked invalid.
		const bad1 = await corruptFrame(chainKey, epoch, senderPeerIndex, 0n);
		await expect(decodeFrame(receiver, bad1)).rejects.toSatisfy(
			(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
		);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(1);

		// Second frame: a VALID ciphertext at a fresh CTR. Because the key is
		// now invalid (count 1 > tolerance 0), it must be dropped WITHOUT
		// attempting AEAD — KeyInvalidError, not a successful decrypt.
		const good = await encryptFrame(chainKey, epoch, senderPeerIndex, 1n, new Uint8Array([1, 2, 3]));
		await expect(decodeFrame(receiver, good)).rejects.toBeInstanceOf(KeyInvalidError);

		// A decrypt_failure with reason 'key_invalid' must have been emitted.
		expect(failureReasons(errors)).toContain('key_invalid');
		// The valid frame's data must NOT have been decrypted (untouched).
		// (decodeFrame does not overwrite frame.data on the drop path.)
	});

	it('Test 2: tolerance=2 — key invalid only after 3 failures', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		receiver.failureTolerance = 2;
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Two AEAD failures — key still valid (count 2 is NOT > tolerance 2).
		// Use distinct CTRs so the replay window does not reject them.
		const bad1 = await corruptFrame(chainKey, epoch, senderPeerIndex, 0n);
		await expect(decodeFrame(receiver, bad1)).rejects.toSatisfy(
			(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
		);
		const bad2 = await corruptFrame(chainKey, epoch, senderPeerIndex, 1n);
		await expect(decodeFrame(receiver, bad2)).rejects.toSatisfy(
			(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
		);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(2);
		// Not yet invalid — a valid frame should still decrypt.
		expect(failureReasons(errors)).not.toContain('key_invalid');

		const good = await encryptFrame(chainKey, epoch, senderPeerIndex, 2n, new Uint8Array([9, 9]));
		await decodeFrame(receiver, good);
		expect(new Uint8Array(good.data)).toEqual(new Uint8Array([9, 9]));
		// recordSuccess resets the count.
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(0);

		// Now three consecutive failures (3 > 2) → invalid.
		const bad3 = await corruptFrame(chainKey, epoch, senderPeerIndex, 3n);
		await expect(decodeFrame(receiver, bad3)).rejects.toSatisfy(
			(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
		);
		const bad4 = await corruptFrame(chainKey, epoch, senderPeerIndex, 4n);
		await expect(decodeFrame(receiver, bad4)).rejects.toSatisfy(
			(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
		);
		const bad5 = await corruptFrame(chainKey, epoch, senderPeerIndex, 5n);
		await expect(decodeFrame(receiver, bad5)).rejects.toSatisfy(
			(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
		);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(3);

		// Next frame is dropped with KeyInvalidError (no AEAD attempt).
		const next = await encryptFrame(chainKey, epoch, senderPeerIndex, 6n, new Uint8Array([1]));
		await expect(decodeFrame(receiver, next)).rejects.toBeInstanceOf(KeyInvalidError);
		expect(failureReasons(errors)).toContain('key_invalid');
	});

	it('Test 3: tolerance=-1 (default) — key is never invalidated (unlimited failures)', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		// Default tolerance = -1 (unlimited).
		expect(receiver.failureTolerance).toBe(-1);
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Many AEAD failures — key never invalidated.
		for (let i = 0; i < 10; i++) {
			const bad = await corruptFrame(chainKey, epoch, senderPeerIndex, BigInt(i));
			await expect(decodeFrame(receiver, bad)).rejects.toSatisfy(
				(err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError,
			);
		}
		// No tracking when tolerance < 0.
		expect(receiver.failureCounts.size).toBe(0);
		expect(failureReasons(errors)).not.toContain('key_invalid');

		// A valid frame still decrypts (no invalidation).
		const good = await encryptFrame(chainKey, epoch, senderPeerIndex, 100n, new Uint8Array([5]));
		await decodeFrame(receiver, good);
		expect(new Uint8Array(good.data)).toEqual(new Uint8Array([5]));
	});

	it('Test 4: a successful decrypt resets the failure count', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState(() => {});
		receiver.failureTolerance = 2;
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Two failures (count=2, not yet invalid since 2 is not > 2).
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, epoch, senderPeerIndex, 0n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, epoch, senderPeerIndex, 1n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(2);

		// A successful decrypt resets the count to 0.
		const good = await encryptFrame(chainKey, epoch, senderPeerIndex, 2n, new Uint8Array([1]));
		await decodeFrame(receiver, good);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(0);

		// Now two more failures are needed again (not one) to invalidate.
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, epoch, senderPeerIndex, 3n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		// count=1, still valid — a valid frame decrypts.
		const good2 = await encryptFrame(chainKey, epoch, senderPeerIndex, 4n, new Uint8Array([2]));
		await decodeFrame(receiver, good2);
		expect(new Uint8Array(good2.data)).toEqual(new Uint8Array([2]));
	});

	it('Test 5: new epoch install resets failure counts', async () => {
		const chainKey = randomChainKey();
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };

		const bundles0 = await makeBundles(chainKey, 0, peerIndexMap);
		const receiver = createWorkerState(() => {});
		receiver.failureTolerance = 0;
		installEpoch(receiver, 0, senderPeerIndex, bundles0);

		// Force a failure → key invalid for epoch 0.
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, 0, senderPeerIndex, 0n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		expect(receiver.failureCounts.get(`0:${senderPeerIndex}`)).toBe(1);

		// Install epoch 1 — resetFailureCount is called for the new epoch's
		// peers. The epoch-0 count remains (different key), but a fresh frame
		// at epoch 1 must NOT be dropped as key_invalid.
		const bundles1 = await makeBundles(chainKey, 1, peerIndexMap);
		installEpoch(receiver, 1, senderPeerIndex, bundles1);

		// A valid frame at epoch 1 decrypts (fresh slate).
		const good = await encryptFrame(chainKey, 1, senderPeerIndex, 0n, new Uint8Array([7]));
		await decodeFrame(receiver, good);
		expect(new Uint8Array(good.data)).toEqual(new Uint8Array([7]));

		// Re-install epoch 0 keys to confirm resetFailureCount cleared the
		// epoch-0 count on its prior install path too. Re-installing epoch 0
		// calls resetFailureCount(0, 0) again, so a frame at epoch 0 is no
		// longer considered invalid.
		installEpoch(receiver, 0, senderPeerIndex, bundles0);
		const good0 = await encryptFrame(chainKey, 0, senderPeerIndex, 0n, new Uint8Array([8]));
		await decodeFrame(receiver, good0);
		expect(new Uint8Array(good0.data)).toEqual(new Uint8Array([8]));
	});

	it('Test 6: set-failure-tolerance control message changes the threshold and clears counts', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState(() => {});
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// Default -1 (unlimited). Set to 0 via control message.
		expect(receiver.failureTolerance).toBe(-1);
		await handleMessage(receiver, { type: 'set-failure-tolerance', tolerance: 0 });
		expect(receiver.failureTolerance).toBe(0);

		// One failure now invalidates the key.
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, epoch, senderPeerIndex, 0n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(1);
		await expect(decodeFrame(receiver, await encryptFrame(chainKey, epoch, senderPeerIndex, 1n, new Uint8Array([1]))))
			.rejects.toBeInstanceOf(KeyInvalidError);

		// Raise tolerance back to 5 — clears all counts, key valid again.
		await handleMessage(receiver, { type: 'set-failure-tolerance', tolerance: 5 });
		expect(receiver.failureTolerance).toBe(5);
		expect(receiver.failureCounts.size).toBe(0);
		const good = await encryptFrame(chainKey, epoch, senderPeerIndex, 2n, new Uint8Array([3]));
		await decodeFrame(receiver, good);
		expect(new Uint8Array(good.data)).toEqual(new Uint8Array([3]));

		// Clamp: negative-below-−1 becomes −1 (unlimited).
		await handleMessage(receiver, { type: 'set-failure-tolerance', tolerance: -99 });
		expect(receiver.failureTolerance).toBe(-1);
	});

	it('Test 7: drainPreEpochQueue also respects isKeyInvalid', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const errors: OutMsg[] = [];
		const receiver = createWorkerState((m) => errors.push(m));
		receiver.failureTolerance = 0;

		// Install epoch, then invalidate the key with one AEAD failure.
		installEpoch(receiver, epoch, senderPeerIndex, bundles);
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, epoch, senderPeerIndex, 0n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		expect(receiver.failureCounts.get(`${epoch}:${senderPeerIndex}`)).toBe(1);

		// Push a VALID frame directly into the pre-epoch queue and drain.
		// drainPreEpochQueue must hit the isKeyInvalid gate and drop it with
		// reason 'key_invalid' — WITHOUT attempting AEAD (no successful decrypt).
		const good = await encryptFrame(chainKey, epoch, senderPeerIndex, 1n, new Uint8Array([42]));
		const goodDataBefore = new Uint8Array(good.data.slice(0));
		receiver.preEpochQueue.push({ frame: good });
		await drainPreEpochQueue(receiver);

		// The frame was dropped (data untouched — not decrypted).
		expect(new Uint8Array(good.data)).toEqual(goodDataBefore);
		expect(failureReasons(errors)).toContain('key_invalid');
	});
});

// ---------------------------------------------------------------------------
// Error class + metric event tests
// ---------------------------------------------------------------------------

describe('KeyInvalidError', () => {
	it('has code KEY_INVALID and carries epoch/peerIndex/failures context', () => {
		const err = new KeyInvalidError('test', { epoch: 1, peerIndex: 2, failures: 3 });
		expect(err.code).toBe('KEY_INVALID');
		expect(err.context).toEqual({ epoch: 1, peerIndex: 2, failures: 3 });
		expect(err instanceof Error).toBe(true);
	});
});

describe('key_invalidated metric event', () => {
	it('is emitted exactly once at the invalidation transition (tolerance=0)', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver = createWorkerState(() => {});
		receiver.failureTolerance = 0;
		receiver.metricsEnabled = true;
		const metrics: OutMsg[] = [];
		const orig = receiver.emit;
		(receiver as unknown as Record<string, unknown>).emit = (m: OutMsg) => {
			if (m.type === 'metrics') metrics.push(m);
			orig(m);
		};
		installEpoch(receiver, epoch, senderPeerIndex, bundles);

		// First failure: count 0→1, crosses tolerance 0 → emit key_invalidated.
		await expect(decodeFrame(receiver, await corruptFrame(chainKey, epoch, senderPeerIndex, 0n)))
			.rejects.toSatisfy((err) => err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError);
		const invalidated = metrics.filter(
			(m) => m.type === 'metrics' && m.event.kind === 'key_invalidated',
		);
		expect(invalidated).toHaveLength(1);
		expect((invalidated[0] as { event: { failures: number } }).event.failures).toBe(1);

		// Subsequent dropped frames (key_invalid) do NOT re-emit key_invalidated.
		await expect(decodeFrame(receiver, await encryptFrame(chainKey, epoch, senderPeerIndex, 1n, new Uint8Array([1]))))
			.rejects.toBeInstanceOf(KeyInvalidError);
		const invalidated2 = metrics.filter(
			(m) => m.type === 'metrics' && m.event.kind === 'key_invalidated',
		);
		expect(invalidated2).toHaveLength(1);
	});
});
