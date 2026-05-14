// Smoke tests for the SFrame AEAD + header round-trip. Updated for the
// revised per-sender AEAD derivation + 32-bit KID schema (spec §§ 2.2, 6.1,
// 7.4, 7.8). Full M3.4 test matrix lives in a separate suite; these are the
// correctness cases required by the M3.2 fix-round brief.

import { describe, it, expect, vi } from 'vitest';
import { parseHeader, serializeHeader, sframeEncrypt, sframeDecrypt } from '../sframe.ts';
import { deriveEpochKeyTable, deriveSenderKeys, randomChainKey } from '../ratchet-crypto.ts';
import { joinKid, splitKid, validatePeerIndexMap } from '../ratchet-ids.ts';
import { createWorkerState, handleMessage } from '../worker-state.ts';
import { decodeFrame, encodeFrame } from '../worker-frame.ts';
import type { OutMsg, PerSenderKeyBundle } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';

// --- existing smoke tests, updated for the new API ------------------------

describe('sframe smoke', () => {
	it('deriveSenderKeys → encrypt → decrypt round-trips per-sender', async () => {
		// Shared ChainKey, two distinct peer_indices → two independent bundles.
		const chainKey = randomChainKey();
		const alice = await deriveSenderKeys(chainKey, 1, 0);
		const bob = await deriveSenderKeys(chainKey, 1, 1);

		// Per §2.2: salts MUST differ even though ChainKey is shared.
		expect(alice.salt).not.toEqual(bob.salt);
		expect(alice.kid).toBe(joinKid({ epoch: 1, peerIndex: 0 }));
		expect(bob.kid).toBe(joinKid({ epoch: 1, peerIndex: 1 }));

		const plaintext = new TextEncoder().encode('hello sframe');
		const sealed = await sframeEncrypt(plaintext, alice, 7n);

		// Resolver returns alice's key for alice's KID; anything else → null.
		const opened = await sframeDecrypt(sealed, ({ kid }) => (kid === alice.kid ? alice : null));
		expect(new TextDecoder().decode(opened)).toBe('hello sframe');

		// A frame encrypted under alice cannot be opened with bob's bundle.
		await expect(
			sframeDecrypt(sealed, ({ kid }) => (kid === alice.kid ? bob : null)),
		).rejects.toBeDefined();
	});

	it('sframeDecrypt with a different key throws', async () => {
		const chainKeyA = randomChainKey();
		const chainKeyB = randomChainKey();
		const keyA = await deriveSenderKeys(chainKeyA, 2, 0);
		const keyB = await deriveSenderKeys(chainKeyB, 2, 0); // same (epoch, pi), different chainKey
		expect(keyA.kid).toBe(keyB.kid); // KID is purely (epoch, peer_index)

		const sealed = await sframeEncrypt(new TextEncoder().encode('secret'), keyA, 1n);
		await expect(
			sframeDecrypt(sealed, ({ kid }) => (kid === keyB.kid ? keyB : null)),
		).rejects.toBeDefined();
	});

	it('parseHeader(serializeHeader(kid, ctr)) round-trips 32-bit KIDs', () => {
		const cases: Array<[number, bigint]> = [
			[joinKid({ epoch: 0, peerIndex: 0 }), 0n],
			[joinKid({ epoch: 1, peerIndex: 0 }), 1n],
			[joinKid({ epoch: 0x42, peerIndex: 5 }), 0xff_ffn],
			[joinKid({ epoch: 0xff00, peerIndex: 0x00ff }), 0xdead_beef_cafe_baben & 0xffffffffffffffffn],
			[joinKid({ epoch: 0xffff, peerIndex: 0xffff }), 0xffffffffffffffffn],
		];
		for (const [kid, ctr] of cases) {
			const buf = serializeHeader(kid, ctr);
			// Fixed-width KID per spec §6.1 — always 4 bytes.
			expect(buf.length).toBeGreaterThanOrEqual(1 + 4 + 1);
			const parsed = parseHeader(buf);
			expect(parsed.kid).toBe(kid);
			expect(parsed.ctr).toBe(ctr);
			expect(parsed.bodyOffset).toBe(buf.length);

			// splitKid(joinKid(x)) round-trip.
			const parts = splitKid(parsed.kid);
			const rejoined = joinKid(parts);
			expect(rejoined).toBe(kid);
		}
	});

	// --- new cases added by the 2026-04-21 fix round --------------------

	it('validatePeerIndexMap enforces the §7.8 invariant', () => {
		// Valid: three peers, indices 0,1,2.
		expect(validatePeerIndexMap({ alice: 0, bob: 1, charlie: 2 }))
			.toEqual({ valid: true });

		// Gap: {0,2} with |keys|=2 → '2' is out of range [0, 2).
		expect(validatePeerIndexMap({ alice: 0, bob: 2 }))
			.toEqual({ valid: false, reason: 'bad_value' });

		// Duplicate index.
		expect(validatePeerIndexMap({ alice: 1, bob: 1 }))
			.toEqual({ valid: false, reason: 'duplicate_index' });

		// Larger N, genuine gap after the bad_value gate (all in [0,N), dup check fires first).
		// Here N=3, values {0,0,2} → duplicate 0.
		expect(validatePeerIndexMap({ a: 0, b: 0, c: 2 }))
			.toEqual({ valid: false, reason: 'duplicate_index' });

		// Empty map rejected.
		expect(validatePeerIndexMap({})).toEqual({ valid: false, reason: 'empty' });

		// Negative / non-integer values rejected with bad_value.
		expect(validatePeerIndexMap({ alice: -1, bob: 0 }))
			.toEqual({ valid: false, reason: 'bad_value' });
	});

	it('stale-epoch gate: resolver rejects old-epoch frames BEFORE decrypt', async () => {
		// Build a valid key, encrypt a frame, then simulate a post-rotation
		// receiver whose currentMinValidEpoch=1. A naive resolver that returns
		// the real key would decrypt successfully; the gate must fire first.
		const chainKey = randomChainKey();
		const keyEpoch0 = await deriveSenderKeys(chainKey, 0, 0);

		const plaintext = new TextEncoder().encode('stale');
		const sealed = await sframeEncrypt(plaintext, keyEpoch0, 1n);

		// Sanity: control path — gate disabled → decrypt succeeds.
		const opened = await sframeDecrypt(sealed, ({ kid }) => (
			kid === keyEpoch0.kid ? keyEpoch0 : null
		));
		expect(new TextDecoder().decode(opened)).toBe('stale');

		// Real gate: currentMinValidEpoch=1, so any kid.epoch<1 is rejected.
		// The resolver receives the lookup ctx so the gate can fire there (and
		// separately the worker fires before calling sframeDecrypt).
		const currentMinValidEpoch = 1;
		let resolverCalled = false;
		let decryptErr: unknown = null;
		type GateError = Error & { reason: string };
		try {
			await sframeDecrypt(sealed, ({ kid, epoch }) => {
				resolverCalled = true;
				if (epoch < currentMinValidEpoch) {
					const e = new Error('stale_epoch') as GateError;
					e.reason = 'stale_epoch';
					throw e;
				}
				return kid === keyEpoch0.kid ? keyEpoch0 : null;
			});
		} catch (e) {
			decryptErr = e;
		}
		expect(resolverCalled).toBe(true);
		expect(decryptErr).toBeInstanceOf(Error);
		expect((decryptErr as Error).message).toBe('stale_epoch');

		// And the gate-absent resolver with the SAME frame + SAME key succeeds —
		// proves the gate is what rejects it, not bad key material.
		const openedAgain = await sframeDecrypt(sealed, ({ kid }) => (
			kid === keyEpoch0.kid ? keyEpoch0 : null
		));
		expect(new TextDecoder().decode(openedAgain)).toBe('stale');
	});

	// --- end-to-end worker state-machine tests (fix-round 2) ------------

	it('worker state machine rejects stale-epoch frames after grace window', async () => {
		vi.useFakeTimers();
		try {
			const emitted: OutMsg[] = [];
			const state = createWorkerState((m) => emitted.push(m));
			const peerIndexMap: Record<string, PeerIndex> = { alice: 0, bob: 1 };
			const chainKey0 = randomChainKey();
			const chainKey1 = randomChainKey();

			// Install epoch 0 as sender (self=alice, peerIndex=0).
			const bundles0 = await bundlesFromMap(chainKey0, 0, peerIndexMap);
			await handleMessage(state, {
				type: 'epoch', epoch: 0, peerIndexMap, selfPeerIndex: 0, keys: bundles0,
			});

			// Build a valid epoch-0 frame we'll replay after rotation.
			const keyE0 = await deriveSenderKeys(chainKey0, 0, 0);
			const staleBody = await sframeEncrypt(new TextEncoder().encode('stale'), keyE0, 0n);

			// Install epoch 1 — this MUST self-schedule a wipe for epoch 0
			// (fix-round 2: installEpoch advances the gate, not just rotate).
			const bundles1 = await bundlesFromMap(chainKey1, 1, peerIndexMap);
			await handleMessage(state, {
				type: 'epoch', epoch: 1, peerIndexMap, selfPeerIndex: 0, keys: bundles1,
			});

			// Gate has NOT advanced yet — within grace window, epoch 0 still accepted.
			expect(state.currentMinValidEpoch).toBe(0);

			// Advance past the 2 s grace window → wipeEpoch fires → gate moves to 1.
			await vi.advanceTimersByTimeAsync(2001);
			expect(state.currentMinValidEpoch).toBe(1);

			// Now feed the stale-epoch-0 frame into decodeFrame; must be rejected
			// with decrypt_failure{reason: 'stale_epoch'} BEFORE any decrypt attempt.
			const frame = makeFrame(staleBody);
			await expect(decodeFrame(state, frame)).rejects.toThrow('stale_epoch');
			expect(
				emitted.some((m) => m.type === 'decrypt_failure' && m.reason === 'stale_epoch'),
			).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	// --- Round 5: pendingDrain + per-frame parseHeader safety ---------------

	it('concurrent epoch messages: draining=true early-return must not orphan frames (pendingDrain)', async () => {
		// Reproduces the race: two handleMessage('epoch') calls are started
		// concurrently (without awaiting the first). The second fires while the
		// first drain is suspended at an await inside drainPreEpochQueue.
		// Under the old guard (early-return on draining=true), frames queued for
		// the second epoch are never drained → orphaned forever.
		// Fix: pendingDrain flag — the first drain re-runs its loop once more
		// after finishing, picking up frames for the second epoch.

		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const peerIndexMap: Record<string, PeerIndex> = { alice: 0, bob: 1 };
		const chainKey1 = randomChainKey();
		const chainKey2 = randomChainKey();

		// Pre-queue frames for epoch 1 and epoch 2 (both before any epoch installed).
		const keyBob1 = await deriveSenderKeys(chainKey1, 1, 1);
		const body1 = await sframeEncrypt(new TextEncoder().encode('ep1'), keyBob1, 0n);
		const keyBob2 = await deriveSenderKeys(chainKey2, 2, 1);
		const body2 = await sframeEncrypt(new TextEncoder().encode('ep2'), keyBob2, 0n);
		state.preEpochQueue.push({ frame: makeFrame(body1) });
		state.preEpochQueue.push({ frame: makeFrame(body2) });
		expect(state.preEpochQueue).toHaveLength(2);

		// Launch both epoch installs concurrently — do NOT await the first before
		// starting the second. This puts draining=true before the second drain runs.
		const bundles1 = await bundlesFromMap(chainKey1, 1, peerIndexMap);
		const bundles2 = await bundlesFromMap(chainKey2, 2, peerIndexMap);

		const p1 = handleMessage(state, { type: 'epoch', epoch: 1, peerIndexMap, selfPeerIndex: 0, keys: bundles1 });
		const p2 = handleMessage(state, { type: 'epoch', epoch: 2, peerIndexMap, selfPeerIndex: 0, keys: bundles2 });
		await Promise.all([p1, p2]);

		// After both settle: all frames must be drained (no orphans).
		expect(state.preEpochQueue).toHaveLength(0);
		// No decrypt_failure emitted (both frames should decrypt successfully).
		expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});

	it('parseHeader throws on one frame: remaining frames in batch still processed', async () => {
		// Scenario: drainPreEpochQueue processes a batch; if parseHeader throws for
		// frame[0] (corrupt header), frames[1..] must still be decrypted.
		// Old code: for-loop catch wraps all iterations — throw on frame[0] aborts
		// the loop, frames[1..] orphaned. Fix: per-frame try/catch inside the loop.

		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const peerIndexMap: Record<string, PeerIndex> = { alice: 0, bob: 1 };
		const chainKey = randomChainKey();

		// Build a valid epoch-0 frame (good, should decrypt successfully).
		const keyBob = await deriveSenderKeys(chainKey, 0, 1);
		const goodBody = await sframeEncrypt(new TextEncoder().encode('good'), keyBob, 0n);
		const goodFrame = makeFrame(goodBody);

		// Inject directly: a corrupt frame (empty data) FIRST in the queue,
		// then the good frame. Injecting directly bypasses decodeFrame's own
		// parseHeader guard — simulates a frame that was queued but whose header
		// is now unreadable (e.g. data race / memory corruption in the arraybuffer).
		const badFrame = makeFrame(new Uint8Array(0));
		state.preEpochQueue.push({ frame: badFrame });
		state.preEpochQueue.push({ frame: goodFrame });
		expect(state.preEpochQueue).toHaveLength(2);

		// Install epoch 0 → triggers drain. With per-frame try/catch: bad frame
		// emits decrypt_failure and continues; good frame decrypts successfully.
		const bundles = await bundlesFromMap(chainKey, 0, peerIndexMap);
		await handleMessage(state, { type: 'epoch', epoch: 0, peerIndexMap, selfPeerIndex: 0, keys: bundles });

		// goodFrame must have been decrypted — queue empty.
		expect(state.preEpochQueue).toHaveLength(0);
		// Bad frame emits decrypt_failure (not a silent drop).
		expect(emitted.some((m) => m.type === 'decrypt_failure')).toBe(true);
		// Good frame data changed (decrypted — no longer equals original ciphertext).
		expect(new Uint8Array(goodFrame.data)).not.toEqual(goodBody);
	});

	it('cross-SSRC CTR: same-sender audio and video share one monotonic counter', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const peerIndexMap: Record<string, PeerIndex> = { alice: 0, bob: 1 };
		const chainKey = randomChainKey();
		const bundles = await bundlesFromMap(chainKey, 0, peerIndexMap);

		await handleMessage(state, {
			type: 'epoch', epoch: 0, peerIndexMap, selfPeerIndex: 0, keys: bundles,
		});

		// Two frames from the same sender under the same epoch but different
		// SSRCs (audio vs. video). Under the pre-fix per-SSRC CTR, both would
		// emit CTR=0 → identical IV under the shared per-sender key → AES-GCM
		// nonce reuse. Post-fix: sender-wide CTR, monotonic across SSRCs.
		const frameAudio = makeFrame(new TextEncoder().encode('audio-plaintext'));
		const frameVideo = makeFrame(new TextEncoder().encode('video-plaintext-longer'));
		await encodeFrame(state, frameAudio);
		await encodeFrame(state, frameVideo);

		const hAudio = parseHeader(new Uint8Array(frameAudio.data));
		const hVideo = parseHeader(new Uint8Array(frameVideo.data));

		expect(hAudio.ctr).not.toBe(hVideo.ctr); // distinct CTR → distinct IV
		expect(hAudio.ctr).toBe(0n);
		expect(hVideo.ctr).toBe(1n);               // monotonic, not per-SSRC-reset
		// Both frames carry alice's KID (epoch=0, peerIndex=0) — confirms they
		// would have shared the per-sender (key, salt) bundle and therefore
		// collided under the old per-SSRC CTR scheme.
		expect(hAudio.kid).toBe(hVideo.kid);
	});
});

// --- test helpers ---------------------------------------------------------

async function bundlesFromMap(
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
 * Minimal RTCEncodedVideoFrame stand-in: `data` is a mutable ArrayBuffer,
 * which is the only surface encodeFrame / decodeFrame touch. Cast through
 * `unknown` because the full DOM type has many more fields we don't need.
 */
function makeFrame(body: Uint8Array): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}
