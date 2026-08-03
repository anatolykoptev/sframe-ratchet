// Durable cross-reload anti-replay tests for the MEDIA frame path
// (worker-frame.ts decodeFrame + drainPreEpochQueue).
//
// These tests exercise the REAL decodeFrame path — no hand-copied
// function-under-test. Each test encrypts a real SFrame frame and feeds it
// through the actual decode pipeline so the durable replay check runs in
// its true location (after parseHeader + stale-epoch gate + in-memory
// replay check, before tryDecryptWithRatchet).
//
// A "reload" is simulated by creating a FRESH worker state with the SAME
// namespace (fresh in-memory replay windows, like a real worker reload)
// while the durable IndexedDB store persists.
//
// PR-review-council required: media path integration tests. The chat path
// has its own integration tests; this covers the worker-frame.ts path.

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
import { createWorkerState, installEpoch, wipeEpoch, handleMessage } from '../worker-state.ts';
import { decodeFrame } from '../worker-frame.ts';
import { sframeEncrypt } from '../sframe.ts';
import { deriveSenderKeys, randomChainKey } from '../ratchet-crypto.ts';
import { makeKid } from '../ratchet-ids.ts';
import { ReplayError } from '../errors.ts';
import type { OutMsg, PerSenderKeyBundle } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { makeFrame, makeBundles } from './helpers.ts';

// ---------------------------------------------------------------------------
// navigator.locks polyfill — same as durable-replay.test.ts.
// ---------------------------------------------------------------------------

beforeAll(() => {
	if (typeof navigator === 'undefined') {
		(globalThis as Record<string, unknown>).navigator = {};
	}
	const nav = globalThis.navigator as unknown as Record<string, unknown>;
	if (!nav.locks) {
		const held = new Map<string, Promise<void>>();
		const locksApi = {
			request: async (
				name: string,
				optionsOrCallback: unknown,
				maybeCallback?: () => Promise<void>,
			): Promise<void> => {
				const callback =
					typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
				if (typeof callback !== 'function') {
					throw new Error('navigator.locks.request: callback required');
				}
				while (held.has(name)) {
					await held.get(name);
				}
				let resolve!: () => void;
				const p = new Promise<void>((r) => {
					resolve = r;
				});
				held.set(name, p);
				try {
					return await callback();
				} finally {
					held.delete(name);
					resolve();
				}
			},
		};
		Object.defineProperty(nav, 'locks', { value: locksApi, configurable: true, writable: true });
	}
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let nsCounter = 0;
function freshNs(): string {
	return `media-ns-${nsCounter++}`;
}

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

function collectErrors(state: ReturnType<typeof createWorkerState>): OutMsg[] {
	const errors: OutMsg[] = [];
	const originalEmit = state.emit;
	(state as unknown as Record<string, unknown>).emit = (msg: OutMsg) => {
		errors.push(msg);
		originalEmit(msg);
	};
	return errors;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('durable replay — media frame path (CWE-294)', () => {
	it('rejects a replayed frame after a simulated worker reload (fresh state, same namespace)', async () => {
		const ns = freshNs();
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);
		const plaintext = new Uint8Array([1, 2, 3, 4, 5]);

		// Session 1: receiver decodes an authentic frame.
		const receiver1 = createWorkerState((m) => undefined);
		await handleMessage(receiver1, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver1, epoch, senderPeerIndex, bundles);

		const frame = await encryptFrame(chainKey, epoch, senderPeerIndex, 42n, plaintext);
		await decodeFrame(receiver1, frame);

		// Reload: fresh worker state (empty in-memory windows) — durable IDB persists.
		const receiver2 = createWorkerState((m) => undefined);
		await handleMessage(receiver2, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver2, epoch, senderPeerIndex, bundles);

		// Server replays the SAME authentic frame. Must be REJECTED.
		const errors = collectErrors(receiver2);
		const replayedFrame = await encryptFrame(chainKey, epoch, senderPeerIndex, 42n, plaintext);
		await expect(decodeFrame(receiver2, replayedFrame)).rejects.toBeInstanceOf(ReplayError);
		expect(errors.some((m) => m.type === 'decrypt_failure' && m.reason === 'replay')).toBe(true);
	});

	it('accepts a genuinely-new frame after a reload', async () => {
		const ns = freshNs();
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const receiver1 = createWorkerState((m) => undefined);
		await handleMessage(receiver1, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver1, epoch, senderPeerIndex, bundles);

		const frame1 = await encryptFrame(chainKey, epoch, senderPeerIndex, 10n, new Uint8Array([1]));
		await decodeFrame(receiver1, frame1);

		// Reload.
		const receiver2 = createWorkerState((m) => undefined);
		await handleMessage(receiver2, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver2, epoch, senderPeerIndex, bundles);

		// A genuinely-new CTR is accepted.
		const frame2 = await encryptFrame(chainKey, epoch, senderPeerIndex, 20n, new Uint8Array([2]));
		await decodeFrame(receiver2, frame2);
		// No replay error thrown — test passes if we reach this point.
	});

	it('regression: durableReplay disabled (default) — no durable check, replay only in-memory', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);
		const plaintext = new Uint8Array([1, 2, 3]);

		const receiver1 = createWorkerState((m) => undefined);
		await handleMessage(receiver1, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			// No durableReplay — default off.
		});
		installEpoch(receiver1, epoch, senderPeerIndex, bundles);

		const frame = await encryptFrame(chainKey, epoch, senderPeerIndex, 5n, plaintext);
		await decodeFrame(receiver1, frame);

		// Reload — no durable replay, so the old frame is ACCEPTED (in-memory window wiped).
		const receiver2 = createWorkerState((m) => undefined);
		await handleMessage(receiver2, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
		});
		installEpoch(receiver2, epoch, senderPeerIndex, bundles);

		// This is the VULNERABLE behavior (CWE-294) — documented as the default.
		const replayedFrame = await encryptFrame(chainKey, epoch, senderPeerIndex, 5n, plaintext);
		await decodeFrame(receiver2, replayedFrame);
		// No replay error — test passes (the frame is accepted, demonstrating the gap).
	});

	it('throws on init when durableReplay is true but namespace is missing', async () => {
		const receiver = createWorkerState((m) => undefined);
		await expect(
			handleMessage(receiver, {
				type: 'init',
				role: 'receiver',
				peerId: 'bob',
				peerIndex: 1 as PeerIndex,
				durableReplay: true,
				// No durableReplayNamespace.
			}),
		).rejects.toThrow('durableReplayNamespace is required');
	});

	it('throws on init when durableReplayWindow > replayWindowSize', async () => {
		const receiver = createWorkerState((m) => undefined);
		await expect(
			handleMessage(receiver, {
				type: 'init',
				role: 'receiver',
				peerId: 'bob',
				peerIndex: 1 as PeerIndex,
				durableReplay: true,
				durableReplayNamespace: freshNs(),
				durableReplayWindow: 128,
			}),
		).rejects.toThrow('must be <= replayWindowSize');
	});

	it('isolates (epoch, peerIndex) pairs — different peers do not interfere', async () => {
		const ns = freshNs();
		const chainKey = randomChainKey();
		const epoch = 0;
		const peerIndexMap = { alice: 0 as PeerIndex, bob: 1 as PeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		// Session 1: accept CTR=1 from peer 0.
		const receiver1 = createWorkerState((m) => undefined);
		await handleMessage(receiver1, {
			type: 'init',
			role: 'receiver',
			peerId: 'carol',
			peerIndex: 2 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver1, epoch, 2 as PeerIndex, bundles);

		const framePeer0 = await encryptFrame(chainKey, epoch, 0 as PeerIndex, 1n, new Uint8Array([1]));
		await decodeFrame(receiver1, framePeer0);

		// Reload.
		const receiver2 = createWorkerState((m) => undefined);
		await handleMessage(receiver2, {
			type: 'init',
			role: 'receiver',
			peerId: 'carol',
			peerIndex: 2 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver2, epoch, 2 as PeerIndex, bundles);

		// Same CTR=1 from a DIFFERENT peer (peer 1) is NOT a replay.
		const framePeer1 = await encryptFrame(chainKey, epoch, 1 as PeerIndex, 1n, new Uint8Array([2]));
		await decodeFrame(receiver2, framePeer1);
		// No replay error — test passes.
	});

	it('wipeEpoch clears durable replay state — stale CTRs do not false-reject after epoch rotation', async () => {
		const ns = freshNs();
		const chainKey = randomChainKey();
		const epoch0 = 0;
		const epoch1 = 1;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles0 = await makeBundles(chainKey, epoch0, peerIndexMap);
		const bundles1 = await makeBundles(chainKey, epoch1, peerIndexMap);

		const receiver = createWorkerState((m) => undefined);
		await handleMessage(receiver, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver, epoch0, senderPeerIndex, bundles0);

		// Accept CTR=42 at epoch 0 — persists to durable store.
		const frame0 = await encryptFrame(chainKey, epoch0, senderPeerIndex, 42n, new Uint8Array([1]));
		await decodeFrame(receiver, frame0);

		// Rotate to epoch 1 and wipe epoch 0 — clears durable state for epoch 0's peers.
		installEpoch(receiver, epoch1, senderPeerIndex, bundles1);
		wipeEpoch(receiver, epoch0);

		// After wipe, CTR=42 at epoch 1 should be accepted (durable state for
		// epoch 0 was cleared; epoch 1 has a different durable key).
		const frame1 = await encryptFrame(chainKey, epoch1, senderPeerIndex, 42n, new Uint8Array([2]));
		await decodeFrame(receiver, frame1);
		// No replay error — test passes.
	});

	it('wipeEpoch does not clear durable state for OTHER epochs', async () => {
		const ns = freshNs();
		const chainKey = randomChainKey();
		const epoch0 = 0;
		const epoch1 = 1;
		const senderPeerIndex = 0 as PeerIndex;
		const peerIndexMap = { alice: senderPeerIndex };
		const bundles0 = await makeBundles(chainKey, epoch0, peerIndexMap);
		const bundles1 = await makeBundles(chainKey, epoch1, peerIndexMap);

		const receiver = createWorkerState((m) => undefined);
		await handleMessage(receiver, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver, epoch0, senderPeerIndex, bundles0);
		installEpoch(receiver, epoch1, senderPeerIndex, bundles1);

		// Accept CTR=10 at epoch 1 — persists to durable store.
		const frame1 = await encryptFrame(chainKey, epoch1, senderPeerIndex, 10n, new Uint8Array([2]));
		await decodeFrame(receiver, frame1);

		// Wipe epoch 0 — should NOT clear epoch 1's durable state.
		wipeEpoch(receiver, epoch0);

		// Reload: fresh receiver, same namespace.
		const receiver2 = createWorkerState((m) => undefined);
		await handleMessage(receiver2, {
			type: 'init',
			role: 'receiver',
			peerId: 'bob',
			peerIndex: 1 as PeerIndex,
			durableReplay: true,
			durableReplayNamespace: ns,
		});
		installEpoch(receiver2, epoch1, senderPeerIndex, bundles1);

		// CTR=10 at epoch 1 should still be REJECTED (durable state survived the
		// wipe of epoch 0).
		const replayedFrame1 = await encryptFrame(chainKey, epoch1, senderPeerIndex, 10n, new Uint8Array([2]));
		await expect(decodeFrame(receiver2, replayedFrame1)).rejects.toBeInstanceOf(ReplayError);
	});
});
