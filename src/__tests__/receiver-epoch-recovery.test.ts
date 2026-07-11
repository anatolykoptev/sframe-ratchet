// Receiver-epoch detection / recovery surface (v0.6.0, additive).
//
// The prod bug this pins: a receiver's FrameCryptor stayed at currentEpoch=-1
// for a whole call (its EpochAnnouncement was never delivered), silently
// dropping every inbound frame into the bounded pre-epoch queue — 0 audio, no
// way for the main thread to observe or recover it.
//
// This suite covers the new observability/recovery API:
//   A. epoch_applied worker→main signal + FrameCryptor.getAppliedEpoch() / onEpochApplied
//   B. decrypt_starved coalesced worker→main signal + FrameCryptor.onDecryptStarved
//   C. RoomRatchet.getEpochPeerIndexMap(epoch)
//   E. configurable pre-epoch queue cap
//
// All detection is IN-PAYLOAD-ONLY: peerIndex comes from splitKid(hdr.kid) on
// the cleartext SFrame header, never from an RTP header extension.

import { describe, it, expect, vi } from 'vitest';
import { createWorkerState, handleMessage, installEpoch } from '../worker-state.ts';
import { decodeFrame, drainPreEpochQueue } from '../worker-frame.ts';
import { randomChainKey, deriveSenderKeys } from '../ratchet-crypto.ts';
import { sframeEncrypt } from '../sframe.ts';
import { FrameCryptor } from '../frame-cryptor.ts';
import { RoomRatchet } from '../ratchet.ts';
import type { OutMsg } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { makeBundles, makeFrame } from './helpers.ts';

// Build a queued-ready SFrame frame for peer 0, epoch 0.
async function encFrame(chainKey: Uint8Array, ctr: bigint): Promise<RTCEncodedVideoFrame> {
	const key = await deriveSenderKeys(chainKey, 0, 0);
	const ct = await sframeEncrypt(new TextEncoder().encode(`f${ctr}`), key, ctr);
	return makeFrame(ct);
}

// -----------------------------------------------------------------------------
// A. epoch_applied (worker → main)
// -----------------------------------------------------------------------------

describe('A. epoch_applied worker signal', () => {
	it('installEpoch advancing from -1 emits epoch_applied{epoch}', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const ck = randomChainKey();
		const bundles = await makeBundles(ck, 0, { alice: 0 as PeerIndex });

		installEpoch(state, 0, 0, bundles);

		const applied = emitted.filter((m) => m.type === 'epoch_applied');
		expect(applied).toHaveLength(1);
		expect(applied[0]).toMatchObject({ epoch: 0 });
	});

	it('re-installing a LOWER epoch (no advance) does NOT emit epoch_applied', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		const ck = randomChainKey();

		installEpoch(state, 5, 0, await makeBundles(ck, 5, { alice: 0 as PeerIndex }));
		emitted.length = 0; // drop the epoch 5 signal

		// Epoch 3 < currentEpoch (5): a late re-propagation, must not re-signal.
		installEpoch(state, 3, 0, await makeBundles(ck, 3, { alice: 0 as PeerIndex }));
		expect(emitted.filter((m) => m.type === 'epoch_applied')).toHaveLength(0);
	});

	it('epoch_applied is emitted even when metrics are disabled (default)', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		expect(state.metricsEnabled).toBe(false);
		installEpoch(state, 2, 0, await makeBundles(randomChainKey(), 2, { alice: 0 as PeerIndex }));
		expect(emitted.filter((m) => m.type === 'epoch_applied')).toHaveLength(1);
	});
});

// -----------------------------------------------------------------------------
// A. FrameCryptor.getAppliedEpoch() / onEpochApplied
// -----------------------------------------------------------------------------

interface ObservableWorker {
	postMessage: ReturnType<typeof vi.fn>;
	terminate: ReturnType<typeof vi.fn>;
	addEventListener: (t: string, l: (ev: MessageEvent) => void) => void;
	removeEventListener: (t: string, l: (ev: MessageEvent) => void) => void;
	dispatch: (data: unknown) => void;
	listenerCount: () => number;
}

function makeObservableWorker(): ObservableWorker {
	const listeners: Array<(ev: MessageEvent) => void> = [];
	return {
		postMessage: vi.fn(),
		terminate: vi.fn(),
		addEventListener: (t, l) => { if (t === 'message') listeners.push(l); },
		removeEventListener: (t, l) => { const i = listeners.indexOf(l); if (i >= 0) listeners.splice(i, 1); },
		dispatch: (data) => { for (const l of [...listeners]) l({ data } as MessageEvent); },
		listenerCount: () => listeners.length,
	};
}

describe('A. FrameCryptor receiver epoch observation', () => {
	it('getAppliedEpoch() is -1 before any epoch, then reflects epoch_applied', () => {
		const w = makeObservableWorker();
		const c = new FrameCryptor({ worker: w as unknown as Worker, role: 'receiver', peerId: 'p1', peerIndex: 0 });
		expect(c.getAppliedEpoch()).toBe(-1);
		w.dispatch({ type: 'epoch_applied', epoch: 3 });
		expect(c.getAppliedEpoch()).toBe(3);
		c.detach();
	});

	it('onEpochApplied callback fires with the installed epoch number', () => {
		const seen: number[] = [];
		const w = makeObservableWorker();
		const c = new FrameCryptor({
			worker: w as unknown as Worker, role: 'receiver', peerId: 'p1', peerIndex: 0,
			onEpochApplied: (e) => seen.push(e),
		});
		w.dispatch({ type: 'epoch_applied', epoch: 7 });
		expect(seen).toEqual([7]);
		c.detach();
	});

	it('ignores unrelated worker messages', () => {
		const seen: number[] = [];
		const w = makeObservableWorker();
		const c = new FrameCryptor({
			worker: w as unknown as Worker, role: 'receiver', peerId: 'p1', peerIndex: 0,
			onEpochApplied: (e) => seen.push(e),
		});
		w.dispatch({ type: 'ready' });
		w.dispatch({ type: 'metrics', event: { kind: 'decrypt', epoch: 0, peerIndex: 0, bytes: 1 } });
		expect(seen).toEqual([]);
		expect(c.getAppliedEpoch()).toBe(-1);
		c.detach();
	});

	it('detach removes the worker message listener', () => {
		const w = makeObservableWorker();
		const c = new FrameCryptor({
			worker: w as unknown as Worker, role: 'receiver', peerId: 'p1', peerIndex: 0,
			onEpochApplied: () => {},
		});
		expect(w.listenerCount()).toBe(1);
		c.detach();
		expect(w.listenerCount()).toBe(0);
		// A message after detach must not update state.
		w.dispatch({ type: 'epoch_applied', epoch: 9 });
		expect(c.getAppliedEpoch()).toBe(-1);
	});
});

// -----------------------------------------------------------------------------
// B. decrypt_starved (worker → main), coalesced
// -----------------------------------------------------------------------------

describe('B. decrypt_starved starvation signal', () => {
	it('a receiver stuck at epoch -1 that overflows its queue emits decrypt_starved', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.preEpochQueueCap = 2; // overflow fast
		const ck = randomChainKey();

		// 2 fill the queue (no drop), the 3rd overflows → first starvation drop.
		for (let i = 0; i < 3; i++) await decodeFrame(state, await encFrame(ck, BigInt(i)));

		const starved = emitted.filter((m) => m.type === 'decrypt_starved');
		expect(starved).toHaveLength(1);
		expect(starved[0]).toMatchObject({ framesDropped: 1, sinceMs: 0, peerIndex: 0 });

		// The pre-existing per-drop decrypt_failure{queue_overflow} is preserved.
		expect(
			emitted.filter((m) => m.type === 'decrypt_failure' && (m as { reason: string }).reason === 'queue_overflow'),
		).toHaveLength(1);
	});

	it('coalesces multiple drops: one emit per window, framesDropped cumulative', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.preEpochQueueCap = 2;
		let clock = 1000;
		state.now = () => clock;
		const ck = randomChainKey();

		// f0,f1 fill; f2 drop#1 → emit#1 (immediate). f3 drop#2 → coalesced (same tick).
		for (let i = 0; i < 4; i++) await decodeFrame(state, await encFrame(ck, BigInt(i)));
		// advance past the coalesce window; f4 drop#3 → emit#2.
		clock += 1000;
		await decodeFrame(state, await encFrame(ck, 4n));

		const starved = emitted.filter((m) => m.type === 'decrypt_starved') as Array<{
			framesDropped: number; sinceMs: number; peerIndex?: number;
		}>;
		expect(starved).toHaveLength(2);
		expect(starved[0]).toMatchObject({ framesDropped: 1, sinceMs: 0, peerIndex: 0 });
		expect(starved[1]).toMatchObject({ framesDropped: 3, sinceMs: 1000, peerIndex: 0 });
	});

	it('a successful decode clears the starvation episode', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.preEpochQueueCap = 1;
		const ck = randomChainKey();

		// f0 fills, f1 overflows → drop#0, episode active; queue now holds f1.
		await decodeFrame(state, await encFrame(ck, 0n));
		await decodeFrame(state, await encFrame(ck, 1n));
		expect(state.starveActive).toBe(true);

		// Install the epoch and drain — the surviving frame decodes → episode cleared.
		installEpoch(state, 0, 0, await makeBundles(ck, 0, { alice: 0 as PeerIndex }));
		await drainPreEpochQueue(state);
		expect(state.starveActive).toBe(false);
	});
});

// -----------------------------------------------------------------------------
// B. FrameCryptor.onDecryptStarved
// -----------------------------------------------------------------------------

describe('B. FrameCryptor.onDecryptStarved', () => {
	it('fires with the starvation info from the worker', () => {
		const seen: Array<{ peerIndex?: number; framesDropped: number; sinceMs: number }> = [];
		const w = makeObservableWorker();
		const c = new FrameCryptor({
			worker: w as unknown as Worker, role: 'receiver', peerId: 'p1', peerIndex: 0,
			onDecryptStarved: (info) => seen.push(info),
		});
		w.dispatch({ type: 'decrypt_starved', peerIndex: 2, framesDropped: 5, sinceMs: 1200 });
		expect(seen).toHaveLength(1);
		expect(seen[0]).toMatchObject({ peerIndex: 2, framesDropped: 5, sinceMs: 1200 });
		c.detach();
	});
});

// -----------------------------------------------------------------------------
// C. RoomRatchet.getEpochPeerIndexMap
// -----------------------------------------------------------------------------

const PEER_SELF = { peerId: 'aaa', kpub: new Uint8Array(32) };
const PEER_B = { peerId: 'bbb', kpub: new Uint8Array(32) };

interface RatchetSeam {
	installEpoch(version: number, chainKey: Uint8Array, peerIndexMap: Record<string, number>): Promise<void>;
}
async function installRatchet(r: RoomRatchet, version: number): Promise<void> {
	await (r as unknown as RatchetSeam).installEpoch(version, new Uint8Array(32), { aaa: 0, bbb: 1 });
}

describe('C. RoomRatchet.getEpochPeerIndexMap', () => {
	it('returns the peer_index_map for an installed epoch', async () => {
		const r = new RoomRatchet({ identity: PEER_SELF as never, initialPeers: [PEER_B as never] });
		await installRatchet(r, 0);
		expect(r.getEpochPeerIndexMap(0)).toEqual({ aaa: 0, bbb: 1 });
	});

	it('returns null for an unknown / never-installed epoch', () => {
		const r = new RoomRatchet({ identity: PEER_SELF as never });
		expect(r.getEpochPeerIndexMap(99)).toBeNull();
	});

	it('returns a defensive copy — mutating the result does not corrupt internal state', async () => {
		const r = new RoomRatchet({ identity: PEER_SELF as never, initialPeers: [PEER_B as never] });
		await installRatchet(r, 0);
		const m = r.getEpochPeerIndexMap(0);
		expect(m).not.toBeNull();
		(m as Record<string, number>).aaa = 999;
		expect(r.getEpochPeerIndexMap(0)).toEqual({ aaa: 0, bbb: 1 });
	});
});

// -----------------------------------------------------------------------------
// E. configurable pre-epoch queue cap
// -----------------------------------------------------------------------------

describe('E. configurable pre-epoch queue cap', () => {
	it('state.preEpochQueueCap drives the drop threshold', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.preEpochQueueCap = 3;
		const ck = randomChainKey();

		// 4 frames, cap 3 → exactly 1 overflow drop, queue capped at 3.
		for (let i = 0; i < 4; i++) await decodeFrame(state, await encFrame(ck, BigInt(i)));

		expect(state.preEpochQueue.length).toBe(3);
		expect(
			emitted.filter((m) => m.type === 'decrypt_failure' && (m as { reason: string }).reason === 'queue_overflow'),
		).toHaveLength(1);
	});

	it('the init message sets preEpochQueueCap', async () => {
		const state = createWorkerState(() => {});
		await handleMessage(state, { type: 'init', role: 'receiver', peerId: 'p1', peerIndex: 0, preEpochQueueCap: 5 });
		expect(state.preEpochQueueCap).toBe(5);
	});

	it('default cap is 50 when not overridden', () => {
		const state = createWorkerState(() => {});
		expect(state.preEpochQueueCap).toBe(50);
	});
});
