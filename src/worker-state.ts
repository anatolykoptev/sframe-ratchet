// Encoded-frame worker state machine — state-bookkeeping, no DOM / no `self`.
// Concern: per-epoch key-table install, stale-epoch gate advancement, and the
// 2 s grace-window wipe timer (spec §§ 2.2, 4.4 L151, 7.4).
// Message types live in worker-types.ts; frame I/O lives in worker-frame.ts;
// DOM glue lives in worker.ts. This module is pure logic so it can be driven
// from unit tests (sframe.smoke.test.ts) without spawning a real Worker.

import { makeKid } from './ratchet-ids.ts';
import type { PeerIndex, SFrameKey } from './types.ts';
import { drainPreEpochQueue, pipe } from './worker-frame.ts';
import {
	GRACE_WINDOW_MS,
	type InMsg,
	type OutMsg,
	type PerSenderKeyBundle,
	type WorkerState,
} from './worker-types.ts';

export function createWorkerState(emit: (msg: OutMsg) => void): WorkerState {
	return {
		role: null,
		peerId: null,
		selfPeerIndex: null,
		epochs: new Map(),
		currentEpoch: -1,
		currentMinValidEpoch: 0,
		ctr: 0n,
		wipeTimers: new Map(),
		preEpochQueue: [],
		draining: false,
		emit,
		codec: undefined,
		sifTrailer: undefined,
		ratchetWindowSize: 8,
	};
}

export async function handleMessage(state: WorkerState, msg: InMsg): Promise<void> {
	switch (msg.type) {
		case 'init':
			state.role = msg.role;
			state.peerId = msg.peerId;
			state.selfPeerIndex = msg.peerIndex;
			state.emit({ type: 'ready' });
			return;
		case 'epoch':
			installEpoch(state, msg.epoch, msg.selfPeerIndex, msg.keys);
			await drainPreEpochQueue(state);
			return;
		case 'rotate':
			// Benign: installEpoch already self-schedules the wipe when the
			// epoch advances. Kept for protocol compat / explicit rotation.
			installEpoch(state, msg.newEpoch, msg.selfPeerIndex, msg.keys);
			await drainPreEpochQueue(state);
			return;
		case 'streams':
			if (msg.codec !== undefined) state.codec = msg.codec;
			pipe(state, msg.side, msg.readable, msg.writable);
			return;
		case 'set-sif-trailer':
			state.sifTrailer = msg.trailer ?? undefined;
			return;
		case 'set-ratchet-window':
			state.ratchetWindowSize = Math.max(0, Math.floor(msg.size));
			return;
		case 'teardown':
			teardown(state);
			return;
	}
}

export function installEpoch(
	state: WorkerState,
	epoch: number,
	selfPeerIndex: PeerIndex,
	bundles: Map<PeerIndex, PerSenderKeyBundle>,
): void {
	const keys = new Map<PeerIndex, SFrameKey & { rawKey: Uint8Array }>();
	for (const [pi, bundle] of bundles) {
		keys.set(pi, {
			kid: makeKid(epoch, pi),
			epoch, peerIndex: pi,
			cryptoKey: bundle.cryptoKey, salt: bundle.salt,
			rawKey: bundle.rawKey,
		});
	}
	state.epochs.set(epoch, { epoch, selfPeerIndex, keys, ratchetSteps: new Map() });
	if (epoch > state.currentEpoch) {
		state.currentEpoch = epoch;
		state.selfPeerIndex = selfPeerIndex;
		state.ctr = 0n; // single sender-wide CTR, fresh per epoch (spec §2 L42)
		// Self-schedule the 2 s grace wipe of older epochs. This fires on BOTH
		// sender and receiver roles (receivers only see `epoch` messages per
		// M3.3 key-distribution protocol), so the stale-epoch gate at
		// decodeFrame() is reachable on the receiver path.
		scheduleWipeOfEpochsBelow(state, epoch);
	}
}

export function scheduleWipeOfEpochsBelow(state: WorkerState, newEpoch: number): void {
	for (const epoch of state.epochs.keys()) {
		if (epoch >= newEpoch) continue;
		if (state.wipeTimers.has(epoch)) continue;
		const timer = setTimeout(() => wipeEpoch(state, epoch), GRACE_WINDOW_MS);
		state.wipeTimers.set(epoch, timer);
	}
}

export function wipeEpoch(state: WorkerState, epoch: number): void {
	// Drop the per-sender keys; GC reclaims the underlying CryptoKey/ChainKey.
	// Also advance the stale-epoch gate so any late-arriving frame at this
	// epoch is rejected without a decrypt attempt (spec §7.4).
	state.epochs.delete(epoch);
	state.wipeTimers.delete(epoch);
	const nextValid = epoch + 1;
	if (nextValid > state.currentMinValidEpoch) state.currentMinValidEpoch = nextValid;
}

export function teardown(state: WorkerState): void {
	for (const timer of state.wipeTimers.values()) clearTimeout(timer);
	state.wipeTimers.clear();
	state.epochs.clear();
	state.preEpochQueue.length = 0; // discard queued pre-epoch frames on teardown
	state.ctr = 0n;
	state.currentEpoch = -1;
	state.currentMinValidEpoch = 0;
	state.selfPeerIndex = null;
}
