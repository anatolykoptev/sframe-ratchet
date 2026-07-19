// Encoded-frame worker state machine — state-bookkeeping, no DOM / no `self`.
// Concern: per-epoch key-table install, stale-epoch gate advancement, and the
// 2 s grace-window wipe timer (spec §§ 2.2, 4.4 L151, 7.4).
// Message types live in worker-types.ts; frame I/O lives in worker-frame.ts;
// DOM glue lives in worker.ts. This module is pure logic so it can be driven
// from unit tests (sframe.smoke.test.ts) without spawning a real Worker.

import { makeKidCodec, FIXED_KID_CODEC } from './kid-format.ts';
import type { PeerIndex, SFrameKey } from './types.ts';
import { drainPreEpochQueue, pipe } from './worker-frame.ts';
import { zeroize } from './internal/buffer.ts';
import { emitMetric } from './metrics.ts';
import { DEFAULT_CIPHER_SUITE } from './ratchet-crypto.ts';
import {
	GRACE_WINDOW_MS,
	PRE_EPOCH_QUEUE_CAP,
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
		suite: DEFAULT_CIPHER_SUITE,
		kidCodec: FIXED_KID_CODEC,
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
		replayWindowSize: 64,
		replayWindows: new Map(),
		metricsEnabled: false,
		now: () => performance.now(),
		preEpochQueueCap: PRE_EPOCH_QUEUE_CAP,
		starveActive: false,
		starveSinceMs: 0,
		starveFramesDropped: 0,
		starveLastEmitMs: 0,
		starvePeerIndex: undefined,
		failureCounts: new Map(),
		failureTolerance: -1,
		ratchetPromises: new Map(),
	};
}

export async function handleMessage(state: WorkerState, msg: InMsg): Promise<void> {
	switch (msg.type) {
		case 'init':
			state.role = msg.role;
			state.peerId = msg.peerId;
			state.selfPeerIndex = msg.peerIndex;
			if (msg.suite !== undefined) state.suite = msg.suite;
			if (msg.kidFormat !== undefined) {
				state.kidCodec = makeKidCodec(msg.kidFormat, msg.mlsConfig);
			}
			if (msg.preEpochQueueCap !== undefined && Number.isFinite(msg.preEpochQueueCap) && msg.preEpochQueueCap > 0) {
				state.preEpochQueueCap = Math.floor(msg.preEpochQueueCap);
			}
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
		case 'set-metrics-enabled':
			state.metricsEnabled = msg.enabled;
			return;
		case 'set-replay-window': {
			state.replayWindowSize = Math.max(0, Math.floor(msg.size));
			// Existing windows were created with the old size — clear them all
			// so subsequent frames get fresh windows at the new size.
			for (const inner of state.replayWindows.values()) {
				for (const w of inner.values()) w.clear();
			}
			state.replayWindows.clear();
			return;
		}
		case 'set-failure-tolerance': {
			// Allow -1 (unlimited); clamp other negatives to -1. Non-integers floored.
			const t = Math.floor(msg.tolerance);
			state.failureTolerance = t < -1 ? -1 : t;
			// Changing the threshold invalidates existing counts — clear them so
			// a previously-invalidated key gets a fresh slate under the new rule.
			state.failureCounts.clear();
			return;
		}
		case 'teardown':
			teardown(state);
			return;
	}
}

/**
 * Build the failure-count map key for (epoch, peerIndex).
 */
function failureKey(epoch: number, peerIndex: PeerIndex): string {
	return `${epoch}:${peerIndex}`;
}

/**
 * Returns true when the key for (epoch, peerIndex) has been marked invalid:
 * failureTolerance >= 0 AND the consecutive AEAD failure count for this key
 * exceeds the tolerance (issue #14). When true, decodeFrame / drainPreEpochQueue
 * drop the frame WITHOUT attempting AEAD — saving CPU and surfacing the problem
 * via the `key_invalidated` metric event.
 */
export function isKeyInvalid(state: WorkerState, epoch: number, peerIndex: PeerIndex): boolean {
	if (state.failureTolerance < 0) return false;
	const count = state.failureCounts.get(failureKey(epoch, peerIndex)) ?? 0;
	return count > state.failureTolerance;
}

/**
 * Increment the consecutive AEAD failure count for (epoch, peerIndex). If the
 * count now exceeds `failureTolerance`, emit a `key_invalidated` metric event
 * (exactly once, at the transition point). Only AEAD-correctness failures
 * (AEADAuthError, RatchetWindowExhaustedError) should call this — NOT
 * StaleEpochError / HeaderParseError / ReplayError / KeyNotFoundError, which
 * are not key-correctness signals.
 */
export function recordFailure(state: WorkerState, epoch: number, peerIndex: PeerIndex): void {
	if (state.failureTolerance < 0) return; // unlimited — no tracking needed
	const key = failureKey(epoch, peerIndex);
	const prev = state.failureCounts.get(key) ?? 0;
	const next = prev + 1;
	state.failureCounts.set(key, next);
	// Emit the metric exactly once at the transition into invalid state.
	if (prev <= state.failureTolerance && next > state.failureTolerance) {
		emitMetric(state, { kind: 'key_invalidated', epoch, peerIndex, failures: next });
	}
}

/**
 * Reset the consecutive AEAD failure count for (epoch, peerIndex) to 0 after a
 * successful decrypt. A single good frame clears the slate.
 */
export function recordSuccess(state: WorkerState, epoch: number, peerIndex: PeerIndex): void {
	if (state.failureTolerance < 0) return; // unlimited — nothing tracked
	state.failureCounts.set(failureKey(epoch, peerIndex), 0);
}

/**
 * Reset the failure count for (epoch, peerIndex) to 0. Called on new key
 * install so a fresh key starts with a clean failure slate.
 */
export function resetFailureCount(state: WorkerState, epoch: number, peerIndex: PeerIndex): void {
	state.failureCounts.delete(failureKey(epoch, peerIndex));
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
			kid: state.kidCodec.encode(epoch, pi),
			epoch, peerIndex: pi,
			cryptoKey: bundle.cryptoKey, salt: bundle.salt,
			rawKey: bundle.rawKey,
		});
	}
	state.epochs.set(epoch, { epoch, selfPeerIndex, keys, ratchetSteps: new Map() });
	// A fresh key starts with a clean failure slate (issue #14). Reset the
	// per-(epoch, peerIndex) failure count for every peer in the new epoch's
	// key table so a previously-invalidated key is retried after re-install.
	for (const pi of bundles.keys()) {
		resetFailureCount(state, epoch, pi);
	}
	if (epoch > state.currentEpoch) {
		const prevEpoch = state.currentEpoch;
		state.currentEpoch = epoch;
		state.selfPeerIndex = selfPeerIndex;
		state.ctr = 0n; // single sender-wide CTR, fresh per epoch (spec §2 L42)
		// Self-schedule the 2 s grace wipe of older epochs. This fires on BOTH
		// sender and receiver roles (receivers only see `epoch` messages per
		// M3.3 key-distribution protocol), so the stale-epoch gate at
		// decodeFrame() is reachable on the receiver path.
		scheduleWipeOfEpochsBelow(state, epoch);
		// First-class recovery/observability signal: the receiver now has an
		// active epoch. Always emitted (independent of metricsEnabled) so the
		// main thread can observe recovery from a stuck currentEpoch === -1.
		state.emit({ type: 'epoch_applied', epoch });
		// Telemetry: epoch_advance. Only fires when a genuinely new epoch is
		// installed (prevEpoch >= 0 means at least one epoch was already active).
		if (prevEpoch >= 0) {
			emitMetric(state, { kind: 'epoch_advance', from: prevEpoch, to: epoch });
		}
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
	// Zeroize raw AES key material before dropping the reference so the bytes
	// don't linger in the JS heap until GC (repo-review-council #32).
	const entry = state.epochs.get(epoch);
	if (entry) {
		for (const k of entry.keys.values()) {
			if (k.rawKey) zeroize(k.rawKey);
		}
	}
	// Drop the per-sender keys; GC reclaims the underlying CryptoKey.
	// Also advance the stale-epoch gate so any late-arriving frame at this
	// epoch is rejected without a decrypt attempt (spec §7.4).
	state.epochs.delete(epoch);
	state.wipeTimers.delete(epoch);
	// Anti-replay windows for the wiped epoch are no longer needed — a frame
	// at this epoch will be rejected by the stale-epoch gate before the replay
	// check runs. Drop them to free memory (RFC 9605 §9.3, issue #10).
	state.replayWindows.delete(epoch);
	const nextValid = epoch + 1;
	if (nextValid > state.currentMinValidEpoch) state.currentMinValidEpoch = nextValid;
}

export function teardown(state: WorkerState): void {
	for (const timer of state.wipeTimers.values()) clearTimeout(timer);
	state.wipeTimers.clear();
	state.epochs.clear();
	state.replayWindows.clear();
	state.preEpochQueue.length = 0; // discard queued pre-epoch frames on teardown
	state.ctr = 0n;
	state.currentEpoch = -1;
	state.currentMinValidEpoch = 0;
	state.selfPeerIndex = null;
	state.failureCounts.clear();
	state.ratchetPromises.clear();
}
