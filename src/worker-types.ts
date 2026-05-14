// Worker message-schema types and WorkerState shape.
// Concern: the wire / data contract between main thread ↔ encoded-frame
// worker, plus the in-worker state struct that the state-machine
// (worker-state.ts) mutates and the frame pipeline (worker-frame.ts) reads.
// No logic here — just types. Spec §§ 2.2, 4.3, 6.1, 7.4.

import type { PeerIndex, SFrameKey } from './types.ts';

export type Role = 'sender' | 'receiver';
export type Side = 'encode' | 'decode';

export interface PerSenderKeyBundle { cryptoKey: CryptoKey; salt: Uint8Array }

export interface InitMsg { type: 'init'; role: Role; peerId: string; peerIndex: PeerIndex }
export interface EpochMsg {
	type: 'epoch';
	epoch: number;
	peerIndexMap: Record<string, PeerIndex>;
	selfPeerIndex: PeerIndex;
	keys: Map<PeerIndex, PerSenderKeyBundle>;
}
export interface RotateMsg {
	type: 'rotate';
	newEpoch: number;
	peerIndexMap: Record<string, PeerIndex>;
	selfPeerIndex: PeerIndex;
	keys: Map<PeerIndex, PerSenderKeyBundle>;
}
export interface TeardownMsg { type: 'teardown' }
export interface StreamsMsg {
	type: 'streams'; side: Side;
	readable: ReadableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
	writable: WritableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
}
export type InMsg = InitMsg | EpochMsg | RotateMsg | TeardownMsg | StreamsMsg;

/** Worker → main-thread messages emitted through `WorkerState.emit`. */
export type OutMsg =
	| { type: 'ready' }
	| { type: 'decrypt_failure'; reason: 'stale_epoch' | 'decrypt_failed' | 'queue_overflow' | 'decrypt_failed_after_epoch';
		kid?: number; epoch?: number; peerIndex?: number; ctr?: bigint; detail?: string };

/** Bounded pre-epoch frame queue entry (M3.5 first-peer epoch race fix). */
export interface QueuedFrame {
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame;
}

/** Cap for the pre-epoch ring buffer (≈1.5 s @ 30 fps). */
export const PRE_EPOCH_QUEUE_CAP = 50;

export interface EpochEntry {
	epoch: number;
	selfPeerIndex: PeerIndex;
	keys: Map<PeerIndex, SFrameKey>;
}

export interface WorkerState {
	role: Role | null;
	peerId: string | null;
	selfPeerIndex: PeerIndex | null;
	epochs: Map<number, EpochEntry>; // receive table (spec §4.3 L145)
	currentEpoch: number;
	currentMinValidEpoch: number; // stale-epoch gate (spec §7.4)
	ctr: bigint; // single sender-wide CTR, reset on epoch install (spec §2 L42 fix)
	wipeTimers: Map<number, ReturnType<typeof setTimeout>>; // 2 s grace (spec §4.4 L151)
	/** Pre-epoch frame ring buffer. Drained by drainPreEpochQueue() after installEpoch. */
	preEpochQueue: Array<QueuedFrame>;
	/** Re-entrancy guard for drainPreEpochQueue — true while a drain is active. */
	draining: boolean;
	emit: (msg: OutMsg) => void;
}

export const GRACE_WINDOW_MS = 2000;
