// Worker message-schema types and WorkerState shape.
// Concern: the wire / data contract between main thread ↔ encoded-frame
// worker, plus the in-worker state struct that the state-machine
// (worker-state.ts) mutates and the frame pipeline (worker-frame.ts) reads.
// No logic here — just types. Spec §§ 2.2, 4.3, 6.1, 7.4.

import type { PeerIndex, SFrameKey } from './types.ts';
import type { CipherSuite } from './ratchet-crypto.ts';

export type Role = 'sender' | 'receiver';
export type Side = 'encode' | 'decode';

/** Codecs for which the partial-encryption prefix table is defined. */
export type Codec = 'vp8' | 'vp9' | 'h264' | 'av1' | 'opus';

/**
 * Frame kind for VP8: 'key' = keyframe, 'inter' = interframe.
 * Only meaningful for VP8; other codecs ignore this field.
 * Derived from RTCEncodedVideoFrame.type in the stream transform.
 */
export type FrameKind = 'key' | 'inter';

export interface PerSenderKeyBundle {
	cryptoKey: CryptoKey;
	salt: Uint8Array;
	/**
	 * Raw 32-byte AES-GCM key material. Required for the within-epoch ratchet
	 * retry window: `deriveNextSenderKey` in ratchet-crypto.ts chains from these
	 * raw bytes. Kept alongside the non-extractable CryptoKey handle because
	 * WebCrypto does not allow round-tripping a non-extractable key back to bytes.
	 */
	rawKey: Uint8Array;
}

export interface InitMsg { type: 'init'; role: Role; peerId: string; peerIndex: PeerIndex; suite?: CipherSuite; preEpochQueueCap?: number }
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
export interface SetSifTrailerMsg {
	type: 'set-sif-trailer';
	/** `null` disables the trailer; any `Uint8Array` enables it with that byte sequence. */
	trailer: Uint8Array | null;
}
export interface SetRatchetWindowMsg {
	type: 'set-ratchet-window';
	/**
	 * Number of forward ratchet steps to attempt on AEAD failure for a known
	 * epoch + peer. 0 disables the feature entirely (any mismatch fails immediately).
	 */
	size: number;
}
export interface StreamsMsg {
	type: 'streams'; side: Side;
	readable: ReadableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
	writable: WritableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
	/** Optional per-track codec; drives codec-aware partial encryption prefix. */
	codec?: Codec;
}
export interface SetMetricsEnabledMsg { type: 'set-metrics-enabled'; enabled: boolean }
export type InMsg = InitMsg | EpochMsg | RotateMsg | TeardownMsg | SetSifTrailerMsg | SetRatchetWindowMsg | StreamsMsg | SetMetricsEnabledMsg;

/**
 * Structured telemetry event posted from the worker to the main thread when
 * metrics are enabled. Consumers register via `onMetrics(worker, handler)`.
 */
export type MetricsEvent =
	| { kind: 'encrypt'; epoch: number; peerIndex: number; bytes: number; codec?: Codec }
	| { kind: 'decrypt'; epoch: number; peerIndex: number; bytes: number }
	| { kind: 'decrypt_fail'; code: string; epoch?: number; peerIndex?: number }
	| { kind: 'ratchet_retry'; epoch: number; peerIndex: number; steps: number; succeeded: boolean }
	| { kind: 'queue_drop'; reason: 'pre_epoch_full' | 'stale_epoch'; epoch?: number }
	| { kind: 'epoch_advance'; from: number; to: number };

/** Worker → main-thread messages emitted through `WorkerState.emit`. */
export type OutMsg =
	| { type: 'ready' }
	| { type: 'metrics'; event: MetricsEvent }
	| { type: 'decrypt_failure'; reason: 'stale_epoch' | 'decrypt_failed' | 'queue_overflow' | 'decrypt_failed_after_epoch';
		kid?: number; epoch?: number; peerIndex?: number; ctr?: bigint; detail?: string }
	/**
	 * Receiver installed/activated a new epoch (currentEpoch advanced). First-class
	 * control signal — always emitted, independent of `metricsEnabled`. The main
	 * thread mirrors it via `FrameCryptor.getAppliedEpoch()` / `onEpochApplied`.
	 */
	| { type: 'epoch_applied'; epoch: number }
	/**
	 * Receiver is DROPPING inbound frames because no usable epoch key is installed
	 * (queue-overflow at the bounded pre-epoch ring). A first-class RECOVERY signal
	 * derived from the pre_epoch_full/queue_overflow drop points — always emitted,
	 * COALESCED to at most one per `STARVE_COALESCE_MS` per episode. `peerIndex` is
	 * the in-payload SFrame-header hint (never an RTP header extension); `sinceMs`
	 * is elapsed time since the episode's first drop; `framesDropped` is cumulative.
	 */
	| { type: 'decrypt_starved'; peerIndex?: number; framesDropped: number; sinceMs: number };

/** Bounded pre-epoch frame queue entry (M3.5 first-peer epoch race fix). */
export interface QueuedFrame {
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame;
}

/** Cap for the pre-epoch ring buffer (≈1.5 s @ 30 fps). */
export const PRE_EPOCH_QUEUE_CAP = 50;

export interface EpochEntry {
	epoch: number;
	selfPeerIndex: PeerIndex;
	keys: Map<PeerIndex, SFrameKey & { rawKey: Uint8Array }>;
	/**
	 * Per-sender ratchet step cursor. `ratchetSteps.get(peerIndex)` is the highest
	 * step index whose key is currently cached in `keys`. Starts at 0 (the key
	 * derived at installEpoch time). Advanced forward-only when the retry window
	 * finds a matching step — subsequent frames at the same step decrypt immediately.
	 * Cleaned up automatically when the EpochEntry is deleted by wipeEpoch().
	 */
	ratchetSteps: Map<PeerIndex, number>;
}

export interface WorkerState {
	role: Role | null;
	peerId: string | null;
	selfPeerIndex: PeerIndex | null;
	/** RFC 9605 §4.5 cipher suite active for this worker. */
	suite: CipherSuite;
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
	/** Per-track codec; drives codec-aware partial encryption.  Undefined = full encrypt. */
	codec?: Codec;
	/**
	 * Number of forward ratchet steps to attempt per-sender on AEAD failure for
	 * a known epoch + known peer. Default 8. Set to 0 to disable the feature
	 * (any AEAD failure is surfaced immediately with no retry).
	 *
	 * This is a liveness feature: it lets a receiver catch up when the sender
	 * has advanced its per-sender key by fewer steps than the window size — a
	 * scenario that occurs naturally when in-flight frames arrive out of order
	 * relative to the sender's key advancement. See docs/SECURITY.md for why
	 * this does NOT widen attacker decryptability.
	 */
	ratchetWindowSize: number;
	/**
	 * Optional SIF (Secure Interoperable Frame) trailer bytes.
	 * When set, the encoder appends these bytes after the SFrame ciphertext, and the
	 * decoder uses their presence to distinguish E2EE frames from plain frames in
	 * mixed-room deployments. `undefined` = feature disabled; wire format unchanged.
	 * The trailer is NOT inside AES-GCM AAD — it is a routing hint only.
	 */
	sifTrailer?: Uint8Array;
	/**
	 * When true, the worker posts `{ type: 'metrics'; event: MetricsEvent }` messages
	 * after each encrypt, decrypt, ratchet-retry, queue-drop, and epoch-advance.
	 * Disabled by default to keep the hot path zero-cost.
	 */
	metricsEnabled: boolean;
	/**
	 * Injectable monotonic clock (ms). Defaults to `performance.now()` — a true
	 * monotonic clock, unlike `Date.now()` (which can jump backward on an NTP
	 * correction, suppressing a coalesced emit, or forward, emitting early).
	 * Used only for the starvation-signal coalescing window (observability
	 * timing, not a security boundary); injectable so tests can drive it.
	 */
	now: () => number;
	/**
	 * Pre-epoch ring-buffer cap. A tuning value (NOT a security parameter);
	 * defaults to `PRE_EPOCH_QUEUE_CAP`. Overridable via the init message.
	 */
	preEpochQueueCap: number;
	/** True while a starvation episode (queue-overflow drops at no/wrong epoch) is ongoing. */
	starveActive: boolean;
	/** `state.now()` at the first drop of the current starvation episode. */
	starveSinceMs: number;
	/** Cumulative dropped-frame count within the current starvation episode. */
	starveFramesDropped: number;
	/** `state.now()` of the last emitted `decrypt_starved` (drives coalescing). */
	starveLastEmitMs: number;
	/** Last peer_index seen on a dropped frame (in-payload KID hint; may be undefined). */
	starvePeerIndex?: PeerIndex;
}

export const GRACE_WINDOW_MS = 2000;

/** Coalesce window (ms) for `decrypt_starved` — at most one emit per window per episode. */
export const STARVE_COALESCE_MS = 1000;
