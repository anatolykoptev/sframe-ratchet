// Frame-pipeline layer: encodeFrame / decodeFrame + the stream pipe wiring.
// Concern: WebCrypto I/O per frame and the stale-epoch gate. Distinct from
// worker-state.ts (epoch/key table bookkeeping) and worker.ts (DOM glue).
// Spec §§ 2 L42, 2.2, 6.3, 7.4.
//
// M3.5: pre-epoch ring buffer. When decodeFrame can't find a key (epoch not
// yet installed), the frame is queued in state.preEpochQueue (cap
// PRE_EPOCH_QUEUE_CAP). drainPreEpochQueue() is called by worker-state.ts
// after installEpoch to retry decryption. Overflow drops the oldest entry
// and emits decrypt_failure{reason:'queue_overflow'}.

import { parseHeader, serializeHeader } from './sframe-header.ts';
import { sframeDecrypt, sframeEncrypt, sframeEncryptInto } from './sframe.ts';
import { splitKid } from './ratchet-ids.ts';
import { deriveNextSenderKey } from './ratchet-crypto.ts';
import { STARVE_COALESCE_MS, type FrameKind, type Side, type WorkerState } from './worker-types.ts';
import { toArrayBuffer as toExclusiveArrayBuffer } from './internal/buffer.js';
import { ctEndsWith } from './internal/constant-time.js';
import { getUnencryptedBytes } from './codec-partial.ts';
import type { PeerIndex } from './types.ts';
import { KeyNotFoundError, KeyInvalidError, QueueFullError, RatchetWindowExhaustedError, ReplayError, StaleEpochError, AEADAuthError } from './errors.ts';
import { MediaReplayWindow } from './replay.ts';
import { emitMetric } from './metrics.ts';
import { isKeyInvalid, recordFailure, recordSuccess } from './worker-state.ts';

/**
 * Get or create the per-(epoch, peerIndex) anti-replay window (RFC 9605 §9.3,
 * issue #10). Windows are created lazily at the current `replayWindowSize` and
 * deleted by wipeEpoch() on epoch rotation. O(1) lookup.
 */
function getReplayWindow(state: WorkerState, epoch: number, peerIndex: number): MediaReplayWindow {
	let inner = state.replayWindows.get(epoch);
	if (!inner) {
		inner = new Map();
		state.replayWindows.set(epoch, inner);
	}
	let w = inner.get(peerIndex);
	if (!w) {
		w = new MediaReplayWindow(state.replayWindowSize);
		inner.set(peerIndex, w);
	}
	return w;
}

export function pipe(
	state: WorkerState,
	side: Side,
	readable: ReadableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>,
	writable: WritableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>,
): void {
	const transform = new TransformStream<
		RTCEncodedVideoFrame | RTCEncodedAudioFrame,
		RTCEncodedVideoFrame | RTCEncodedAudioFrame
	>({
		async transform(frame, controller) {
			// Derive VP8 frame kind from the native encoded-frame metadata.
			// RTCEncodedVideoFrame.type is 'key' | 'delta'; audio frames have no
			// such property. Map to our FrameKind ('key' | 'inter').
			const rawType = (frame as RTCEncodedVideoFrame).type;
			const frameKind: FrameKind | undefined =
				rawType === 'key' ? 'key' : rawType === 'delta' ? 'inter' : undefined;
			try {
				if (side === 'encode') await encodeFrame(state, frame, frameKind);
				else await decodeFrame(state, frame);
				controller.enqueue(frame);
			} catch (err) {
				// M3.3 race gotcha #1: a sender-side frame may arrive at the
				// transform BEFORE the first epoch propagates over DC id:1.
				// `encodeFrame` throws "worker: no active send epoch" in that
				// window. Surface a breadcrumb so the smoke test can grep for
				// it; the frame is dropped (not queued) — by the time the
				// epoch lands the encoder has already moved on, and a delayed
				// frame would carry a stale CTR. M3.4 may add a small
				// pre-epoch buffer; for now the keyframe-request loop will
				// recover the receiver's video within ~1s.
				const msg = err instanceof Error ? err.message : String(err);
				if (side === 'encode' && msg === 'worker: no active send epoch') {
					console.warn('[gc:e2e] frame before epoch — dropped');
				}
				// Decode-side: decodeFrame already called state.emit(decrypt_failure)
				// before rethrowing. Add a debug breadcrumb behind ?__e2e_debug=1
				// so developers can see individual frame drops without prod noise.
				if (side === 'decode' && (globalThis as Record<string, unknown>).__e2e_debug === true) {
					console.warn('[sframe] decode drop', { reason: msg });
				}
				// Drop frames that fail to decrypt; sender-side errors are fatal.
				if (side === 'encode') throw err;
			}
		},
	});
	readable.pipeThrough(transform).pipeTo(writable).catch(() => {
		// Stream terminated; nothing to do.
	});
}

export async function encodeFrame(
	state: WorkerState,
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
	frameKind?: FrameKind,
): Promise<void> {
	const entry = state.epochs.get(state.currentEpoch);
	if (!entry) throw new Error('worker: no active send epoch');
	const key = entry.keys.get(entry.selfPeerIndex);
	if (!key) throw new Error('worker: no self key in current epoch');

	// Atomic read-then-increment of the sender-wide CTR. Shared across all
	// SSRCs (audio + video + …) the sender emits under this epoch, matching
	// spec §2 L42 / §2.2 per-sender-per-epoch invariant.
	const ctr = state.ctr;
	state.ctr = ctr + 1n;

	const plaintext = new Uint8Array(frame.data);

	// Codec-aware partial encryption: N leading bytes stay in the clear so the
	// SFU can route by frame type and decoders fail gracefully on key mismatch.
	// When codec is unset (undefined), N=0 — identical to the current full-encrypt
	// path. NOTE: the unencrypted prefix is NOT in AES-GCM AAD; see SECURITY.md.
	const N = Math.min(getUnencryptedBytes(state.codec, frameKind), plaintext.byteLength);
	const prefix = plaintext.subarray(0, N);  // untouched
	const body = plaintext.subarray(N);       // encrypted

	// Hot path: build wire buffer in one allocation.
	// Serialise header first so we know its length for sizing the buffer.
	const header = serializeHeader(key.kid, ctr);
	// AEAD_TAG_BYTES (16) is baked into sframeEncryptInto; body.length is plaintext.
	const AEAD_TAG_BYTES = 16;
	const trailer = state.sifTrailer;
	const trailerLen = trailer ? trailer.byteLength : 0;
	// Wire layout: [prefix (N bytes)] [SFrame header] [ciphertext + tag] [SIF trailer (optional)]
	// The SIF trailer is appended OUTSIDE the AEAD — it is a routing hint, not a security boundary.
	const wire = new Uint8Array(N + header.length + body.byteLength + AEAD_TAG_BYTES + trailerLen);
	if (N > 0) wire.set(prefix, 0);
	const written = await sframeEncryptInto(wire, N, header, body, key, ctr);
	if (trailer) wire.set(trailer, N + written);
	// wire is a freshly allocated exclusive ArrayBuffer — .buffer is safe to assign
	// directly without the toExclusiveArrayBuffer copy.
	frame.data = wire.buffer;
	emitMetric(state, {
		kind: 'encrypt',
		epoch: key.epoch,
		peerIndex: key.peerIndex,
		bytes: plaintext.byteLength,
		codec: state.codec,
	});
}


/**
 * Attempt to decrypt `buf` (full SFrame: header+ciphertext+tag) using the
 * known key for (epoch, peerIndex), then — on AEAD failure — try forward
 * ratchet steps up to `state.ratchetWindowSize`.
 *
 * Returns the decrypted plaintext on success. On success at step N > 0 the
 * per-sender cached key is advanced to step N so subsequent frames at the same
 * step decrypt on the first try without a retry loop.
 *
 * Throws the ORIGINAL decrypt error after exhausting the window, so the caller
 * can surface it (no silent drop). Also throws immediately when:
 *   - The epoch is unknown (no EpochEntry found).
 *   - The peer is unknown within the epoch (no initial key found).
 *   - ratchetWindowSize === 0 (retry disabled; exactly 1 AEAD attempt is made).
 *
 * IMPORTANT: this function does NOT cross epoch boundaries. A frame carrying a
 * different epoch KID is rejected by the normal sframeDecrypt resolver path
 * (key not found) and the error propagates up without consuming retry budget.
 *
 * Forward-only cursor note: if a sender skips ahead M steps and then a frame
 * from BEFORE the advance arrives, the cached step is already M. The retry loop
 * tries steps M+1 .. M+window — none match the older frame. The older frame
 * fails. This is expected and correct: the retry window smooths RTP reorder
 * jitter around a single key advance; it does not reconstruct past keys.
 */
async function tryDecryptWithRatchet(
	state: WorkerState,
	buf: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
): Promise<Uint8Array> {
	const entry = state.epochs.get(epoch);
	if (!entry) {
		throw new KeyNotFoundError(`sframe: no epoch entry for epoch=${epoch}`, { epoch, peerIndex });
	}
	const key = entry.keys.get(peerIndex);
	if (!key) {
		throw new KeyNotFoundError(`sframe: key not found for epoch=${epoch} peer=${peerIndex}`, { epoch, peerIndex });
	}

	// Step 0 — try the currently cached key.
	let firstError: unknown;
	try {
		return await sframeDecrypt(buf, ({ epoch: e, peerIndex: pi }) => {
			const ep = state.epochs.get(e);
			return ep?.keys.get(pi) ?? null;
		});
	} catch (err) {
		firstError = err;
	}

	// If the window is disabled, surface the original failure immediately.
	if (state.ratchetWindowSize === 0) throw firstError;

	// Steps 1..ratchetWindowSize — forward ratchet.
	let currentRaw = key.rawKey;
	const salt = key.salt;
	for (let step = 1; step <= state.ratchetWindowSize; step++) {
		const next = await deriveNextSenderKey(currentRaw, salt, epoch, peerIndex, state.suite);
		try {
			const plaintext = await sframeDecrypt(buf, ({ epoch: e, peerIndex: pi }) => {
				if (e === epoch && pi === peerIndex) return next;
				const ep = state.epochs.get(e);
				return ep?.keys.get(pi) ?? null;
			});
			// Success at step N: advance the cached key so subsequent frames at
			// this step hit immediately without re-deriving.
			entry.keys.set(peerIndex, next);
			entry.ratchetSteps.set(peerIndex, (entry.ratchetSteps.get(peerIndex) ?? 0) + step);
			emitMetric(state, { kind: 'ratchet_retry', epoch, peerIndex, steps: step, succeeded: true });
			return plaintext;
		} catch {
			// This step failed; advance and try next.
			currentRaw = next.rawKey;
		}
	}

	// Window exhausted — wrap in a typed error so callers can branch on it.
	emitMetric(state, { kind: 'ratchet_retry', epoch, peerIndex, steps: state.ratchetWindowSize, succeeded: false });
	throw new RatchetWindowExhaustedError(
		`sframe: ratchet window exhausted (${state.ratchetWindowSize} steps) for epoch=${epoch} peer=${peerIndex}`,
		{ epoch, peerIndex, attempts: state.ratchetWindowSize },
	);
}

export async function decodeFrame(
	state: WorkerState,
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
): Promise<void> {
	const raw = new Uint8Array(frame.data);

	// SIF trailer gate — checked BEFORE codec prefix peel and BEFORE parseHeader.
	// When a trailer is configured:
	//   - Frame ends with trailer → strip it, proceed with normal decrypt on the remainder.
	//   - Frame does NOT end with trailer → this is a non-E2EE (plain) frame.
	//     Pass it through unchanged without attempting AEAD. This is the mixed-room case.
	//     A short frame (shorter than the trailer) also falls here safely.
	const trailer = state.sifTrailer;
	let payload = raw; // view of the bytes to decrypt (trailer-stripped if applicable)
	if (trailer !== undefined) {
		if (!ctEndsWith(raw, trailer)) {
			// Non-E2EE frame — pass through unchanged.
			if ((globalThis as Record<string, unknown>).__e2e_debug === true) {
				console.debug('[sframe] SIF pass-through: no trailer, treating as plain frame');
			}
			return; // frame.data untouched
		}
		// Strip the trailer — the rest of the pipeline sees only the SFrame bytes.
		payload = raw.subarray(0, raw.byteLength - trailer.byteLength);
	}

	// Codec-aware prefix peel: receiver must know the codec (set via StreamsMsg)
	// to determine N. Both sides must agree. N=0 when codec is unset (default).
	// Clamp to frame length to handle truncated/corrupt frames safely.
	const rawType = (frame as RTCEncodedVideoFrame).type;
	const frameKind: FrameKind | undefined =
		rawType === 'key' ? 'key' : rawType === 'delta' ? 'inter' : undefined;
	const N = Math.min(getUnencryptedBytes(state.codec, frameKind), payload.byteLength);
	const prefix = payload.subarray(0, N);   // unencrypted prefix (not authenticated)
	const buf = payload.subarray(N);         // [SFrame header][ciphertext+tag]

	let hdrKid = -1;
	let hdrEpoch = -1;
	let hdrPeerIndex = -1;
	let hdrCtr = 0n;
	try {
		const hdr = parseHeader(buf);
		const { epoch, peerIndex } = splitKid(hdr.kid);
		hdrKid = hdr.kid; hdrEpoch = epoch; hdrPeerIndex = peerIndex; hdrCtr = hdr.ctr;
		// Stale-epoch gate — fire BEFORE any decrypt attempt (spec §7.4).
		if (epoch < state.currentMinValidEpoch) {
			state.emit({
				type: 'decrypt_failure', reason: 'stale_epoch',
				kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
			});
			emitMetric(state, { kind: 'queue_drop', reason: 'stale_epoch', epoch });
			throw new StaleEpochError(
				`sframe: stale epoch ${epoch} (min valid: ${state.currentMinValidEpoch})`,
				{ frameEpoch: epoch, minValidEpoch: state.currentMinValidEpoch, kid: hdr.kid },
			);
		}
		// M3.5: pre-epoch race guard. If NO epoch has ever been installed yet
		// (currentEpoch === -1), this receiver is still waiting for its first
		// KeyExchange identity exchange to complete. Queue the frame for retry
		// instead of dropping it silently.
		//
		// We restrict queuing to the truly-no-epoch case (currentEpoch === -1)
		// rather than any missing epoch: once the receiver has at least one
		// epoch installed, a frame for an unknown epoch is a genuine cross-epoch
		// mismatch (wrong sender state), not a timing race.
		//
		// M3.4 deferred — multi-epoch races during rotation surface as
		// decrypt_failed (not re-queued); distinguish via reason field in events.
		if (state.currentEpoch === -1) {
			enqueuePreEpoch(state, frame, peerIndex);
			return; // not an error from caller's perspective
		}

		// Anti-replay sliding window (RFC 9605 §9.3, issue #10).
		// AFTER parseHeader + stale-epoch gate, BEFORE AEAD. A replayed frame
		// is rejected without consuming ratchet-retry budget or touching
		// WebCrypto. accept() is called only after a successful decrypt below.
		const replayWindow = getReplayWindow(state, epoch, peerIndex);
		if (!replayWindow.check(hdr.ctr)) {
			state.emit({
				type: 'decrypt_failure', reason: 'replay',
				kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
			});
			emitMetric(state, { kind: 'queue_drop', reason: 'replay', epoch });
			emitMetric(state, { kind: 'replay_drop', epoch, peerIndex, ctr: hdr.ctr.toString() });
			throw new ReplayError(
				`sframe: replay detected (epoch=${epoch} peer=${peerIndex} ctr=${hdr.ctr})`,
				{ epoch, peerIndex, ctr: hdr.ctr },
			);
		}

		// Failure-invalidation gate (issue #14, pattern from livekit
		// ParticipantKeyHandler.ts:58). AFTER parseHeader + stale-epoch gate +
		// replay check, BEFORE tryDecryptWithRatchet. When the key for
		// (epoch, peerIndex) has exceeded `failureTolerance` consecutive AEAD
		// failures, drop the frame WITHOUT attempting AEAD — saving CPU and
		// surfacing the problem via the `key_invalidated` metric event. The
		// count is reset by a successful decrypt (recordSuccess) or by a fresh
		// key install (resetFailureCount in installEpoch).
		if (isKeyInvalid(state, epoch, peerIndex)) {
			state.emit({
				type: 'decrypt_failure', reason: 'key_invalid',
				kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
			});
			emitMetric(state, { kind: 'decrypt_fail', code: 'KEY_INVALID', epoch, peerIndex });
			throw new KeyInvalidError(
				`sframe: key invalid for epoch=${epoch} peer=${peerIndex} (failures exceeded tolerance)`,
				{ epoch, peerIndex, failures: state.failureCounts.get(`${epoch}:${peerIndex}`) ?? 0 },
			);
		}

		const opened = await tryDecryptWithRatchet(state, buf, epoch, peerIndex);
		// Record the CTR as seen ONLY after a successful AEAD decrypt.
		replayWindow.accept(hdr.ctr);
		// A successful decrypt resets the consecutive AEAD failure count for
		// this key (issue #14) — a single good frame clears the slate.
		recordSuccess(state, epoch, peerIndex);

		// Reassemble: [unencrypted prefix] [decrypted plaintext]
		const plaintext = new Uint8Array(N + opened.byteLength);
		plaintext.set(prefix, 0);
		plaintext.set(opened, N);
		frame.data = toExclusiveArrayBuffer(plaintext);
		// A frame decoded — the receiver is healthy; end any starvation episode.
		clearStarve(state);
		emitMetric(state, { kind: 'decrypt', epoch, peerIndex, bytes: plaintext.byteLength });
	} catch (err) {
		// Failure-invalidation tracking (issue #14): only count AEAD-correctness
		// failures (AEADAuthError, RatchetWindowExhaustedError) as key-correctness
		// signals. NOT StaleEpochError / HeaderParseError / ReplayError /
		// KeyNotFoundError / KeyInvalidError — those are not AEAD failures.
		if (
			hdrEpoch >= 0 && hdrPeerIndex >= 0 &&
			(err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError)
		) {
			recordFailure(state, hdrEpoch, hdrPeerIndex);
		}
		// StaleEpochError, ReplayError, and KeyInvalidError already emitted
		// their decrypt_failure events above (with specific reasons). Only emit
		// the generic decrypt_failed for other errors.
		if (!(err instanceof StaleEpochError) && !(err instanceof ReplayError) && !(err instanceof KeyInvalidError)) {
			const detail = err instanceof Error ? err.message : String(err);
			const errCode = err instanceof Error && 'code' in err ? String((err as { code: unknown }).code) : 'UNKNOWN';
			emitMetric(state, {
				kind: 'decrypt_fail',
				code: errCode,
				epoch: hdrEpoch >= 0 ? hdrEpoch : undefined,
				peerIndex: hdrPeerIndex >= 0 ? hdrPeerIndex : undefined,
			});
			state.emit({
				type: 'decrypt_failure', reason: 'decrypt_failed',
				kid: hdrKid >= 0 ? hdrKid : undefined,
				epoch: hdrEpoch >= 0 ? hdrEpoch : undefined,
				peerIndex: hdrPeerIndex >= 0 ? hdrPeerIndex : undefined,
				ctr: hdrCtr,
				detail,
			});
		} else {
			// StaleEpochError / ReplayError: emit metrics event too
			emitMetric(state, {
				kind: 'decrypt_fail',
				code: (err as { code: string }).code,
				epoch: hdrEpoch >= 0 ? hdrEpoch : undefined,
				peerIndex: hdrPeerIndex >= 0 ? hdrPeerIndex : undefined,
			});
		}
		throw err;
	}
}

/**
 * Push a frame into the pre-epoch queue, enforcing the FIFO ring cap.
 * Overflow drops the oldest entry and emits decrypt_failure{reason:'queue_overflow'}.
 * Used by both enqueuePreEpoch (initial enqueue) and drainPreEpochQueue
 * (re-enqueue on still-missing key) so cap is enforced on all paths.
 */
function pushToQueue(
	state: WorkerState,
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
	peerIndex?: PeerIndex,
): void {
	if (state.preEpochQueue.length >= state.preEpochQueueCap) {
		// Drop oldest (FIFO ring — shift the front).
		state.preEpochQueue.shift();
		state.emit({ type: 'decrypt_failure', reason: 'queue_overflow' });
		emitMetric(state, { kind: 'queue_drop', reason: 'pre_epoch_full' });
		// Promote the drop to a first-class, coalesced recovery signal.
		noteStarveDrop(state, peerIndex);
	}
	state.preEpochQueue.push({ frame });
}

/**
 * Note a frame dropped at pre-epoch overflow as part of a starvation episode
 * and emit a COALESCED `decrypt_starved` signal. Emits immediately on the first
 * drop of an episode (so recovery can start), then at most once per
 * STARVE_COALESCE_MS. `framesDropped` is cumulative for the episode; `sinceMs`
 * is elapsed time since the first drop. Reset by clearStarve() on the next
 * successful decode. `peerIndex` is the in-payload SFrame-header hint only.
 */
function noteStarveDrop(state: WorkerState, peerIndex?: PeerIndex): void {
	const now = state.now();
	if (!state.starveActive) {
		state.starveActive = true;
		state.starveSinceMs = now;
		state.starveFramesDropped = 1;
		state.starveLastEmitMs = now;
		state.starvePeerIndex = peerIndex;
		state.emit({ type: 'decrypt_starved', peerIndex, framesDropped: 1, sinceMs: 0 });
		return;
	}
	state.starveFramesDropped += 1;
	if (peerIndex !== undefined) state.starvePeerIndex = peerIndex;
	if (now - state.starveLastEmitMs >= STARVE_COALESCE_MS) {
		state.starveLastEmitMs = now;
		state.emit({
			type: 'decrypt_starved',
			peerIndex: state.starvePeerIndex,
			framesDropped: state.starveFramesDropped,
			sinceMs: now - state.starveSinceMs,
		});
	}
}

/** End the current starvation episode — a frame decoded successfully. */
function clearStarve(state: WorkerState): void {
	if (!state.starveActive) return;
	state.starveActive = false;
	state.starveSinceMs = 0;
	state.starveFramesDropped = 0;
	state.starveLastEmitMs = 0;
	state.starvePeerIndex = undefined;
}

/**
 * Enqueue a frame that failed decrypt due to missing epoch. Delegates to
 * pushToQueue to enforce the bounded ring cap consistently.
 */
function enqueuePreEpoch(
	state: WorkerState,
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
	peerIndex?: PeerIndex,
): void {
	pushToQueue(state, frame, peerIndex);
}

/**
 * Drain the pre-epoch frame queue by retrying decryption with the now-installed
 * epoch keys. Called by worker-state.ts after installEpoch. Frames that still
 * fail (e.g. they were for a different epoch not yet available) stay queued.
 */
export async function drainPreEpochQueue(state: WorkerState): Promise<void> {
	// Re-entrancy guard: if another drain is already running (concurrent epoch
	// message or rotate arriving mid-await), return early. The next installEpoch
	// will trigger a fresh drain call — correct path, no frames lost.
	if (state.draining) return;
	state.draining = true;
	try {
		// Single-pass snapshot: take all currently queued frames and clear the queue.
		// Frames that arrive during our awaits land in preEpochQueue and will be
		// processed by the drain triggered from the *next* installEpoch call.
		// This eliminates the livelock: if no key arrives for a given epoch, frames
		// are re-enqueued and the function returns — it does NOT re-loop.
		const pending = state.preEpochQueue.splice(0);
		for (const { frame } of pending) {
			const raw = new Uint8Array(frame.data);
			try {
				// Codec-aware prefix peel — mirrors decodeFrame logic.
				const rawType = (frame as RTCEncodedVideoFrame).type;
				const frameKind: FrameKind | undefined =
					rawType === 'key' ? 'key' : rawType === 'delta' ? 'inter' : undefined;
				const N = Math.min(getUnencryptedBytes(state.codec, frameKind), raw.byteLength);
				const prefix = raw.subarray(0, N);
				const buf = raw.subarray(N);

				const hdr = parseHeader(buf);
				const { epoch, peerIndex } = splitKid(hdr.kid);
				if (epoch < state.currentMinValidEpoch) {
					// Frame became stale while queued — discard silently (already
					// past grace window; re-emitting decrypt_failure would spam).
					continue;
				}
				const entry = state.epochs.get(epoch);
				const key = entry?.keys.get(peerIndex) ?? null;
				if (!key) {
					// Still no key for this epoch — re-enqueue via pushToQueue (enforces
					// cap). Will be retried when the correct epoch's installEpoch fires.
					pushToQueue(state, frame, peerIndex);
					continue;
				}
				// Anti-replay sliding window — same check/accept as decodeFrame
				// (RFC 9605 §9.3, issue #10). A replayed frame queued before the
				// first epoch must still be caught when drained.
				const replayWindow = getReplayWindow(state, epoch, peerIndex);
				if (!replayWindow.check(hdr.ctr)) {
					state.emit({
						type: 'decrypt_failure', reason: 'replay',
						kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
					});
					emitMetric(state, { kind: 'queue_drop', reason: 'replay', epoch });
					emitMetric(state, { kind: 'replay_drop', epoch, peerIndex, ctr: hdr.ctr.toString() });
					continue; // drop the replayed frame; do not re-enqueue
				}
				// Failure-invalidation gate (issue #14) — same as decodeFrame.
				// AFTER replay check, BEFORE tryDecryptWithRatchet. A queued frame
				// for an already-invalidated key is dropped without AEAD.
				if (isKeyInvalid(state, epoch, peerIndex)) {
					state.emit({
						type: 'decrypt_failure', reason: 'key_invalid',
						kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
					});
					emitMetric(state, { kind: 'decrypt_fail', code: 'KEY_INVALID', epoch, peerIndex });
					continue; // drop; do not re-enqueue
				}
				// Use the ratchet retry helper so that within-epoch key advances are
				// also handled for queued frames, consistent with the live decode path.
				const opened = await tryDecryptWithRatchet(state, buf, epoch, peerIndex);
				// Record the CTR as seen ONLY after a successful AEAD decrypt.
				replayWindow.accept(hdr.ctr);
				// A successful decrypt resets the consecutive AEAD failure count.
				recordSuccess(state, epoch, peerIndex);

				// Reassemble: [unencrypted prefix] [decrypted plaintext]
				const plaintext = new Uint8Array(N + opened.byteLength);
				plaintext.set(prefix, 0);
				plaintext.set(opened, N);
				frame.data = toExclusiveArrayBuffer(plaintext);
				// Drained a frame — starvation (if any) has ended.
				clearStarve(state);
			} catch (err) {
				// Failure-invalidation tracking (issue #14): only count AEAD
				// failures (AEADAuthError, RatchetWindowExhaustedError). The drain
				// path parses the header inline, so re-derive epoch/peerIndex from
				// the typed error context where available.
				if (err instanceof AEADAuthError || err instanceof RatchetWindowExhaustedError) {
					const ctx = err.context as { epoch?: number; peerIndex?: number };
					if (typeof ctx.epoch === 'number' && typeof ctx.peerIndex === 'number') {
						recordFailure(state, ctx.epoch, ctx.peerIndex);
					}
				}
				// Decrypt error on retry — emit observability event (CLAUDE.md: no silent errors).
				const detail = err instanceof Error ? err.message : String(err);
				state.emit({
					type: 'decrypt_failure', reason: 'decrypt_failed_after_epoch',
					detail,
				});
			}
		}
	} finally {
		state.draining = false;
	}
}

