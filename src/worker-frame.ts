// Frame-pipeline layer: encodeFrame / decodeFrame + the stream pipe wiring.
// Concern: WebCrypto I/O per frame and the stale-epoch gate. Distinct from
// worker-state.ts (epoch/key table bookkeeping) and worker.ts (DOM glue).
// Spec §§ 2 L42, 2.2, 6.3, 7.4.
//
// M3.5: pre-epoch ring buffer. When decodeFrame can't find a key (epoch not
// yet installed), the frame is queued in state.preEpochQueue (cap
// PRE_EPOCH_QUEUE_CAP). drainPreEpochQueue() is called by worker-state.ts
// after installEpoch to retry decryption. Overflow drops the newest entry
// (tail eviction) and emits decrypt_failure{reason:'queue_overflow'}.
//
// Phase 1 receive-side tolerance: the decoder accepts three AAD forms
// ('header', 'prefix', 'canonical') and two prefix lengths for VP9/AV1
// (N=0 old, N=1 new). The resolved format is cached per (epoch, peerIndex)
// so the common case is 1 AEAD attempt per frame. See sframe.ts for the
// AAD form definitions and docs/SECURITY.md for the staged-rollout plan.

import { parseHeader, serializeHeader } from './sframe-header.ts';
import { sframeDecrypt, sframeEncrypt, sframeEncryptInto, type AadForm } from './sframe.ts';
import { deriveNextSenderKey } from './ratchet-crypto.ts';
import { STARVE_COALESCE_MS, type FrameKind, type Side, type WorkerState, type FormatGuess, type Codec } from './worker-types.ts';
import { toArrayBuffer as toExclusiveArrayBuffer } from './internal/buffer.js';
import { ctEndsWith } from './internal/constant-time.js';
import { getUnencryptedBytes } from './codec-partial.ts';
import type { PeerIndex } from './types.ts';
import { KeyNotFoundError, KeyInvalidError, QueueFullError, RatchetWindowExhaustedError, ReplayError, StaleEpochError, AEADAuthError } from './errors.ts';
import { SlidingReplayWindow } from './internal/replay.ts';
import { getOrCreateNested } from './internal/collections.ts';
import { emitMetric } from './metrics.ts';
import { isKeyInvalid, recordFailure, recordSuccess, durableReplayKey } from './worker-state.ts';

/**
 * Get or create the per-(epoch, peerIndex) anti-replay window (RFC 9605 §9.3,
 * issue #10). Windows are created lazily at the current `replayWindowSize` and
 * deleted by wipeEpoch() on epoch rotation. O(1) lookup.
 */
function getReplayWindow(state: WorkerState, epoch: number, peerIndex: number): SlidingReplayWindow {
	return getOrCreateNested(
		state.replayWindows, epoch, peerIndex,
		() => new SlidingReplayWindow(state.replayWindowSize),
	);
}

// ---------------------------------------------------------------------------
// Phase 1: receive-side format tolerance helpers
// ---------------------------------------------------------------------------

/**
 * Ordered list of (prefixLen, aadForm) candidates to try when the format is
 * not yet cached for a sender. Ordered by likelihood in phase 1: the old
 * format (AAD=header) is most common because the phase-1 sender emits it.
 *
 * For VP8/H264/Opus the prefix length is fixed by the codec — only the AAD
 * form is ambiguous. For VP9/AV1 both the prefix length (0=old, 1=new) and
 * the AAD form are ambiguous. For undefined codec, N=0 and only 'header'
 * vs 'canonical' (be16(0)||header) differ.
 *
 * Worst-case candidate counts (cache miss, first frame only):
 *   VP9/AV1:        4  (N=0 header, N=1 canonical, N=1 prefix, N=1 header)
 *   VP8/H264/Opus:  3  (header, canonical, prefix)
 *   undefined:      2  (header, canonical)
 * After the first frame resolves the format, the cache ensures 1 attempt.
 */
function formatCandidates(codec: Codec | undefined, frameKind: FrameKind | undefined): Array<{ prefixLen: number; aadForm: AadForm }> {
	if (codec === 'vp9' || codec === 'av1') {
		return [
			{ prefixLen: 0, aadForm: 'header' },     // old format (N=0, AAD=header)
			{ prefixLen: 1, aadForm: 'canonical' },   // new canonical (N=1, AAD=be16||prefix||header)
			{ prefixLen: 1, aadForm: 'prefix' },       // intermediate b6ded9d (N=1, AAD=prefix||header)
			{ prefixLen: 1, aadForm: 'header' },        // robustness: N=1 with old AAD (no real sender)
		];
	}
	const N = getUnencryptedBytes(codec, frameKind);
	if (N === 0) {
		return [
			{ prefixLen: 0, aadForm: 'header' },     // old = new-non-canonical (empty prefix)
			{ prefixLen: 0, aadForm: 'canonical' },   // new canonical (be16(0)||header)
		];
	}
	return [
		{ prefixLen: N, aadForm: 'header' },          // old format (prefix not in AAD)
		{ prefixLen: N, aadForm: 'canonical' },        // new canonical
		{ prefixLen: N, aadForm: 'prefix' },            // intermediate b6ded9d
	];
}

/** Get the cached format guess for (epoch, peerIndex), or undefined. */
function getFormatCache(state: WorkerState, epoch: number, peerIndex: number): FormatGuess | undefined {
	return state.formatCache.get(epoch)?.get(peerIndex);
}

/** Cache a resolved format guess for (epoch, peerIndex). */
function setFormatCache(state: WorkerState, epoch: number, peerIndex: number, guess: FormatGuess): void {
	let inner = state.formatCache.get(epoch);
	if (!inner) {
		inner = new Map();
		state.formatCache.set(epoch, inner);
	}
	inner.set(peerIndex, guess);
}

/** Invalidate the cached format for (epoch, peerIndex) — used when a cached
 *  guess fails AEAD, so the next frame re-resolves from scratch. */
function deleteFormatCache(state: WorkerState, epoch: number, peerIndex: number): void {
	state.formatCache.get(epoch)?.delete(peerIndex);
}

/**
 * Probe all format candidates at step 0 (cached key, no ratchet) and return
 * the first that decrypts. This is the cache-miss path — it runs at most
 * once per (epoch, peerIndex), after which the result is cached.
 *
 * Does NOT run the stale-epoch / replay / failure-invalidation gates — those
 * run in the caller after the format is resolved. The probe only determines
 * which wire format the sender used; it does not accept the frame.
 *
 * Returns the resolved format + plaintext + parsed header fields, or null
 * if no candidate succeeded at step 0 (the key may have ratcheted past step
 * 0, in which case the caller falls back to tryDecryptWithRatchet with the
 * default format).
 */
async function probeFormat(
	state: WorkerState,
	payload: Uint8Array,
	codec: Codec | undefined,
	frameKind: FrameKind | undefined,
): Promise<{
	prefixLen: number; aadForm: AadForm; plaintext: Uint8Array;
	epoch: number; peerIndex: PeerIndex; ctr: bigint;
	prefix: Uint8Array; kid: number;
} | null> {
	const candidates = formatCandidates(codec, frameKind);
	for (const { prefixLen, aadForm } of candidates) {
		const buf = payload.subarray(prefixLen);
		if (buf.length < 1) continue;
		let hdr;
		try { hdr = parseHeader(buf); } catch { continue; } // wrong prefixLen → garbage header
		if (buf.length < hdr.bodyOffset + 16) continue; // too short for tag
		const { epoch, peerIndex } = state.kidCodec.decode(hdr.kid);
		const entry = state.epochs.get(epoch);
		const key = entry?.keys.get(peerIndex);
		if (!key) continue; // unknown epoch/peer for this prefixLen
		const prefix = prefixLen > 0 ? payload.subarray(0, prefixLen) : undefined;
		try {
			const plaintext = await sframeDecrypt(
				buf,
				() => key,
				{ kidCodec: state.kidCodec, aadPrefix: prefix, aadForm },
			);
			return {
				prefixLen, aadForm, plaintext,
				epoch, peerIndex, ctr: hdr.ctr, kid: hdr.kid,
				prefix: prefixLen > 0 ? payload.subarray(0, prefixLen) : new Uint8Array(0),
			};
		} catch {
			// AEAD failed or key mismatch — try next candidate
		}
	}
	return null;
}

// ---------------------------------------------------------------------------
// Encode-side starvation coalescing (LOW finding)
// ---------------------------------------------------------------------------

/**
 * Note an encode-side frame drop and emit a COALESCED `encrypt_failure` signal.
 * Emits immediately on the first drop of an episode, then at most once per
 * `STARVE_COALESCE_MS`. Mirrors the decode-side `noteStarveDrop`. The
 * `encode_drop` metric is still emitted per-drop (metrics are high-volume);
 * only the OutMsg is coalesced to prevent 30/s spam under a persistent fault.
 */
function noteEncryptDrop(state: WorkerState, reason: 'encode_failed' | 'no_epoch', detail: string): void {
	const now = state.now();
	if (!state.encryptStarveActive) {
		state.encryptStarveActive = true;
		state.encryptStarveSinceMs = now;
		state.encryptStarveFramesDropped = 1;
		state.encryptStarveLastEmitMs = now;
		state.emit({ type: 'encrypt_failure', reason, detail });
		return;
	}
	state.encryptStarveFramesDropped += 1;
	if (now - state.encryptStarveLastEmitMs >= STARVE_COALESCE_MS) {
		state.encryptStarveLastEmitMs = now;
		state.emit({ type: 'encrypt_failure', reason, detail });
	}
}

/** End the encode-side starvation episode — a frame encoded successfully. */
function clearEncryptStarve(state: WorkerState): void {
	if (!state.encryptStarveActive) return;
	state.encryptStarveActive = false;
	state.encryptStarveSinceMs = 0;
	state.encryptStarveFramesDropped = 0;
	state.encryptStarveLastEmitMs = 0;
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
				// window. The frame is dropped (not queued) — by the time the
				// epoch lands the encoder has already moved on, and a delayed
				// frame would carry a stale CTR.
				const msg = err instanceof Error ? err.message : String(err);
				const errCode = err instanceof Error && 'code' in err ? String((err as { code: unknown }).code) : 'UNKNOWN';

				if (side === 'encode') {
					// Encode-side: do NOT rethrow. A rethrow rejects pipeTo, and a
					// rejected pipeTo does not recover — the sender's media stops
					// for the rest of the call (oxpulse-partner-edge#618). Drop the
					// frame, count it, and let the next frame flow. The decode side
					// already drops without rethrowing; this removes the asymmetry.
					const reason = msg === 'worker: no active send epoch' ? 'no_epoch' : 'encode_failed';
					// Distinguish the most common failure in the metric code: the
					// 'no_epoch' error carries no `.code` property, so it would
					// otherwise show as 'UNKNOWN'. The encrypt_failure OutMsg
					// already distinguishes via `reason`; make the metric match.
					const metricCode = reason === 'no_epoch' ? 'NO_EPOCH' : errCode;
					console.warn(`[gc:e2e] encode drop (${reason}): ${msg}`);
					emitMetric(state, { kind: 'encode_drop', code: metricCode });
					// Coalesce encrypt_failure to at most once per STARVE_COALESCE_MS
					// (LOW finding: 30/s spam under a persistent fault).
					noteEncryptDrop(state, reason, msg);
				} else {
					// Decode-side: decodeFrame already called state.emit(decrypt_failure)
					// before rethrowing. Add a debug breadcrumb behind ?__e2e_debug=1
					// so developers can see individual frame drops without prod noise.
					if ((globalThis as Record<string, unknown>).__e2e_debug === true) {
						console.warn('[sframe] decode drop', { reason: msg });
					}
				}
				// Frame is dropped — not enqueued. The pipe survives.
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
	// path.
	// PHASE 1: the unencrypted prefix is NOT included in AES-GCM AAD. The sender
	// emits the original format (AAD = header only). Phase 2 will switch the
	// sender to the canonical AAD form (be16(prefix.length) || prefix || header).
	const N = Math.min(getUnencryptedBytes(state.codec, frameKind), plaintext.byteLength);
	const prefix = plaintext.subarray(0, N);  // untouched, NOT authenticated in phase 1
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
	// The prefix is INSIDE the AEAD AAD (prefix || header) — tamper-evident.
	const wire = new Uint8Array(N + header.length + body.byteLength + AEAD_TAG_BYTES + trailerLen);
	if (N > 0) wire.set(prefix, 0);
	// PHASE 1: pass undefined as aadPrefix → AAD = header only (old format).
	// Phase 2 will pass `N > 0 ? prefix : undefined` with aadForm='canonical'.
	const written = await sframeEncryptInto(wire, N, header, body, key, ctr, undefined, 'header');
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
	// A frame encoded — the sender is healthy; end any encode-side starvation.
	clearEncryptStarve(state);
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
 *
 * Concurrent ratchet dedup (issue #15, pattern from livekit
 * ParticipantKeyHandler.ts:26 ratchetPromiseMap): when multiple frames fail
 * AEAD simultaneously for the same (epoch, peerIndex), only ONE retry loop
 * runs at a time. Concurrent callers await the in-flight promise (stored in
 * `state.ratchetPromises`) instead of starting parallel HKDF derivations.
 * After the in-flight promise settles, the concurrent caller retries step 0
 * with the now-advanced cached key; if that still fails, it starts its own
 * retry loop (the first caller's promise is done, so no duplication).
 */
async function tryDecryptWithRatchet(
	state: WorkerState,
	buf: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	aadPrefix?: Uint8Array,
	aadForm: AadForm = 'header',
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
		}, { kidCodec: state.kidCodec, aadPrefix, aadForm });
	} catch (err) {
		firstError = err;
	}

	// If the window is disabled, surface the original failure immediately.
	if (state.ratchetWindowSize === 0) throw firstError;

	const dedupKey = `${epoch}:${peerIndex}`;

	// Concurrent ratchet dedup (issue #15). If a retry loop is already in
	// flight for this (epoch, peerIndex), await it instead of starting a
	// parallel derivation. After it settles:
	//   - Resolved: the cached key was advanced. Retry step 0 — it may match
	//     our frame without a new loop.
	//   - Rejected (window exhausted): the cached key was NOT advanced. Fall
	//     through to start our own retry loop.
	const inFlight = state.ratchetPromises.get(dedupKey);
	if (inFlight) {
		try {
			await inFlight;
			// The first caller advanced the cached key. Retry step 0 with the
			// now-advanced key — it may match our frame without a new loop.
			try {
				return await sframeDecrypt(buf, ({ epoch: e, peerIndex: pi }) => {
					const ep = state.epochs.get(e);
					return ep?.keys.get(pi) ?? null;
				}, { kidCodec: state.kidCodec, aadPrefix, aadForm });
			} catch {
				// Step 0 still fails — our frame is at a different step than
				// the one the first caller found. Fall through to our own
				// retry loop (the in-flight promise is done, so we're the
				// only one running it now).
			}
		} catch {
			// The in-flight promise rejected (window exhausted). The cached
			// key was NOT advanced. Fall through to start our own retry loop.
		}
	}

	// No in-flight promise (or the previous one already settled). Before
	// starting our own retry loop, re-check the map — another caller may have
	// set a promise while we were suspended in the step-0 retry above
	// (repo-review-council #30: race condition in ratchetPromises dedup).
	const afterAwait = state.ratchetPromises.get(dedupKey);
	if (afterAwait && afterAwait !== inFlight) {
		try {
			return await afterAwait;
		} catch {
			// That one also failed — fall through to our own retry loop.
		}
	}

	// Run the retry loop under a dedup promise so concurrent callers await us
	// instead of racing a parallel HKDF derivation.
	const retryLoop = async (): Promise<Uint8Array> => {
		// Re-fetch the current cached key — it may have been advanced by a
		// concurrent caller we just awaited. Chain from its rawKey so we
		// don't re-derive already-cached steps.
		const currentKey = entry.keys.get(peerIndex);
		if (!currentKey) {
			throw new KeyNotFoundError(
				`sframe: key not found for epoch=${epoch} peer=${peerIndex}`,
				{ epoch, peerIndex },
			);
		}
		let currentRaw = currentKey.rawKey;
		const salt = currentKey.salt;
		for (let step = 1; step <= state.ratchetWindowSize; step++) {
			const next = await deriveNextSenderKey(currentRaw, salt, epoch, peerIndex, state.suite, state.kidCodec);
			try {
				const plaintext = await sframeDecrypt(buf, ({ epoch: e, peerIndex: pi }) => {
					if (e === epoch && pi === peerIndex) return next;
					const ep = state.epochs.get(e);
					return ep?.keys.get(pi) ?? null;
				}, { kidCodec: state.kidCodec, aadPrefix, aadForm });
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
	};

	const promise = retryLoop();
	state.ratchetPromises.set(dedupKey, promise);
	try {
		return await promise;
	} finally {
		state.ratchetPromises.delete(dedupKey);
	}
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

	// Phase 1: format tolerance. The receiver accepts three AAD forms
	// ('header', 'prefix', 'canonical') and, for VP9/AV1, two prefix lengths
	// (N=0 old, N=1 new). The resolved format is cached per (epoch, peerIndex)
	// so the common case is 1 AEAD attempt per frame. See sframe.ts for the
	// AAD form definitions and docs/SECURITY.md for the staged-rollout plan.
	const rawType = (frame as RTCEncodedVideoFrame).type;
	const frameKind: FrameKind | undefined =
		rawType === 'key' ? 'key' : rawType === 'delta' ? 'inter' : undefined;
	const codec = state.codec;
	const codecN = Math.min(getUnencryptedBytes(codec, frameKind), payload.byteLength);

	let hdrKid = -1;
	let hdrEpoch = -1;
	let hdrPeerIndex = -1;
	let hdrCtr = 0n;

	try {
		// === Format resolution ===
		// Try cache: parse header at codecN to get (epoch, peerIndex) for lookup.
		// For VP9/AV1 with N=0 (old format), codecN=0 and the parse succeeds.
		// For N=1 (new format), codecN=0 and the parse tries to read the prefix
		// byte as the header start — it will fail or give a wrong kid, and we
		// fall through to the probe which tries N=1.
		let cached: FormatGuess | undefined;
		if (codecN < payload.byteLength) {
			try {
				const tHdr = parseHeader(payload.subarray(codecN));
				const { epoch: tEpoch, peerIndex: tPeer } = state.kidCodec.decode(tHdr.kid);
				cached = getFormatCache(state, tEpoch, tPeer);
			} catch { /* header parse at codecN failed — will probe */ }
		}

		let prefixLen: number;
		let aadForm: AadForm;
		let probedPlaintext: Uint8Array | null = null;

		if (cached) {
			prefixLen = cached.prefixLen;
			aadForm = cached.aadForm;
		} else {
			// Cache miss: probe all format candidates at step 0 (cached key).
			const probed = await probeFormat(state, payload, codec, frameKind);
			if (probed) {
				prefixLen = probed.prefixLen;
				aadForm = probed.aadForm;
				probedPlaintext = probed.plaintext;
				hdrKid = probed.kid;
				hdrEpoch = probed.epoch;
				hdrPeerIndex = probed.peerIndex;
				hdrCtr = probed.ctr;
			} else {
				// Probe failed (key ratcheted past step 0, or unknown format).
				// Fall back to the default (old) format for ratchet retry.
				prefixLen = codecN;
				aadForm = 'header';
			}
		}

		const prefix = payload.subarray(0, prefixLen);  // unencrypted prefix
		const buf = payload.subarray(prefixLen);         // [SFrame header][ciphertext+tag]

		// Parse header at the resolved prefixLen.
		const hdr = parseHeader(buf);
		const { epoch, peerIndex } = state.kidCodec.decode(hdr.kid);
		if (probedPlaintext === null) {
			hdrKid = hdr.kid; hdrEpoch = epoch; hdrPeerIndex = peerIndex; hdrCtr = hdr.ctr;
		}

		// === Gates (stale-epoch, pre-epoch, replay, failure-invalidation) ===
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
		if (state.currentEpoch === -1) {
			enqueuePreEpoch(state, frame, peerIndex);
			return; // not an error from caller's perspective
		}

		// Anti-replay sliding window (RFC 9605 §9.3, issue #10).
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
		// Durable cross-reload replay check (CWE-294).
		if (state.durableReplay?.available) {
			if (!(await state.durableReplay.check(durableReplayKey(epoch, peerIndex), hdr.ctr))) {
				state.emit({
					type: 'decrypt_failure', reason: 'replay',
					kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
				});
				emitMetric(state, { kind: 'queue_drop', reason: 'replay', epoch });
				emitMetric(state, { kind: 'replay_drop', epoch, peerIndex, ctr: hdr.ctr.toString() });
				throw new ReplayError(
					`sframe: durable cross-reload replay detected (epoch=${epoch} peer=${peerIndex} ctr=${hdr.ctr})`,
					{ epoch, peerIndex, ctr: hdr.ctr },
				);
			}
		}

		// Failure-invalidation gate (issue #14).
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

		// === Decrypt / accept ===
		let opened: Uint8Array;
		if (probedPlaintext !== null) {
			// Probe already decrypted at step 0 — cache the format and accept.
			setFormatCache(state, epoch, peerIndex, { prefixLen, aadForm });
			opened = probedPlaintext;
		} else {
			opened = await tryDecryptWithRatchet(
				state, buf, epoch, peerIndex,
				prefixLen > 0 ? prefix : undefined, aadForm,
			);
			// Cache the format on success (first frame from this sender, or
			// ratchet fallback succeeded).
			setFormatCache(state, epoch, peerIndex, { prefixLen, aadForm });
		}

		// Record the CTR as seen ONLY after a successful AEAD decrypt.
		replayWindow.accept(hdr.ctr);
		// Durable accept — persist the CTR so the replay defense survives a
		// worker reload (CWE-294). Only when the guard is present and
		// available. Non-fatal on persist failure (the in-memory window still
		// defends this session).
		if (state.durableReplay?.available) {
			await state.durableReplay.accept(durableReplayKey(epoch, peerIndex), hdr.ctr);
		}
		// A successful decrypt resets the consecutive AEAD failure count for
		// this key (issue #14) — a single good frame clears the slate.
		recordSuccess(state, epoch, peerIndex);

		// Reassemble: [unencrypted prefix] [decrypted plaintext]
		const plaintext = new Uint8Array(prefixLen + opened.byteLength);
		plaintext.set(prefix, 0);
		plaintext.set(opened, prefixLen);
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
 * Push a frame into the pre-epoch queue, enforcing the bounded cap.
 * Overflow drops the NEWEST entry (tail) and emits
 * decrypt_failure{reason:'queue_overflow'}.
 *
 * Eviction policy: TAIL eviction (drop the newest), NOT head eviction.
 * The head of a video stream is the keyframe — the one frame that must
 * survive. Every later frame in the queue is undecodable without it.
 * Dropping from the head (the previous behaviour, oxpulse-partner-edge#618)
 * evicted the keyframe first, making every subsequent frame useless.
 * Tail eviction preserves the oldest frames (including the keyframe) and
 * sacrifices the newest, which is the least damaging choice: the newest
 * frame can be re-requested via PLI/FIR, but a lost keyframe stalls the
 * entire stream until the next periodic keyframe.
 *
 * Used by both enqueuePreEpoch (initial enqueue) and drainPreEpochQueue
 * (re-enqueue on still-missing key) so cap is enforced on all paths.
 */
function pushToQueue(
	state: WorkerState,
	frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
	peerIndex?: PeerIndex,
): void {
	if (state.preEpochQueue.length >= state.preEpochQueueCap) {
		// Drop newest (tail) to preserve the keyframe at the head.
		state.preEpochQueue.pop();
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
	// Trailing-edge coalesce re-entrancy guard (issue #40, pattern:
	// schwepps/hanabi-intelligence-extension/drain.ts). If a second drain
	// arrives while one is already running, set pendingDrain and return.
	// The in-flight drain re-runs once in its finally block if the flag is
	// set — preventing orphaned frames when two epoch messages interleave.
	if (state.draining) {
		state.pendingDrain = true;
		return;
	}
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
				// Phase 1: format tolerance — mirrors decodeFrame logic.
				// Resolve (prefixLen, aadForm) from cache or probe, then decrypt.
				const rawType = (frame as RTCEncodedVideoFrame).type;
				const frameKind: FrameKind | undefined =
					rawType === 'key' ? 'key' : rawType === 'delta' ? 'inter' : undefined;
				const codec = state.codec;
				const codecN = Math.min(getUnencryptedBytes(codec, frameKind), raw.byteLength);

				// Try cache: parse header at codecN for (epoch, peerIndex) lookup.
				let cached: FormatGuess | undefined;
				if (codecN < raw.byteLength) {
					try {
						const tHdr = parseHeader(raw.subarray(codecN));
						const { epoch: tEpoch, peerIndex: tPeer } = state.kidCodec.decode(tHdr.kid);
						cached = getFormatCache(state, tEpoch, tPeer);
					} catch { /* will probe */ }
				}

				let prefixLen: number;
				let aadForm: AadForm;
				let probedPlaintext: Uint8Array | null = null;

				if (cached) {
					prefixLen = cached.prefixLen;
					aadForm = cached.aadForm;
				} else {
					const probed = await probeFormat(state, raw, codec, frameKind);
					if (probed) {
						prefixLen = probed.prefixLen;
						aadForm = probed.aadForm;
						probedPlaintext = probed.plaintext;
					} else {
						prefixLen = codecN;
						aadForm = 'header';
					}
				}

				const prefix = raw.subarray(0, prefixLen);
				const buf = raw.subarray(prefixLen);

				const hdr = parseHeader(buf);
				const { epoch, peerIndex } = state.kidCodec.decode(hdr.kid);
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
				// Durable cross-reload replay check (CWE-294) — same as decodeFrame.
				// Architecture-council nit #1: in-memory check FIRST, durable only
				// if in-memory passes.
				if (state.durableReplay?.available) {
					if (!(await state.durableReplay.check(durableReplayKey(epoch, peerIndex), hdr.ctr))) {
						state.emit({
							type: 'decrypt_failure', reason: 'replay',
							kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
						});
						emitMetric(state, { kind: 'queue_drop', reason: 'replay', epoch });
						emitMetric(state, { kind: 'replay_drop', epoch, peerIndex, ctr: hdr.ctr.toString() });
						continue; // drop; do not re-enqueue
					}
				}
				// Failure-invalidation gate (issue #14) — same as decodeFrame.
				if (isKeyInvalid(state, epoch, peerIndex)) {
					state.emit({
						type: 'decrypt_failure', reason: 'key_invalid',
						kid: hdr.kid, epoch, peerIndex, ctr: hdr.ctr,
					});
					emitMetric(state, { kind: 'decrypt_fail', code: 'KEY_INVALID', epoch, peerIndex });
					continue; // drop; do not re-enqueue
				}

				// Decrypt: use probed plaintext if available, else ratchet retry.
				let opened: Uint8Array;
				if (probedPlaintext !== null) {
					setFormatCache(state, epoch, peerIndex, { prefixLen, aadForm });
					opened = probedPlaintext;
				} else {
					opened = await tryDecryptWithRatchet(
						state, buf, epoch, peerIndex,
						prefixLen > 0 ? prefix : undefined, aadForm,
					);
					setFormatCache(state, epoch, peerIndex, { prefixLen, aadForm });
				}
				// Record the CTR as seen ONLY after a successful AEAD decrypt.
				replayWindow.accept(hdr.ctr);
				// Durable accept — persist the CTR so the replay defense survives a
				// worker reload (CWE-294). Non-fatal on persist failure.
				if (state.durableReplay?.available) {
					await state.durableReplay.accept(durableReplayKey(epoch, peerIndex), hdr.ctr);
				}
				// A successful decrypt resets the consecutive AEAD failure count.
				recordSuccess(state, epoch, peerIndex);

				// Reassemble: [unencrypted prefix] [decrypted plaintext]
				const plaintext = new Uint8Array(prefixLen + opened.byteLength);
				plaintext.set(prefix, 0);
				plaintext.set(opened, prefixLen);
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
		// Trailing-edge coalesce: if a second drain arrived while we were
		// running, re-run once to pick up frames it would have processed.
		if (state.pendingDrain) {
			state.pendingDrain = false;
			void drainPreEpochQueue(state);
		}
	}
}

