// Main-thread glue for the E2E frame cryptor.
// Wires RTCRtpSender/Receiver transforms to the encoded-frame worker, preferring
// the native RTCRtpScriptTransform path and falling back to createEncodedStreams
// on Firefox <141 / pre-native Chrome. See spec §7.5 and research §2 matrix.
//
// Revision 2026-04-21: setEpoch now takes `(epoch, peerIndexMap, chainKey)`
// and derives the full per-sender key table on the main thread before posting
// the worker — raw ChainKey bytes never cross the postMessage boundary.

import type { PeerIndex, SFrameSupport } from './types.ts';
import { DEFAULT_CIPHER_SUITE, type CipherSuite, deriveEpochKeyTable } from './ratchet-crypto.ts';

export { validatePeerIndexMap } from './ratchet-ids.ts';

type Role = 'sender' | 'receiver';

export interface FrameCryptorOptions {
	worker: Worker;
	role: Role;
	peerId: string;
	/** This node's peer_index in the starting epoch (may be rotated later). */
	peerIndex: PeerIndex;
	/**
	 * RFC 9605 §4.5 cipher suite. Defaults to `AES_128_GCM_SHA256` (suite 4).
	 * All members of a room MUST use the same suite.
	 */
	suite?: CipherSuite;
}

/** Parameters for setEpoch — post-revision per-epoch key install. */
export interface EpochParams {
	epoch: number;
	peerIndexMap: Record<string, PeerIndex>;
	/**
	 * 32-byte ChainKey for this epoch. The cryptor derives all N per-sender
	 * bundles on the main thread and posts only the CryptoKey/salt pairs into
	 * the worker — raw bytes stay out of postMessage.
	 */
	chainKey: Uint8Array;
}

/**
 * Browser-capability probe. `native` → RTCRtpScriptTransform is present.
 * `fallback` → createEncodedStreams is present. Both false → transit-only mode.
 */
export function supportsSFrame(): SFrameSupport {
	const g = globalThis as unknown as {
		RTCRtpScriptTransform?: unknown;
		RTCRtpSender?: { prototype?: { createEncodedStreams?: unknown } };
	};
	const native = typeof g.RTCRtpScriptTransform !== 'undefined';
	const fallback = typeof g.RTCRtpSender?.prototype?.createEncodedStreams === 'function';
	return { native, fallback };
}

interface CreateEncodedStreamsCapable {
	createEncodedStreams(): {
		readable: ReadableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
		writable: WritableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
	};
}

/**
 * FrameCryptor: owns one worker per peer (livekit-style). attach* functions
 * install the transform on a sender/receiver; setEpoch updates the active key
 * table in the worker; detach tears everything down.
 *
 * `transitOnly` is set at construction when the browser exposes neither
 * RTCRtpScriptTransform nor createEncodedStreams (Chromium 130+ realm-identity
 * bug + removal of the deprecated fallback API). In transit-only mode all
 * attach* calls are no-ops — the track is added to the PC without a transform,
 * DTLS provides transport-layer encryption, but per-sender SFrame E2E is
 * unavailable. Callers should surface this via telemetry and the E2EBadge UI.
 */
export class FrameCryptor {
	private readonly worker: Worker;
	private readonly role: Role;
	private readonly peerId: string;
	private readonly suite: CipherSuite;
	private currentPeerIndex: PeerIndex;
	private attached: Array<() => void> = [];
	private initialised = false;
	/** True when the browser lacks both RTCRtpScriptTransform and
	 *  createEncodedStreams — SFrame transforms cannot be installed. */
	readonly transitOnly: boolean;

	constructor(opts: FrameCryptorOptions) {
		this.worker = opts.worker;
		this.role = opts.role;
		this.peerId = opts.peerId;
		this.suite = opts.suite ?? DEFAULT_CIPHER_SUITE;
		this.currentPeerIndex = opts.peerIndex;
		const { native, fallback } = supportsSFrame();
		this.transitOnly = !native && !fallback;
	}

	private ensureInit(): void {
		if (this.initialised) return;
		this.worker.postMessage({
			type: 'init', role: this.role, peerId: this.peerId,
			peerIndex: this.currentPeerIndex, suite: this.suite,
		});
		this.initialised = true;
	}

	/**
	 * Attach an outbound transform to an RTCRtpSender.
	 * Caller: construct the sender (via addTrack / addTransceiver), then call
	 * this before the offer is created so the transform is in place before
	 * media begins flowing.
	 *
	 * No-op in transit-only mode (browser lacks SFrame transform APIs).
	 * Check `this.transitOnly` and emit telemetry before calling if needed.
	 */
	attachSender(sender: RTCRtpSender): void {
		if (this.transitOnly) {
			console.info('[frame-cryptor] transit-only mode — no SFrame API available, sender not transformed', sender.track?.kind);
			return;
		}
		this.ensureInit();
		this.installTransform(sender, 'encode');
	}

	/**
	 * Attach an inbound transform to an RTCRtpReceiver.
	 *
	 * No-op in transit-only mode (browser lacks SFrame transform APIs).
	 */
	attachReceiver(receiver: RTCRtpReceiver): void {
		if (this.transitOnly) {
			console.info('[frame-cryptor] transit-only mode — no SFrame API available, receiver not transformed');
			return;
		}
		this.ensureInit();
		this.installTransform(receiver, 'decode');
	}

	private installTransform(
		endpoint: RTCRtpSender | RTCRtpReceiver,
		side: 'encode' | 'decode',
	): void {
		const { native, fallback } = supportsSFrame();
		// Try the native RTCRtpScriptTransform path first when the global is
		// present. Some browser builds expose the constructor but reject our
		// Worker with TypeError "parameter 1 is not of type 'Worker'." even
		// though we pass a real Worker — observed on Chromium 130+ headless
		// (CloakBrowser) where the IDL Worker check appears to be checking
		// realm identity. When the native constructor throws we fall through
		// to createEncodedStreams instead of failing the whole call.
		if (native) {
			const Ctor = (globalThis as unknown as {
				RTCRtpScriptTransform: new (worker: Worker, options: Record<string, unknown>) => unknown;
			}).RTCRtpScriptTransform;
			try {
				const transform = new Ctor(this.worker, { side, peerId: this.peerId });
				(endpoint as unknown as { transform: unknown }).transform = transform;
				this.attached.push(() => {
					try { (endpoint as unknown as { transform: unknown }).transform = null; } catch {
						/* endpoint may already be gone */
					}
				});
				return;
			} catch (err) {
				console.warn(
					'[frame-cryptor] RTCRtpScriptTransform constructor rejected the Worker; falling back to createEncodedStreams',
					err,
				);
				// fall through to fallback path below
			}
		}
		if (fallback && typeof (endpoint as unknown as CreateEncodedStreamsCapable)
			.createEncodedStreams === 'function') {
			const streams = (endpoint as unknown as CreateEncodedStreamsCapable).createEncodedStreams();
			this.worker.postMessage(
				{ type: 'streams', side, readable: streams.readable, writable: streams.writable },
				[streams.readable as unknown as Transferable, streams.writable as unknown as Transferable],
			);
			this.attached.push(() => {
				// Streams are closed by the worker when it tears down; nothing to do.
			});
			return;
		}
		// Defense-in-depth: installTransform should only be reached when
		// transitOnly=false, meaning at least one path probed as available.
		// If the probe was optimistic and the constructor nonetheless fails
		// (e.g., RTCRtpScriptTransform present but broken, createEncodedStreams
		// absent), log and return silently rather than throwing — the track
		// stays in the PC without a transform (transit-only degradation).
		console.info(
			'[frame-cryptor] transit-only mode (no SFrame) — both native and fallback paths unavailable',
		);
	}

	/**
	 * Install a new epoch: derive the per-sender key table from `chainKey` +
	 * `peerIndexMap` on the main thread and post the resulting bundles to the
	 * worker. The worker type for `keys` is `Map<peerIndex, {cryptoKey, salt}>`.
	 *
	 * Idempotent — repeated setEpoch with the same params is safe. For sender
	 * role, issues a `rotate` (which also starts the 2 s grace wipe of old
	 * epochs) so outbound frames switch on the next transform tick.
	 */
	async setEpoch(params: EpochParams): Promise<void> {
		this.ensureInit();
		const selfPeerIndex = params.peerIndexMap[this.peerId];
		if (selfPeerIndex === undefined) {
			throw new Error('FrameCryptor: peerIndexMap missing self');
		}
		this.currentPeerIndex = selfPeerIndex;

		const table = await deriveEpochKeyTable(
			params.chainKey, params.epoch, params.peerIndexMap, this.suite,
		);
		const bundles = new Map<PeerIndex, { cryptoKey: CryptoKey; salt: Uint8Array; rawKey: Uint8Array }>();
		for (const [pi, k] of table) bundles.set(pi, { cryptoKey: k.cryptoKey, salt: k.salt, rawKey: k.rawKey });

		// Always install, then rotate on sender role (also triggers wipe of old epochs).
		this.worker.postMessage({
			type: 'epoch', epoch: params.epoch,
			peerIndexMap: params.peerIndexMap, selfPeerIndex, keys: bundles,
		});
		if (this.role === 'sender') {
			this.worker.postMessage({
				type: 'rotate', newEpoch: params.epoch,
				peerIndexMap: params.peerIndexMap, selfPeerIndex, keys: bundles,
			});
		}
	}

	/** Detach all transforms. Safe to call multiple times. */
	detach(): void {
		for (const fn of this.attached) fn();
		this.attached = [];
		if (this.initialised) {
			this.worker.postMessage({ type: 'teardown' });
			this.initialised = false;
		}
	}
}
