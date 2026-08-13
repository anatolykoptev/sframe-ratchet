// sframe-ratchet/chat/mls — MLS-backed chat-mode provider.
//
// Like createChatProvider but driven by MLS epoch material instead of a static
// getKey callback. The caller (MLSGroupManager in chat-sdk) manages the ts-mls
// group lifecycle and calls setEpoch after each epoch advance; the provider
// derives per-sender SFrame AEAD keys from the MLS ChainKey via the SAME
// deriveSenderKeys path FrameCryptor.setEpoch uses internally — no Worker,
// no media-frame path, pure WebCrypto.
//
// Subpath export: import { createMlsChatProvider } from 'sframe-ratchet/chat/mls'
//
// Threat model:
//   Defends: AEAD confidentiality+integrity, in-session replay (sliding window),
//            cross-reload replay when `durableReplay` is enabled (CWE-294),
//            forward secrecy + post-compromise security (via MLS TreeKEM — the
//            ChainKey rotates on every epoch advance, so compromise of one
//            epoch's key does NOT reveal past or future epoch keys).
//   Does NOT defend: traffic analysis.
//   MLS credential verification is the CALLER's responsibility (via ts-mls
//   AuthenticationService). The provider surfaces the epoch authenticator for
//   optional out-of-band verification.
//
// Key derivation (per epoch, per sender):
//   ChainKey = mlsExporter(exporterSecret, 'sframe-ratchet/epoch', groupId||suiteByte, chainKeyBytes)
//   AEADKey  = HKDF-Expand(ChainKey, "sframe/v1/key"  || peer_index_be16, aeadKeyBytes)  [deriveSenderKeys]
//   Salt     = HKDF-Expand(ChainKey, "sframe/v1/salt" || peer_index_be16, 12)            [deriveSenderKeys]
//
// The ChainKey is derived by the caller (createMlsRatchetProvider or equivalent)
// and passed in via setEpoch. This module never touches the MLS exporter secret
// directly — clean separation between the MLS state machine (ts-mls) and the
// SFrame AEAD layer (this module).

import { sframeEncrypt, sframeDecrypt, parseHeader } from '../sframe.ts';
import { StaleEpochError, KeyNotFoundError } from '../errors.ts';
import { ReplayError } from './index.ts';
import { deriveSenderKeys, suiteParams, type CipherSuite } from '../ratchet-crypto.ts';
import { FIXED_KID_CODEC, type KidCodec } from '../kid-format.ts';
import {
	createReplayCtrState,
	getReplayWindow as getRw,
	durableKey as dk,
} from './shared.ts';
import { zeroize } from '../internal/buffer.ts';
import type { PeerIndex, SFrameKey } from '../types.ts';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Context passed to seal/unseal identifying the room and sender. */
export interface MlsSealContext {
	roomId: string;
	senderUid: string;
}

/** Epoch material delivered to the provider via setEpoch. */
export interface MlsEpochParams {
	/** MLS epoch number (from ts-mls groupContext.epoch). */
	epoch: number;
	/** peerId → peerIndex map for this epoch (lex-sorted, §7.8-valid). */
	peerIndexMap: Record<string, PeerIndex>;
	/** MLS ChainKey (suite.chainKeyBytes long) derived via mlsExporter. */
	chainKey: Uint8Array;
}

/** Options for createMlsChatProvider. */
export interface MlsChatProviderOptions {
	/**
	 * SFrame cipher suite — determines chainKeyBytes (32 or 64) and HKDF hash.
	 * MUST match the MLS group's ciphersuite. Default 'AES_128_GCM_SHA256'.
	 */
	suite?: CipherSuite;
	/**
	 * CTR allocation strategy. Same semantics as createChatProvider.
	 * Default 'random-64'.
	 */
	ctrStrategy?: 'random-64' | 'monotonic-idb';
	/** Required when ctrStrategy is 'monotonic-idb'. Namespaces the IDB store. */
	ctrKeyspace?: string;
	/**
	 * In-memory replay window size (per sender per room). Default 1024.
	 * 0 disables replay protection (debug only).
	 */
	replayWindow?: number;
	/**
	 * Durable cross-reload replay protection (CWE-294). Same semantics as
	 * createChatProvider. Default ON when a namespace is provided.
	 */
	durableReplay?: boolean;
	/** Namespace for the durable replay IDB store. */
	durableReplayNamespace?: string;
	/** Durable replay window size. Default equals replayWindow. */
	durableReplayWindow?: number;
	/**
	 * Maps a senderUid (from SealContext) to a peerId in the peerIndexMap.
	 * The default uses the senderUid directly — override if your peerIds
	 * differ from senderUids (e.g. base64-encoded MLS credentials).
	 */
	uidToPeerId?: (senderUid: string) => string;
	/** Called synchronously when clearEpoch(roomId) is invoked. */
	onEpochCleared?: (roomId: string) => void;
}

/** The provider returned by createMlsChatProvider. */
export interface MlsChatProvider {
	/**
	 * Install epoch material for a room. Called after each MLS epoch advance
	 * (createGroup, joinGroup, processMessage on commit). Derives per-sender
	 * SFrameKeys from the ChainKey and caches them.
	 *
	 * The ChainKey is zeroized after derivation — the caller's copy is not
	 * touched.
	 */
	setEpoch(roomId: string, params: MlsEpochParams): Promise<void>;
	/**
	 * Encrypt plaintext for the given (roomId, senderUid). The sender MUST be
	 * a member of the current epoch's peerIndexMap. Throws if no epoch has
	 * been installed for the room or the sender is not in the map.
	 */
	seal(plaintext: Uint8Array, ctx: MlsSealContext): Promise<Uint8Array>;
	/**
	 * Decrypt an SFrame buffer. Validates AEAD, checks replay window.
	 * Throws ReplayError on replay; AEADAuthError on key/uid/room mismatch.
	 */
	unseal(sealed: Uint8Array, ctx: MlsSealContext): Promise<Uint8Array>;
	/**
	 * Clear epoch state + replay windows for a room. Called when leaving a
	 * room or on full state reset. Does NOT clear CTR allocator state.
	 */
	clearEpoch(roomId: string): void;
	/** Current epoch number for a room, or null if none installed. */
	getEpoch(roomId: string): number | null;
	/** Release all resources. */
	dispose(): void;
}

// ---------------------------------------------------------------------------
// Per-room epoch state
// ---------------------------------------------------------------------------

interface RoomEpochState {
	epoch: number;
	/** peerId → SFrameKey (one per sender in the epoch). */
	keys: Map<string, SFrameKey>;
	/** peerIndex → peerId (reverse lookup for unseal by peerIndex from KID). */
	indexToPeerId: Map<PeerIndex, string>;
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

/**
 * Create an MLS-backed chat-mode SFrame provider.
 *
 * The provider is stateful (per-room epoch state, replay windows). Create one
 * instance per application lifetime. The caller drives MLS group lifecycle
 * via ts-mls and calls setEpoch after each epoch advance.
 *
 * @example
 * ```ts
 * const provider = createMlsChatProvider({ suite: 'AES_128_GCM_SHA256' });
 * // After MLS epoch advance:
 * await provider.setEpoch(roomId, { epoch, peerIndexMap, chainKey });
 * const sealed = await provider.seal(plaintext, { roomId, senderUid });
 * const plain  = await provider.unseal(sealed,  { roomId, senderUid });
 * ```
 */
export function createMlsChatProvider(opts: MlsChatProviderOptions = {}): MlsChatProvider {
	const suite = opts.suite ?? 'AES_128_GCM_SHA256';
	const uidToPeerId = opts.uidToPeerId ?? ((uid: string) => uid);

	// Shared CTR allocator + replay window + durable guard construction.
	const { allocator, replayWindow, durable, replayWindows } =
		createReplayCtrState(opts, 'createMlsChatProvider');

	// Per-room epoch state.
	const roomEpochs = new Map<string, RoomEpochState>();

	// KID codec — fixed format (epoch << 16 | peerIndex), same as chat mode.
	const kidCodec: KidCodec = FIXED_KID_CODEC;

	async function setEpoch(roomId: string, params: MlsEpochParams): Promise<void> {
		const { epoch, peerIndexMap, chainKey } = params;
		const { chainKeyBytes } = suiteParams(suite);
		if (chainKey.length !== chainKeyBytes) {
			throw new Error(
				`createMlsChatProvider: chainKey must be ${chainKeyBytes} bytes for suite ${suite}, got ${chainKey.length}`,
			);
		}

		// Derive per-sender SFrameKeys from the ChainKey.
		// Same deriveSenderKeys path FrameCryptor.setEpoch uses internally.
		const peerIds = Object.keys(peerIndexMap);
		const keys = new Map<string, SFrameKey>();
		const indexToPeerId = new Map<PeerIndex, string>();

		await Promise.all(
			peerIds.map(async (peerId) => {
				const peerIndex = peerIndexMap[peerId];
				const sframeKey = await deriveSenderKeys(chainKey, epoch, peerIndex, suite, kidCodec);
				keys.set(peerId, sframeKey);
				indexToPeerId.set(peerIndex, peerId);
			}),
		);

		// Zeroize the ChainKey — we've derived all per-sender keys from it.
		// This mutates the caller's Uint8Array in place; the caller should not
		// retain a reference after calling setEpoch.
		zeroize(chainKey);

		roomEpochs.set(roomId, { epoch, keys, indexToPeerId });

		// Clear replay windows for this room — new epoch = new key space,
		// old CTRs are under a different key and would false-reject.
		const senders = replayWindows.get(roomId);
		if (senders) {
			replayWindows.delete(roomId);
			if (durable?.available) {
				for (const senderUid of senders.keys()) {
					void durable.clear(dk(roomId, senderUid));
				}
			}
		}
	}

	async function seal(plaintext: Uint8Array, ctx: MlsSealContext): Promise<Uint8Array> {
		const { roomId, senderUid } = ctx;
		const roomState = roomEpochs.get(roomId);
		if (!roomState) {
			throw new Error(`createMlsChatProvider: no epoch installed for room ${roomId}`);
		}
		const peerId = uidToPeerId(senderUid);
		const sframeKey = roomState.keys.get(peerId);
		if (!sframeKey) {
			throw new Error(
				`createMlsChatProvider: sender ${senderUid} (peerId ${peerId}) is not a member of epoch ${roomState.epoch} in room ${roomId}`,
			);
		}
		const ctr = await allocator.next(roomId, senderUid);
		return sframeEncrypt(plaintext, sframeKey, ctr);
	}

	async function unseal(sealed: Uint8Array, ctx: MlsSealContext): Promise<Uint8Array> {
		const { roomId, senderUid } = ctx;
		const roomState = roomEpochs.get(roomId);
		if (!roomState) {
			throw new Error(`createMlsChatProvider: no epoch installed for room ${roomId}`);
		}

		// Parse header to extract KID → (epoch, peerIndex) and CTR.
		const hdr = parseHeader(sealed);
		const { epoch, peerIndex } = kidCodec.decode(hdr.kid);
		const ctr = hdr.ctr;

		// Stale-epoch guard: reject frames from a different epoch than the
		// currently installed one. The caller advances epochs via setEpoch;
		// a frame from an old epoch should have been processed before the
		// advance. This is stricter than FrameCryptor (which keeps a 2s grace
		// window) — chat messages are not real-time media, so no grace needed.
		if (epoch !== roomState.epoch) {
			throw new StaleEpochError(
				`createMlsChatProvider: stale epoch ${epoch} (current ${roomState.epoch}) for room ${roomId}`,
				{ frameEpoch: epoch, minValidEpoch: roomState.epoch, kid: hdr.kid },
			);
		}

		// Resolve the sender's key by peerIndex (from KID) → peerId → SFrameKey.
		const peerId = roomState.indexToPeerId.get(peerIndex);
		if (!peerId) {
			throw new KeyNotFoundError(
				`createMlsChatProvider: unknown peerIndex ${peerIndex} in epoch ${epoch} for room ${roomId}`,
				{ kid: hdr.kid, epoch, peerIndex },
			);
		}
		const sframeKey = roomState.keys.get(peerId);
		if (!sframeKey) {
			throw new KeyNotFoundError(
				`createMlsChatProvider: no key for peerId ${peerId} in epoch ${epoch}`,
				{ kid: hdr.kid, epoch, peerIndex },
			);
		}

		// Replay check before AEAD (avoids AEAD oracle amplification).
		// The replay window is keyed by senderUid from the context, NOT by
		// peerIndex from the KID — this binds the replay window to the
		// authenticated sender identity, not the wire-encoded index.
		const rw = getRw(replayWindows, roomId, senderUid, replayWindow);
		if (!rw.check(ctr)) {
			throw new ReplayError(
				`createMlsChatProvider: replay detected (ctr=${ctr}, room=${roomId}, uid=${senderUid})`,
				{ roomId, senderUid, ctr },
			);
		}
		if (durable?.available) {
			if (!(await durable.check(dk(roomId, senderUid), ctr))) {
				throw new ReplayError(
					`createMlsChatProvider: durable cross-reload replay detected (ctr=${ctr}, room=${roomId}, uid=${senderUid})`,
					{ roomId, senderUid, ctr },
				);
			}
		}

		const plaintext = await sframeDecrypt(sealed, () => sframeKey);

		// Record CTR only after successful AEAD.
		rw.accept(ctr);
		if (durable?.available) {
			await durable.accept(dk(roomId, senderUid), ctr);
		}
		return plaintext;
	}

	function clearEpoch(roomId: string): void {
		roomEpochs.delete(roomId);
		const senders = replayWindows.get(roomId);
		replayWindows.delete(roomId);
		if (durable?.available && senders) {
			for (const senderUid of senders.keys()) {
				void durable.clear(dk(roomId, senderUid));
			}
		}
		opts.onEpochCleared?.(roomId);
	}

	function getEpoch(roomId: string): number | null {
		return roomEpochs.get(roomId)?.epoch ?? null;
	}

	function dispose(): void {
		// Zeroize is not possible for CryptoKey objects (non-extractable keys
		// are managed by the WebCrypto runtime). We drop all references so
		// GC can collect them.
		roomEpochs.clear();
		replayWindows.clear();
	}

	return { setEpoch, seal, unseal, clearEpoch, getEpoch, dispose };
}
