// Room ratchet: epoch axis (membership changes) only. Revision 2026-04-21:
// per-sender AEAD derivation (spec §2.2), per-epoch receive-side key table
// keyed by peer_index (spec §4.3 step 8). Lex-smallest peer is epoch author;
// non-authors wait for an EpochAnnouncement addressed to them.

import type {
	EpochAnnouncement,
	IdentityKeyPair,
	MemberChange,
	PeerIdentity,
	PeerIndex,
	SFrameKey,
} from './types.ts';
import { KeyNotFoundError } from './errors.ts';
import { assertSuiteAllowed } from './strict-fips.ts';
import {
	DEFAULT_CIPHER_SUITE,
	type CipherSuite,
	deriveEpochKeyTable,
	deriveSenderKeys,
	deriveWrapKey,
	randomChainKey,
	unwrapChainKey,
	x25519Dh,
} from './ratchet-crypto.ts';
import {
	buildPeerIndexMap,
	validatePeerIndexMap,
	wrapChainKeyForPeer,
} from './ratchet-ids.ts';
import { computeSas, type SasData } from './sas.ts';
import { makeKidCodec, type KidCodec, type KidFormat, type MlsKidConfig } from './kid-format.ts';

export { joinKid, makeKid, newIdentity, splitKid, validatePeerIndexMap } from './ratchet-ids.ts';
export type { KidFormat, MlsKidConfig, KidCodec } from './kid-format.ts';
export { makeKidCodec, FIXED_KID_CODEC, encodeMlsKid, decodeMlsKid, validateMlsBitRange } from './kid-format.ts';

/** Per-epoch state. Raw `chainKey` bytes are never logged. */
interface EpochState {
	epoch: number;
	chainKey: Uint8Array; // 32 bytes — kept to re-wrap for late joiners
	peerIndexMap: Record<string, PeerIndex>;
	selfPeerIndex: PeerIndex;
	// Per-sender keys for every member of this epoch, keyed by peer_index.
	keys: Map<PeerIndex, SFrameKey>;
}

/**
 * Per-peer SAS state. Stored when a peer session is established (ChainKey
 * wrap/unwrap complete and the DH secret is available). Wiped on epoch
 * rotation (issue #11 security contract: SAS is per-peer, per-epoch).
 *
 * SECURITY: `data` is a derivation of the DH secret, not the secret itself.
 * It is displayed locally and compared out-of-band — never sent over the
 * signaling channel.
 */
interface PeerSasState {
	/** The epoch this SAS was computed for. */
	epoch: number;
	/** The SAS data (decimal + emoji) shown to the user. */
	data: SasData;
	/** User-verified flag, set via markSasVerified. */
	verified: boolean;
}

export interface RoomRatchetOptions {
	identity: IdentityKeyPair;
	/** Known members at construction time (excluding self). */
	initialPeers?: PeerIdentity[];
	/**
	 * RFC 9605 §4.5 cipher suite. Defaults to `AES_128_GCM_SHA256` (suite 4).
	 * All members of a room MUST use the same suite.
	 */
	suite?: CipherSuite;
	/**
	 * KID encoding format (RFC 9605 §5.2 / §6.1). Defaults to `'fixed'`
	 * (the historical 32-bit `(epoch << 16) | peerIndex` split). When set to
	 * `'mls'`, the KID is encoded/decoded per the §5.2 MLS Key ID layout
	 * using `mlsConfig`.
	 *
	 * SECURITY: all parties in a room MUST agree on kidFormat + bit widths
	 * (signaling concern — same as suite agreement). No auto-negotiation.
	 */
	kidFormat?: KidFormat;
	/**
	 * MLS Key ID configuration (RFC 9605 §5.2). Required when `kidFormat` is
	 * `'mls'`; ignored when `kidFormat` is `'fixed'` or unset.
	 */
	mlsConfig?: MlsKidConfig;
}

/**
 * The per-room ratchet. Single instance per room per client.
 *
 * Caller coordinates signaling: after `startNewEpoch()` the caller sends each
 * returned `EpochAnnouncement` on DC id:1, and on receipt of a peer's
 * announcement calls `consumeEpochAnnouncement()`. The ratchet does not do
 * any I/O itself.
 */
export class RoomRatchet {
	private readonly identity: IdentityKeyPair;
	private readonly suite: CipherSuite;
	private readonly _kidCodec: KidCodec;
	private peers: Map<string, PeerIdentity>;
	private epochs: Map<number, EpochState> = new Map();
	private currentEpoch = -1;

	// Per-peer SAS state, keyed by peerId. Set when a session is established
	// (ChainKey wrap/unwrap complete + DH secret available). Wiped on epoch
	// rotation (issue #11: SAS is per-peer, per-epoch).
	private sasState: Map<string, PeerSasState> = new Map();

	// Callbacks fired when SAS becomes available for a peer (onSasReady).
	private sasReadyCallbacks: Set<(peerId: string) => void> = new Set();

	constructor(opts: RoomRatchetOptions) {
		this.identity = opts.identity;
		this.suite = opts.suite ?? DEFAULT_CIPHER_SUITE;
		assertSuiteAllowed(this.suite);
		this._kidCodec = makeKidCodec(opts.kidFormat, opts.mlsConfig);
		this.peers = new Map();
		for (const p of opts.initialPeers ?? []) this.peers.set(p.peerId, p);
	}

	/** True if this node's peer_id is lex-smallest across all epoch members (§4.3 step 6). */
	private isAuthoritativeAuthor(): boolean {
		const allIds = [this.identity.peerId, ...this.peers.keys()].sort();
		return allIds[0] === this.identity.peerId;
	}

	/** Mint or re-wrap ChainKey_e, build peer_index_map, emit one announcement per recipient (§4.3). */
	async startNewEpoch(
		members: PeerIdentity[],
		options: { version?: number; viaChainKey?: Uint8Array } = {},
	): Promise<EpochAnnouncement[]> {
		this.peers = new Map(members.map((p) => [p.peerId, p]));
		const version = options.version ?? this.currentEpoch + 1;

		let chainKey: Uint8Array;
		if (options.viaChainKey) {
			chainKey = options.viaChainKey;
		} else if (this.isAuthoritativeAuthor()) {
			chainKey = randomChainKey(this.suite);
		} else {
			throw new Error('ratchet: non-authoritative author called startNewEpoch without viaChainKey');
		}

		const allIds = [this.identity.peerId, ...members.map((p) => p.peerId)];
		const peerIndexMap = buildPeerIndexMap(allIds);
		await this.installEpoch(version, chainKey, peerIndexMap);

		const out: EpochAnnouncement[] = [];
		for (const peer of members) {
			if (peer.peerId === this.identity.peerId) continue;
			const { announcement, dhSecret } = await wrapChainKeyForPeer(
				this.identity.peerId, peer, chainKey, version, peerIndexMap,
			);
			out.push(announcement);
			// SAS: derive from the SAME DH secret used to wrap the ChainKey
			// (security contract, issue #11). The dhSecret is the X25519
			// shared secret that was used to derive the wrap key above.
			await this.installSas(peer.peerId, version, dhSecret);
		}
		return out;
	}

	/** Consume inbound EpochAnnouncement; throws on decrypt fail or bad map (caller emits epoch_error, §4.2/§7.8). */
	async consumeEpochAnnouncement(msg: EpochAnnouncement): Promise<void> {
		if (msg.forPeer !== this.identity.peerId) {
			// Fix 2b: mirror epoch_new_dropped_for_peer_mismatch observability in the ratchet layer.
			// Callers (handleEpochNew) already guard with for_peer check before reaching here,
			// so this path is an extra safety net for direct callers of consumeEpochAnnouncement.
			console.warn('[gc:ratchet] consumeEpochAnnouncement: announcement for different peer dropped', {
				mine: this.identity.peerId,
				target: msg.forPeer,
				version: msg.version,
			});
			return;
		}
		const validation = validatePeerIndexMap(msg.peerIndexMap);
		if (!validation.valid) {
			throw new Error(`ratchet: invalid peer_index_map (${validation.reason})`);
		}
		if (!(this.identity.peerId in msg.peerIndexMap)) {
			throw new Error('ratchet: peer_index_map missing self');
		}
		const shared = await x25519Dh(this.identity.privateKey, msg.ephemeralPub);
		const wrapKey = await deriveWrapKey(shared, msg.version);
		const chainKey = await unwrapChainKey(msg.keyWrapped, msg.iv, wrapKey);
		await this.installEpoch(msg.version, chainKey, msg.peerIndexMap);
		// SAS: derive from the SAME DH secret used to unwrap the ChainKey
		// (security contract, issue #11). `shared` is the X25519 secret that
		// was used to derive the wrap key above — the same secret the sender
		// used to wrap, so both peers get identical SAS.
		await this.installSas(msg.from, msg.version, shared);
	}

	private async installEpoch(
		version: number,
		chainKey: Uint8Array,
		peerIndexMap: Record<string, PeerIndex>,
	): Promise<void> {
		const selfPeerIndex = peerIndexMap[this.identity.peerId];
		if (selfPeerIndex === undefined) {
			throw new Error('ratchet: self peer_id missing from peer_index_map');
		}
		const keys = await deriveEpochKeyTable(chainKey, version, peerIndexMap, this.suite, this._kidCodec);
		this.epochs.set(version, {
			epoch: version, chainKey, peerIndexMap, selfPeerIndex, keys,
		});
		if (version > this.currentEpoch) {
			const prev = this.currentEpoch;
			this.currentEpoch = version;
			// Rotation wipes SAS state (issue #11 security contract: SAS is
			// per-peer, per-epoch). New epoch → new DH secrets → old SAS is
			// invalid. We wipe all SAS for epochs < the new current epoch.
			this.wipeSasForRotation(version);
			// Memory-leak fix (#60-followup, found via dead-code audit):
			// without this, this.epochs grows unbounded across rotations
			// (each member-change adds an entry that's never freed). Spec
			// §7.4 mandates a 2s grace so late RTP frames from the prior
			// epoch still decrypt; we use 5s for safety on slow networks.
			if (prev >= 0) {
				setTimeout(() => this.forgetEpoch(prev), 5_000);
			}
		}
	}

	/** This node's per-sender SFrame key for the current epoch (idempotent; no per-frame ratchet in v1). */
	advanceSending(): SFrameKey {
		const state = this.epochs.get(this.currentEpoch);
		if (!state) {
			throw new KeyNotFoundError('ratchet: no active epoch', { epoch: this.currentEpoch });
		}
		const key = state.keys.get(state.selfPeerIndex);
		if (!key) {
			throw new KeyNotFoundError('ratchet: no self key in current epoch', {
				epoch: this.currentEpoch,
				peerIndex: state.selfPeerIndex,
			});
		}
		return key;
	}

	/**
	 * Look up a receiving key by (epoch, peerIndex) extracted from a KID.
	 * Returns null if the epoch is unknown (wiped after the 2 s grace) or the
	 * peer_index is outside the epoch's map.
	 */
	getReceivingKey(epoch: number, peerIndex: PeerIndex): SFrameKey | null {
		const state = this.epochs.get(epoch);
		return state?.keys.get(peerIndex) ?? null;
	}

	/**
	 * Handle a membership change by bumping to a new epoch. See spec §§ 4.3, 4.4.
	 * Returns announcements to broadcast (may be empty if this node is not the
	 * authoritative author).
	 */
	async rotateOnMemberChange(delta: MemberChange): Promise<EpochAnnouncement[]> {
		const next = new Map(this.peers);
		if (delta.kind === 'join' || delta.kind === 'reconnect') {
			next.set(delta.peer.peerId, delta.peer);
		} else {
			next.delete(delta.peerId);
		}
		this.peers = next;
		if (!this.isAuthoritativeAuthor()) return [];
		return this.startNewEpoch(Array.from(next.values()));
	}

	/** Drop an epoch's key material (spec §7.4 2 s grace expiry). */
	forgetEpoch(epoch: number): void {
		this.epochs.delete(epoch);
	}

	/** Current epoch number, for diagnostics / signaling. */
	get epoch(): number { return this.currentEpoch; }

	/** The KID codec in use (fixed or mls). Read-only accessor for diagnostics. */
	get kidCodec(): KidCodec { return this._kidCodec; }

	/** Peer-index map for the current epoch. Returns empty object before first epoch.
	 *  Used by debug diagnostics (installGroupCallDebugGetters) and by kxConsumerEpochs
	 *  in the diag-503 debug getters — acceptable production use, not in a hot loop. */
	get currentPeerIndexMap(): Record<string, number> {
		return { ...this.epochs.get(this.currentEpoch)?.peerIndexMap ?? {} };
	}

	/**
	 * Peer-index map for a SPECIFIC installed epoch. Returns null if the epoch is
	 * unknown (never installed, or already wiped after the grace window). Returns a
	 * defensive copy so callers cannot mutate internal state. Public accessor so
	 * consumers stop narrow-casting into the private `epochs` map.
	 */
	getEpochPeerIndexMap(epoch: number): Record<string, PeerIndex> | null {
		const state = this.epochs.get(epoch);
		return state ? { ...state.peerIndexMap } : null;
	}

	/** Self's peer_index in the current epoch (undefined before first epoch). */
	get selfPeerIndex(): PeerIndex | undefined {
		return this.epochs.get(this.currentEpoch)?.selfPeerIndex;
	}

	/** Read-only identity (used by M3.3 `KeyExchange` to advertise kpub). */
	getIdentity(): Readonly<IdentityKeyPair> { return this.identity; }

	/** ChainKey bytes for an installed epoch; null if unknown/wiped. Sensitive — do not log. */
	getEpochChainKey(epoch: number): Uint8Array | null {
		return this.epochs.get(epoch)?.chainKey ?? null;
	}

	/** Re-wrap current ChainKey for `peer` (spec §7.2 epoch_request retry). Null if not author. */
	async rewrapCurrentEpochFor(peer: PeerIdentity): Promise<EpochAnnouncement | null> {
		if (!this.isAuthoritativeAuthor()) return null;
		const state = this.epochs.get(this.currentEpoch);
		if (!state) return null;
		const { announcement, dhSecret } = await wrapChainKeyForPeer(
			this.identity.peerId, peer, state.chainKey, state.epoch, state.peerIndexMap,
		);
		// SAS: derive from the SAME DH secret used to re-wrap the ChainKey.
		await this.installSas(peer.peerId, state.epoch, dhSecret);
		return announcement;
	}

	// ---- SAS (Short Authentication String) verification -------------------
	//
	// Issue #11: MITM detection for the ECIES ChainKey wrap. SAS bytes are
	// derived from the SAME DH secret used to wrap/unwrap the ChainKey, so a
	// MITM who substitutes their own identity key produces a different SAS
	// that users detect by comparing out-of-band.

	/**
	 * Internal: compute SAS from a DH secret and store it for `peerId`.
	 *
	 * SECURITY INVARIANT: `dhSecret` MUST be the same X25519 shared secret
	 * that was used to derive the wrap key for this peer in this epoch. The
	 * callers (startNewEpoch, consumeEpochAnnouncement, rewrapCurrentEpochFor)
	 * enforce this by passing the `shared` / `dhSecret` variable that fed
	 * `deriveWrapKey` — the very same bytes.
	 */
	private async installSas(peerId: string, epoch: number, dhSecret: Uint8Array): Promise<void> {
		const data = await computeSas(dhSecret);
		this.sasState.set(peerId, { epoch, data, verified: false });
		// Notify subscribers that SAS is available for this peer.
		for (const cb of this.sasReadyCallbacks) {
			try { cb(peerId); } catch { /* swallow — a buggy callback must not break others */ }
		}
	}

	/**
	 * Wipe SAS state for all peers whose SAS belongs to an epoch older than
	 * `newEpoch`. Called on epoch rotation (issue #11: SAS is per-peer,
	 * per-epoch; rotation wipes it).
	 */
	private wipeSasForRotation(newEpoch: number): void {
		for (const [peerId, state] of this.sasState) {
			if (state.epoch < newEpoch) {
				this.sasState.delete(peerId);
			}
		}
	}

	/**
	 * Returns the SAS (decimal + emoji) for an established peer session, or
	 * `null` if no session has been established for `peerId` in the current
	 * epoch.
	 *
	 * The SAS is displayed locally and compared out-of-band. It is NEVER sent
	 * over the signaling channel.
	 */
	getSas(peerId: string): SasData | null {
		return this.sasState.get(peerId)?.data ?? null;
	}

	/**
	 * Record the user's out-of-band SAS verification result for `peerId`.
	 * Call with `true` after the user confirms the SAS matches, `false` to
	 * revoke (e.g. mismatch detected or session re-keyed).
	 */
	markSasVerified(peerId: string, verified: boolean): void {
		const state = this.sasState.get(peerId);
		if (state) {
			state.verified = verified;
		}
	}

	/**
	 * Returns the SAS verification state for `peerId`. `false` if no session
	 * is established or the user has not yet verified.
	 */
	isSasVerified(peerId: string): boolean {
		return this.sasState.get(peerId)?.verified ?? false;
	}

	/**
	 * Subscribe to a callback that fires when a peer session is established
	 * and SAS is available for out-of-band comparison.
	 *
	 * @returns An unsubscribe function. Call it to remove the listener.
	 */
	onSasReady(callback: (peerId: string) => void): () => void {
		this.sasReadyCallbacks.add(callback);
		return () => { this.sasReadyCallbacks.delete(callback); };
	}
}
