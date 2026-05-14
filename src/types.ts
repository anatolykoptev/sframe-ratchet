// Shared types for the SFrame E2E layer (M3.2).
// Consumed by sframe.ts, ratchet.ts, worker.ts, frame-cryptor.ts.
// See docs/superpowers/specs/2026-04-21-sframe-protocol.md.

/**
 * A 16-bit per-epoch enumeration of a peer, assigned by the epoch author
 * (spec §4.3 step 6) and carried to all recipients via `peer_index_map` in the
 * `epoch_new` DataChannel message (spec §4.2). Travels on the wire inside the
 * SFrame `KID` field (spec §6.1).
 *
 * Newtype for clarity only — at runtime it is a plain `number` in [0, 0xFFFF].
 */
export type PeerIndex = number;

/**
 * An SFrame key as materialised for the AEAD encrypt/decrypt path.
 *
 * - `kid` encodes `(epoch_version << 16) | (peer_index & 0xFFFF)` per spec §6.1.
 * - `epoch` and `peerIndex` are the decomposed KID fields, kept alongside for
 *   O(1) lookup without re-splitting.
 * - `cryptoKey` is a WebCrypto AES-GCM key (non-extractable when produced
 *   by the ratchet; may be extractable in tests).
 * - `salt` is the 12-byte nonce salt per RFC 9605 §4.4.4; XORed with the
 *   big-endian zero-padded CTR to produce the 96-bit AEAD IV.
 *
 * Invariant: `kid === (epoch << 16) | peerIndex`.
 */
export interface SFrameKey {
	kid: number;
	epoch: number;
	peerIndex: PeerIndex;
	cryptoKey: CryptoKey;
	salt: Uint8Array;
}

/**
 * Context handed to the resolver on the decrypt path. The resolver may use
 * `epoch` to enforce the stale-epoch gate (spec §7.4) BEFORE a decrypt attempt.
 */
export interface SFrameKeyLookup {
	kid: number;
	epoch: number;
	peerIndex: PeerIndex;
	ctr: bigint;
}

/** Resolver given to the decrypt path so it can find a key by KID context. */
export type SFrameKeyResolver = (lookup: SFrameKeyLookup) => SFrameKey | null;

/**
 * A long-lived X25519 keypair for the current call session. Ephemeral per
 * call (not persisted); generated on room join. See spec §4.1.
 */
export interface IdentityKeyPair {
	peerId: string;
	publicKey: Uint8Array; // 32 bytes, X25519
	privateKey: Uint8Array; // 32 bytes, X25519 scalar
}

/** A peer's public identity as seen on the DataChannel `identity` message. */
export interface PeerIdentity {
	peerId: string;
	publicKey: Uint8Array; // 32 bytes
}

/**
 * A membership change event driving the ratchet's epoch axis.
 * `kind: 'join'` = new peer, `'leave'` = peer departed, `'reconnect'` = same
 * peer_id re-joining with a fresh pubkey (spec §4.5; treated as a join).
 */
export type MemberChange =
	| { kind: 'join'; peer: PeerIdentity }
	| { kind: 'leave'; peerId: string }
	| { kind: 'reconnect'; peer: PeerIdentity };

/**
 * The DataChannel (id:1) message issued by existing members to a joiner, one
 * per recipient. See spec §4.2 schema 2. Transport is M3.3's concern; this
 * type is a shared contract between M3.2 producers and future M3.3 wire
 * plumbing. base64url encoding is applied at the wire boundary, not here:
 * the fields below are the decoded bytes as passed into ratchet.ts.
 *
 * `peerIndexMap` is identical across all `epoch_new` messages sharing the
 * same `version` — recipient uses it to route inbound frames by KID to the
 * correct per-sender AEAD key (spec §4.2 schema 2, §4.3 step 7).
 */
export interface EpochAnnouncement {
	version: number; // epoch number, monotonic per room
	from: string; // peer_id of sender (author or re-wrap)
	forPeer: string; // peer_id of intended recipient
	keyWrapped: Uint8Array; // AES-256-GCM(shared_key, ChainKey_new)
	iv: Uint8Array; // 12-byte random IV for the wrap AEAD
	ephemeralPub: Uint8Array; // 32-byte X25519 ephemeral pubkey
	peerIndexMap: Record<string, PeerIndex>; // peer_id → 16-bit index
}

/** Result of advanceSending / getReceivingKey: includes epoch + key material. */
export interface EpochKey {
	epoch: number;
	key: SFrameKey;
}

/** Structured error raised for decrypt failures surfaced to the main thread. */
export interface SFrameError {
	reason:
		| 'decrypt_failed'
		| 'key_not_found'
		| 'stale_epoch'
		| 'bad_header'
		| 'short_frame'
		| 'unsupported';
	kid?: number;
	epoch?: number;
	peerIndex?: PeerIndex;
	ctr?: bigint;
	detail?: string;
}

/**
 * Browser-capability probe result returned by supportsSFrame().
 * - `native`: the preferred path (RTCRtpScriptTransform) is present.
 * - `fallback`: createEncodedStreams is present.
 * Both false → transit-only mode (spec §7.5 / §7.6).
 */
export interface SFrameSupport {
	native: boolean;
	fallback: boolean;
}
