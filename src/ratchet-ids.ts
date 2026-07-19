// Identity + KID + peer_index helpers for the room ratchet.
// Split out from ratchet.ts to keep the state machine module focused and to
// keep ratchet-crypto.ts under the 200-LOC soft limit. Pure functions only —
// no mutable state, no side effects beyond the WebCrypto calls inside
// `wrapChainKeyForPeer`.

import type {
	EpochAnnouncement,
	IdentityKeyPair,
	PeerIdentity,
	PeerIndex,
} from './types.ts';
import {
	deriveWrapKey,
	generateX25519Keypair,
	wrapChainKey,
	x25519Dh,
} from './ratchet-crypto.ts';

// --- KID schema (spec §6.1) -----------------------------------------------

/**
 * Build a 32-bit KID per spec §6.1:
 *   KID = (epoch_version << 16) | (peer_index & 0xFFFF)
 *
 * High 16 bits: monotonic epoch counter per room.
 * Low 16 bits : per-sender index within the epoch.
 *
 * Both fields are 16-bit unsigned. The `>>> 0` cast forces JS's 32-bit
 * unsigned semantics (otherwise `|` would yield a signed int32).
 */
export function makeKid(epoch: number, peerIndex: PeerIndex): number {
	if (!Number.isInteger(epoch) || epoch < 0 || epoch > 0xffff) {
		throw new RangeError(`epoch out of range [0, 0xffff]: ${epoch}`);
	}
	if (!Number.isInteger(peerIndex) || peerIndex < 0 || peerIndex > 0xffff) {
		throw new RangeError(`peerIndex out of range [0, 0xffff]: ${peerIndex}`);
	}
	return (((epoch & 0xffff) << 16) | (peerIndex & 0xffff)) >>> 0;
}

/** Inverse of makeKid — extract (epoch, peer_index) from a 32-bit KID. */
export function splitKid(kid: number): { epoch: number; peerIndex: PeerIndex } {
	return { epoch: (kid >>> 16) >>> 0, peerIndex: kid & 0xffff };
}

/**
 * Synonym of {@link makeKid} with a struct-shaped input — handy for the
 * frame-cryptor and test sites that already carry {epoch, peerIndex} objects.
 */
export function joinKid(parts: { epoch: number; peerIndex: PeerIndex }): number {
	return makeKid(parts.epoch, parts.peerIndex);
}

// --- per-sender HKDF info construction (spec §2.2) ------------------------

/**
 * HKDF `info` base labels. MUST match spec §2.2 byte-for-byte. Per the
 * revision note, the labels are `sframe/v1/key` (13 B) and `sframe/v1/salt`
 * (14 B), concatenated with `peer_index_be16` (2 B) for domain separation.
 */
export const SFRAME_INFO_KEY = new TextEncoder().encode('sframe/v1/key'); // 13 B
export const SFRAME_INFO_SALT = new TextEncoder().encode('sframe/v1/salt'); // 14 B

/** Encode a 16-bit peer_index as 2 big-endian bytes. */
export function peerIndexBe16(peerIndex: PeerIndex): Uint8Array {
	if (!Number.isInteger(peerIndex) || peerIndex < 0 || peerIndex > 0xffff) {
		throw new RangeError(`peerIndex out of range [0, 0xffff]: ${peerIndex}`);
	}
	const out = new Uint8Array(2);
	out[0] = (peerIndex >>> 8) & 0xff;
	out[1] = peerIndex & 0xff;
	return out;
}

/** Concatenate `base || peer_index_be16` to build the HKDF info parameter. */
export function hkdfInfo(base: Uint8Array, peerIndex: PeerIndex): Uint8Array {
	const pi = peerIndexBe16(peerIndex);
	const out = new Uint8Array(base.length + pi.length);
	out.set(base, 0);
	out.set(pi, base.length);
	return out;
}

// --- peer_index_map invariant (spec §7.8) ---------------------------------

export type PeerIndexMapValidation =
	| { valid: true }
	| { valid: false; reason: 'empty' | 'duplicate_index' | 'gap_or_out_of_range' | 'bad_value' };

/**
 * Enforce the spec §7.8 invariant on `peer_index_map`:
 *   - Non-empty.
 *   - Integer indices in `[0, N)` where `N = Object.keys(map).length`.
 *   - All values distinct.
 *   - Value set equals exactly `{0, 1, …, N-1}` (no gaps, no duplicates,
 *     no out-of-range).
 *
 * Records cannot have duplicate keys in JS, so key-distinctness is implicit.
 *
 * Fail-closed: the caller MUST reject the `epoch_new` on any `valid: false`
 * result and degrade to transit-only per spec §7.8 / §7.2.
 */
export function validatePeerIndexMap(
	map: Record<string, PeerIndex>,
): PeerIndexMapValidation {
	const keys = Object.keys(map);
	if (keys.length === 0) return { valid: false, reason: 'empty' };

	const n = keys.length;
	const seen = new Set<number>();
	for (const k of keys) {
		const v = map[k];
		if (!Number.isInteger(v) || v < 0 || v >= n) {
			return { valid: false, reason: 'bad_value' };
		}
		if (seen.has(v)) return { valid: false, reason: 'duplicate_index' };
		seen.add(v);
	}
	// With non-negative integers < n, |seen| == n iff values = {0..n-1}.
	// Duplicates are already rejected above, so a short set means a gap.
	if (seen.size !== n) return { valid: false, reason: 'gap_or_out_of_range' };
	return { valid: true };
}

// --- identity + wrapping --------------------------------------------------

/** Create a fresh IdentityKeyPair for the current session (ephemeral per call). */
export function newIdentity(peerId: string): IdentityKeyPair {
	const kp = generateX25519Keypair();
	return { peerId, publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Result of {@link wrapChainKeyForPeer}: the announcement + the DH secret. */
export interface WrapChainKeyResult {
	announcement: EpochAnnouncement;
	/**
	 * The X25519 shared secret used to derive the wrap key. Returned so the
	 * caller can derive SAS bytes from the SAME secret (security contract:
	 * SAS must derive from the same DH secret that wrapped the ChainKey).
	 * The caller is responsible for not logging this.
	 */
	dhSecret: Uint8Array;
}

/**
 * Wrap a ChainKey for a specific recipient at a given version.
 * Generates a fresh ephemeral X25519 keypair (forward secrecy), computes
 * ECDH → HKDF → AES-GCM(ChainKey).
 *
 * Returns both the announcement and the DH shared secret. The DH secret is
 * needed by the caller to derive SAS bytes — SAS MUST derive from the same
 * DH secret that wrapped the ChainKey (security contract, issue #11).
 *
 * The caller owns the ChainKey lifecycle; this helper neither stores nor
 * zeroises it. `peerIndexMap` is copied verbatim into the announcement — it
 * MUST already be the deterministic `sorted(peer_ids).enumerate()` shape
 * (spec §4.3 step 6); the author is responsible for consistency across
 * recipients of the same epoch version.
 */
export async function wrapChainKeyForPeer(
	fromPeerId: string,
	peer: PeerIdentity,
	chainKey: Uint8Array,
	version: number,
	peerIndexMap: Record<string, PeerIndex>,
): Promise<WrapChainKeyResult> {
	const ephemeral = generateX25519Keypair();
	const shared = await x25519Dh(ephemeral.privateKey, peer.publicKey);
	const wrapKey = await deriveWrapKey(shared, version);
	const { ciphertext, iv } = await wrapChainKey(chainKey, wrapKey);
	const announcement: EpochAnnouncement = {
		version,
		from: fromPeerId,
		forPeer: peer.peerId,
		keyWrapped: ciphertext,
		iv,
		ephemeralPub: ephemeral.publicKey,
		peerIndexMap: { ...peerIndexMap },
	};
	return { announcement, dhSecret: shared };
}

/**
 * Compute the canonical peer_index assignment for an epoch: sort peer_ids
 * lexicographically and enumerate 0..N−1. Matches spec §4.3 step 6 and §4.4.
 */
export function buildPeerIndexMap(peerIds: string[]): Record<string, PeerIndex> {
	const sorted = [...peerIds].sort();
	const out: Record<string, PeerIndex> = {};
	for (let i = 0; i < sorted.length; i++) out[sorted[i]] = i;
	return out;
}
