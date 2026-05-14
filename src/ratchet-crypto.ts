// Crypto primitive helpers for the room ratchet: X25519 DH (WebCrypto with
// @noble/curves fallback), HKDF extraction, per-epoch AES-GCM key-wrap used to
// deliver ChainKeys, and the per-sender AEAD key derivation (spec §§ 4.3, 5,
// 2.2). Raw ChainKey bytes are touched only here and never logged. AES-GCM
// CryptoKeys are non-extractable.

import { x25519 } from '@noble/curves/ed25519.js';
import type { PeerIndex, SFrameKey } from './types.ts';
import { SFRAME_INFO_KEY, SFRAME_INFO_SALT, hkdfInfo, makeKid } from './ratchet-ids.ts';
import { toArrayBuffer as asArrayBuffer } from './internal/buffer.js';

export const X25519_KEY_BYTES = 32;
export const CHAIN_KEY_BYTES = 32;
export const SFRAME_SALT_BYTES = 12;

// HKDF info label for the per-recipient epoch-wrap key (spec §4.3 step 5).
// Unchanged by this revision — the X25519→HKDF→AES-GCM wrap delivers ChainKey.
const INFO_WRAP = (version: number) =>
	new TextEncoder().encode(`oxpulse/sframe/v1/epoch-wrap/${version}`);

// --- X25519 DH (feature-detect WebCrypto, fall back to @noble/curves) ------

let webCryptoX25519: boolean | null = null;

async function hasWebCryptoX25519(): Promise<boolean> {
	if (webCryptoX25519 !== null) return webCryptoX25519;
	try {
		await crypto.subtle.generateKey({ name: 'X25519' } as never, true, ['deriveBits']);
		webCryptoX25519 = true;
	} catch {
		webCryptoX25519 = false;
	}
	return webCryptoX25519;
}

/** Fresh X25519 keypair — raw 32 B pub + 32 B secret via @noble (uniform format). */
export function generateX25519Keypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
	const kp = x25519.keygen();
	return { publicKey: kp.publicKey, privateKey: kp.secretKey };
}

/** X25519 DH. WebCrypto preferred; @noble/curves fallback for old browsers. */
export async function x25519Dh(
	privateKey: Uint8Array,
	peerPublicKey: Uint8Array,
): Promise<Uint8Array> {
	if (await hasWebCryptoX25519()) {
		try {
			const priv = await crypto.subtle.importKey(
				'raw', asArrayBuffer(privateKey),
				{ name: 'X25519' } as never, false, ['deriveBits'],
			);
			const pub = await crypto.subtle.importKey(
				'raw', asArrayBuffer(peerPublicKey),
				{ name: 'X25519' } as never, false, [],
			);
			const shared = await crypto.subtle.deriveBits(
				{ name: 'X25519', public: pub } as never, priv, 256,
			);
			return new Uint8Array(shared);
		} catch {
			// Some browsers ship X25519 under a slightly different shape; @noble below is always correct.
		}
	}
	return x25519.getSharedSecret(privateKey, peerPublicKey);
}

// --- HKDF / key-wrap ------------------------------------------------------

async function hkdfExtractExpand(
	ikm: Uint8Array,
	info: Uint8Array,
	length: number,
): Promise<Uint8Array> {
	const material = await crypto.subtle.importKey(
		'raw', asArrayBuffer(ikm), 'HKDF', false, ['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: new ArrayBuffer(0),
			info: asArrayBuffer(info),
		},
		material,
		length * 8,
	);
	return new Uint8Array(bits);
}

/** Per-recipient AES-256-GCM wrap key from ECDH shared secret (spec §4.3 step 5). */
export async function deriveWrapKey(shared: Uint8Array, version: number): Promise<CryptoKey> {
	const raw = await hkdfExtractExpand(shared, INFO_WRAP(version), 32);
	return crypto.subtle.importKey(
		'raw', asArrayBuffer(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
	);
}

/** Wrap a 32-byte ChainKey under an AES-GCM wrap key with a fresh 12-byte IV. */
export async function wrapChainKey(
	chainKey: Uint8Array,
	wrapKey: CryptoKey,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
	if (chainKey.length !== CHAIN_KEY_BYTES) {
		throw new Error(`ratchet: chain key must be ${CHAIN_KEY_BYTES} bytes`);
	}
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = new Uint8Array(await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: asArrayBuffer(iv) }, wrapKey, asArrayBuffer(chainKey),
	));
	return { ciphertext: ct, iv };
}

/** Unwrap a ChainKey ciphertext. Throws on tag failure. */
export async function unwrapChainKey(
	ciphertext: Uint8Array, iv: Uint8Array, wrapKey: CryptoKey,
): Promise<Uint8Array> {
	const pt = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: asArrayBuffer(iv) }, wrapKey, asArrayBuffer(ciphertext),
	);
	const out = new Uint8Array(pt);
	if (out.length !== CHAIN_KEY_BYTES) {
		throw new Error(`ratchet: unwrapped key has wrong length: ${out.length}`);
	}
	return out;
}

/**
 * Per-sender SFrame AEAD bundle from ChainKey + peer_index (spec §2.2, revised):
 *   AEADKey = HKDF-Expand(ChainKey, "sframe/v1/key"  || peer_index_be16, 32)
 *   Salt    = HKDF-Expand(ChainKey, "sframe/v1/salt" || peer_index_be16, 12)
 * HKDF-Expand only (empty salt) — ChainKey is already uniform 32 B.
 */
export async function deriveSenderKeys(
	chainKey: Uint8Array, epoch: number, peerIndex: PeerIndex,
): Promise<SFrameKey> {
	if (chainKey.length !== CHAIN_KEY_BYTES) {
		throw new Error(`ratchet: chain key must be ${CHAIN_KEY_BYTES} bytes`);
	}
	const [keyRaw, salt] = await Promise.all([
		hkdfExtractExpand(chainKey, hkdfInfo(SFRAME_INFO_KEY, peerIndex), 32),
		hkdfExtractExpand(chainKey, hkdfInfo(SFRAME_INFO_SALT, peerIndex), SFRAME_SALT_BYTES),
	]);
	const cryptoKey = await crypto.subtle.importKey(
		'raw', asArrayBuffer(keyRaw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
	);
	return { kid: makeKid(epoch, peerIndex), epoch, peerIndex, cryptoKey, salt };
}

/** Derive per-sender bundles for every entry in `peerIndexMap` (spec §4.3 step 8). */
export async function deriveEpochKeyTable(
	chainKey: Uint8Array, epoch: number, peerIndexMap: Record<string, PeerIndex>,
): Promise<Map<PeerIndex, SFrameKey>> {
	const entries = await Promise.all(
		Object.values(peerIndexMap).map(async (idx) => {
			const key = await deriveSenderKeys(chainKey, epoch, idx);
			return [idx, key] as const;
		}),
	);
	return new Map(entries);
}

/** Fresh 32-byte ChainKey (spec §3.1: author uses getRandomValues). */
export function randomChainKey(): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(CHAIN_KEY_BYTES));
}

