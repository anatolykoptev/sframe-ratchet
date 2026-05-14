// Crypto primitive helpers for the room ratchet: X25519 DH (WebCrypto with
// @noble/curves fallback), HKDF extraction, per-epoch AES-GCM key-wrap used to
// deliver ChainKeys, and the per-sender AEAD key derivation (spec §§ 4.3, 5,
// 2.2). Raw ChainKey bytes are touched only here and never logged. AES-GCM
// CryptoKeys are non-extractable.

import { x25519 } from '@noble/curves/ed25519.js';
import type { PeerIndex, SFrameKey } from './types.ts';
import { SFRAME_INFO_KEY, SFRAME_INFO_SALT, hkdfInfo, makeKid } from './ratchet-ids.ts';
import { toArrayBuffer as asArrayBuffer } from './internal/buffer.js';

// ---- Cipher suite --------------------------------------------------------

/**
 * RFC 9605 §4.5 cipher suites supported by this library.
 *
 * | Suite                   | AEAD        | AEAD key | KDF hash | KDF output | Tag |
 * |-------------------------|-------------|----------|----------|------------|-----|
 * | AES_128_GCM_SHA256_128  | AES-128-GCM | 16 bytes | SHA-256  | 32 bytes   | 16  |
 * | AES_256_GCM_SHA512_128  | AES-256-GCM | 32 bytes | SHA-512  | 64 bytes   | 16  |
 */
export type CipherSuite = 'AES_128_GCM_SHA256' | 'AES_256_GCM_SHA512';

/** Default suite per RFC 9605 (suite 4). */
export const DEFAULT_CIPHER_SUITE: CipherSuite = 'AES_128_GCM_SHA256';

/** Per-suite parameters (RFC 9605 §4.5 table). */
export interface SuiteParams {
	/** WebCrypto hash name for HKDF. */
	hash: 'SHA-256' | 'SHA-512';
	/** AEAD key length in bytes (AES key size). */
	aeadKeyBytes: 16 | 32;
	/**
	 * KDF output length in bytes; used as the ChainKey size (RFC §4.4.1: the
	 * base_key feeding the SFrame key schedule has size KDF.Nh).
	 */
	chainKeyBytes: 32 | 64;
}

/** Return the immutable parameter set for a given suite. */
export function suiteParams(suite: CipherSuite): SuiteParams {
	switch (suite) {
		case 'AES_128_GCM_SHA256':
			return { hash: 'SHA-256', aeadKeyBytes: 16, chainKeyBytes: 32 };
		case 'AES_256_GCM_SHA512':
			return { hash: 'SHA-512', aeadKeyBytes: 32, chainKeyBytes: 64 };
	}
}

export const X25519_KEY_BYTES = 32;
/** ChainKey size for the default suite (suite 4 / SHA-256). */
export const CHAIN_KEY_BYTES = 32;
export const SFRAME_SALT_BYTES = 12;

// HKDF info label for the per-recipient epoch-wrap key (spec §4.3 step 5).
// The wrap transport itself always uses AES-256-GCM + HKDF-SHA-256 regardless
// of the call-level cipher suite — it is not part of the RFC 9605 §4.5 suite
// definition, which governs only the per-sender AEAD key schedule.
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
	hash: 'SHA-256' | 'SHA-512' = 'SHA-256',
): Promise<Uint8Array> {
	const material = await crypto.subtle.importKey(
		'raw', asArrayBuffer(ikm), 'HKDF', false, ['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash,
			salt: new ArrayBuffer(0),
			info: asArrayBuffer(info),
		},
		material,
		length * 8,
	);
	return new Uint8Array(bits);
}

/**
 * Per-recipient AES-256-GCM wrap key from ECDH shared secret (spec §4.3 step 5).
 *
 * The wrap transport always uses HKDF-SHA-256 + AES-256-GCM regardless of the
 * call-level cipher suite. This is an internal transport mechanism, not the
 * RFC 9605 §4.5 per-sender AEAD key schedule.
 */
export async function deriveWrapKey(shared: Uint8Array, version: number): Promise<CryptoKey> {
	const raw = await hkdfExtractExpand(shared, INFO_WRAP(version), 32, 'SHA-256');
	return crypto.subtle.importKey(
		'raw', asArrayBuffer(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
	);
}

/** Wrap a ChainKey under an AES-GCM wrap key with a fresh 12-byte IV. */
export async function wrapChainKey(
	chainKey: Uint8Array,
	wrapKey: CryptoKey,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
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
	return new Uint8Array(pt);
}

/**
 * Per-sender SFrame AEAD bundle from ChainKey + peer_index (RFC 9605 §4.4, §4.5):
 *   AEADKey = HKDF-Expand(ChainKey, "sframe/v1/key"  || peer_index_be16, aeadKeyBytes)
 *   Salt    = HKDF-Expand(ChainKey, "sframe/v1/salt" || peer_index_be16, 12)
 * HKDF hash and AEAD key size are determined by the cipher suite.
 * ChainKey must be suite.chainKeyBytes long.
 */
export async function deriveSenderKeys(
	chainKey: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	suite: CipherSuite = DEFAULT_CIPHER_SUITE,
): Promise<SFrameKey & { rawKey: Uint8Array }> {
	const params = suiteParams(suite);
	if (chainKey.length !== params.chainKeyBytes) {
		throw new Error(
			`ratchet: chain key must be ${params.chainKeyBytes} bytes for suite ${suite}, got ${chainKey.length}`,
		);
	}
	const [keyRaw, salt] = await Promise.all([
		hkdfExtractExpand(chainKey, hkdfInfo(SFRAME_INFO_KEY, peerIndex), params.aeadKeyBytes, params.hash),
		hkdfExtractExpand(chainKey, hkdfInfo(SFRAME_INFO_SALT, peerIndex), SFRAME_SALT_BYTES, params.hash),
	]);
	const cryptoKey = await crypto.subtle.importKey(
		'raw', asArrayBuffer(keyRaw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
	);
	return { kid: makeKid(epoch, peerIndex), epoch, peerIndex, cryptoKey, salt, rawKey: keyRaw };
}

/** Derive per-sender bundles for every entry in `peerIndexMap` (spec §4.3 step 8). */
export async function deriveEpochKeyTable(
	chainKey: Uint8Array,
	epoch: number,
	peerIndexMap: Record<string, PeerIndex>,
	suite: CipherSuite = DEFAULT_CIPHER_SUITE,
): Promise<Map<PeerIndex, SFrameKey & { rawKey: Uint8Array }>> {
	const entries = await Promise.all(
		Object.values(peerIndexMap).map(async (idx) => {
			const key = await deriveSenderKeys(chainKey, epoch, idx, suite);
			return [idx, key] as const;
		}),
	);
	return new Map(entries);
}

/** Fresh ChainKey sized for the given suite (defaults to suite 4 = 32 bytes). */
export function randomChainKey(suite: CipherSuite = DEFAULT_CIPHER_SUITE): Uint8Array {
	const { chainKeyBytes } = suiteParams(suite);
	return crypto.getRandomValues(new Uint8Array(chainKeyBytes));
}

// HKDF info label for the per-step ratchet derivation within a single epoch.
// This is a FORWARD derivation: K_{n+1} = HKDF(K_n_raw, info="sframe/v1/ratchet-step").
// The label is intentionally distinct from the per-sender key/salt labels so that
// ratchet-step outputs cannot be confused with leaf AEAD key material.
const SFRAME_INFO_RATCHET_STEP = new TextEncoder().encode('sframe/v1/ratchet-step');

/**
 * Derive the NEXT per-sender AEAD bundle in the within-epoch ratchet chain.
 *
 * K_{n+1} = HKDF-Expand(K_n_raw, "sframe/v1/ratchet-step" || peer_index_be16, aeadKeyBytes)
 * Salt stays FIXED (the same salt as step 0). Nonce uniqueness is maintained by the
 * frame-level CTR, so reusing the salt is safe. Rotating the salt would require
 * shipping it alongside every key-bundle update and complicates the state machine
 * with no security benefit: the AEAD key itself already changes.
 *
 * @param rawKey  Raw bytes of the CURRENT step's AEAD key (suite-sized: 16 or 32).
 * @param salt    The original 12-byte salt for this sender. Passed through unchanged.
 * @param epoch   Epoch number (used to reconstruct the KID).
 * @param peerIndex  Peer index for HKDF domain separation and KID reconstruction.
 * @param suite   Cipher suite — determines hash and AEAD key output size.
 */
export async function deriveNextSenderKey(
	rawKey: Uint8Array,
	salt: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
	suite: CipherSuite = DEFAULT_CIPHER_SUITE,
): Promise<SFrameKey & { rawKey: Uint8Array }> {
	const { hash, aeadKeyBytes } = suiteParams(suite);
	const nextRaw = await hkdfExtractExpand(
		rawKey,
		hkdfInfo(SFRAME_INFO_RATCHET_STEP, peerIndex),
		aeadKeyBytes,
		hash,
	);
	const cryptoKey = await crypto.subtle.importKey(
		'raw', asArrayBuffer(nextRaw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
	);
	return { kid: makeKid(epoch, peerIndex), epoch, peerIndex, cryptoKey, salt, rawKey: nextRaw };
}
