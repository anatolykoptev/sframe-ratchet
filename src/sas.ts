// SAS (Short Authentication String) verification for MITM detection (#11).
//
// The X25519 ECIES ChainKey wrap (ratchet-crypto.ts) has no key-verification
// mechanism: if the signaling channel is compromised, an attacker can
// substitute their own identity keys and MITM the ChainKey delivery. Both
// peers establish a session with the attacker instead of with each other, and
// AEAD cannot detect this (the keys are valid, just wrong).
//
// SAS lets users compare emoji or decimal numbers out-of-band to detect the
// MITM. The SAS bytes are derived from the SAME DH shared secret used to
// wrap/unwrap the ChainKey — no separate handshake. The SAS is displayed
// locally only and NEVER sent over the signaling channel.
//
// This is the standard Signal / Matrix / Jitsi approach.
//
// SECURITY CONTRACT:
//   - SAS bytes derive from the SAME DH secret used to wrap the ChainKey.
//   - SAS is NOT sent over the signaling channel — displayed locally only.
//   - SAS state is per-peer, per-epoch; rotation wipes it.
//   - No new key material exposed — SAS bytes are a derivation, not a key.
//   - No timing-safe comparison needed in this layer (users compare visually).

import { toArrayBuffer as asArrayBuffer } from './internal/buffer.js';

// ---- Types ----------------------------------------------------------------

/** A single emoji entry in the 64-emoji SAS table. */
export interface EmojiEntry {
	emoji: string;
	name: string;
}

/** The full SAS representation shown to users for out-of-band comparison. */
export interface SasData {
	/** 3 groups of 5 decimal digits (0–99999), Matrix format. */
	decimal: number[];
	/** 7 emoji from the 64-emoji table. */
	emoji: EmojiEntry[];
}

// ---- Constants ------------------------------------------------------------

/**
 * HKDF info label for SAS derivation. MUST be exactly this string — it
 * domain-separates SAS bytes from all other HKDF outputs in the ratchet
 * (wrap keys, sender keys, ratchet-step keys).
 */
const SAS_INFO = new TextEncoder().encode('sframe-ratchet-sas-v1');

/** Number of bytes derived from the DH secret via HKDF. */
const SAS_BYTES_LENGTH = 6; // 48 bits — enough for 3×2-byte decimal + 7×6-bit emoji

/** Number of decimal groups displayed to the user. */
export const SAS_DECIMAL_GROUP_COUNT = 3;

/** Number of digits per decimal group (zero-padded). */
export const SAS_DECIMAL_DIGITS_PER_GROUP = 5;

/** Modulus for decimal group computation (5 digits → 0–99999). */
const SAS_DECIMAL_MOD = 100000;

/** Number of emoji displayed to the user. */
export const SAS_EMOJI_COUNT = 7;

// ---- 64-emoji table (Matrix / Signal canonical set) -----------------------
//
// Source: matrix-js-sdk SAS.ts EMOJI table (64 entries).
// Each entry is { emoji, name } for accessibility (screen readers).

export const SAS_EMOJI_TABLE: readonly EmojiEntry[] = [
	{ emoji: '🐶', name: 'Dog' },
	{ emoji: '🐱', name: 'Cat' },
	{ emoji: '🦁', name: 'Lion' },
	{ emoji: '🐎', name: 'Horse' },
	{ emoji: '🦄', name: 'Unicorn' },
	{ emoji: '🐷', name: 'Pig' },
	{ emoji: '🐘', name: 'Elephant' },
	{ emoji: '🐰', name: 'Rabbit' },
	{ emoji: '🐼', name: 'Panda' },
	{ emoji: '🐓', name: 'Rooster' },
	{ emoji: '🐧', name: 'Penguin' },
	{ emoji: '🐢', name: 'Turtle' },
	{ emoji: '🐟', name: 'Fish' },
	{ emoji: '🐙', name: 'Octopus' },
	{ emoji: '🦋', name: 'Butterfly' },
	{ emoji: '🌷', name: 'Flower' },
	{ emoji: '🌳', name: 'Tree' },
	{ emoji: '🌵', name: 'Cactus' },
	{ emoji: '🍄', name: 'Mushroom' },
	{ emoji: '🌏', name: 'Globe' },
	{ emoji: '🌙', name: 'Moon' },
	{ emoji: '☁️', name: 'Cloud' },
	{ emoji: '🔥', name: 'Fire' },
	{ emoji: '🍌', name: 'Banana' },
	{ emoji: '🍎', name: 'Apple' },
	{ emoji: '🍓', name: 'Strawberry' },
	{ emoji: '🌽', name: 'Corn' },
	{ emoji: '🍕', name: 'Pizza' },
	{ emoji: '🎂', name: 'Cake' },
	{ emoji: '❤️', name: 'Heart' },
	{ emoji: '😀', name: 'Smiley' },
	{ emoji: '🤖', name: 'Robot' },
	{ emoji: '🎩', name: 'Hat' },
	{ emoji: '👓', name: 'Glasses' },
	{ emoji: '🔧', name: 'Spanner' },
	{ emoji: '🎅', name: 'Santa' },
	{ emoji: '👍', name: 'Thumbs Up' },
	{ emoji: '☂️', name: 'Umbrella' },
	{ emoji: '⌛', name: 'Hourglass' },
	{ emoji: '⏰', name: 'Clock' },
	{ emoji: '🎁', name: 'Gift' },
	{ emoji: '💡', name: 'Light Bulb' },
	{ emoji: '📕', name: 'Book' },
	{ emoji: '✏️', name: 'Pencil' },
	{ emoji: '📎', name: 'Paperclip' },
	{ emoji: '✂️', name: 'Scissors' },
	{ emoji: '🔒', name: 'Lock' },
	{ emoji: '🔑', name: 'Key' },
	{ emoji: '🔨', name: 'Hammer' },
	{ emoji: '📞', name: 'Telephone' },
	{ emoji: '🏁', name: 'Flag' },
	{ emoji: '🚂', name: 'Train' },
	{ emoji: '🚲', name: 'Bicycle' },
	{ emoji: '✈️', name: 'Aeroplane' },
	{ emoji: '🚀', name: 'Rocket' },
	{ emoji: '🏆', name: 'Trophy' },
	{ emoji: '⚽', name: 'Ball' },
	{ emoji: '🎸', name: 'Guitar' },
	{ emoji: '🎺', name: 'Trumpet' },
	{ emoji: '🔔', name: 'Bell' },
	{ emoji: '⚓', name: 'Anchor' },
	{ emoji: '🎧', name: 'Headphones' },
	{ emoji: '📁', name: 'Folder' },
	{ emoji: '📌', name: 'Pin' },
] as const;

// ---- Derivation -----------------------------------------------------------

/**
 * Derive 6 SAS bytes from the DH shared secret via HKDF-SHA-256.
 *
 * Uses WebCrypto HKDF with:
 *   - hash: SHA-256
 *   - ikm:  dhSecret (the SAME X25519 shared secret used to wrap the ChainKey)
 *   - salt: empty (consistent with the rest of the ratchet)
 *   - info: "sframe-ratchet-sas-v1"
 *   - output: 6 bytes (48 bits)
 *
 * SECURITY: The `dhSecret` MUST be the same DH secret used in the ECIES
 * ChainKey wrap/unwrap. This is enforced by the caller (RoomRatchet) which
 * passes the `shared` variable that is used for BOTH deriveWrapKey and
 * computeSas.
 */
export async function deriveSasBytes(dhSecret: Uint8Array): Promise<Uint8Array> {
	const material = await crypto.subtle.importKey(
		'raw', asArrayBuffer(dhSecret), 'HKDF', false, ['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: new ArrayBuffer(0),
			info: asArrayBuffer(SAS_INFO),
		},
		material,
		SAS_BYTES_LENGTH * 8,
	);
	return new Uint8Array(bits);
}

// ---- Decimal SAS ----------------------------------------------------------

/**
 * Generate 3 groups of 5 decimal digits from SAS bytes (Matrix format).
 *
 * Algorithm: for each of 3 groups, take 2 bytes as big-endian uint16,
 * mod 100000, yielding a 5-digit number (0–99999, zero-padded for display).
 * Uses all 6 SAS bytes (3 groups × 2 bytes).
 *
 * @returns Array of 3 numbers, each in [0, 99999].
 */
export function generateDecimalSas(sasBytes: Uint8Array): number[] {
	if (sasBytes.length < SAS_DECIMAL_GROUP_COUNT * 2) {
		throw new Error(
			`sas: need at least ${SAS_DECIMAL_GROUP_COUNT * 2} bytes for decimal, got ${sasBytes.length}`,
		);
	}
	const decimal: number[] = [];
	for (let i = 0; i < SAS_DECIMAL_GROUP_COUNT; i++) {
		const hi = sasBytes[i * 2];
		const lo = sasBytes[i * 2 + 1];
		decimal.push(((hi << 8) | lo) % SAS_DECIMAL_MOD);
	}
	return decimal;
}

// ---- Emoji SAS ------------------------------------------------------------

/**
 * Generate 7 emoji indices from 6 SAS bytes via bit-slicing.
 *
 * 6 bytes = 48 bits. We extract 7 groups of 6 bits (42 bits used, 6 unused)
 * from the most-significant end, big-endian. Each 6-bit value (0–63) indexes
 * into the 64-emoji table.
 *
 * This is the Matrix/Olm bit-slicing algorithm: it packs 7 emoji indices
 * into 6 bytes without wasting a full byte per index.
 *
 * @returns Array of 7 {@link EmojiEntry} from the 64-emoji table.
 */
export function generateEmojiSas(sasBytes: Uint8Array): EmojiEntry[] {
	if (sasBytes.length < SAS_BYTES_LENGTH) {
		throw new Error(
			`sas: need at least ${SAS_BYTES_LENGTH} bytes for emoji, got ${sasBytes.length}`,
		);
	}
	const indices: number[] = [];
	for (let i = 0; i < SAS_EMOJI_COUNT; i++) {
		const bitOffset = i * 6; // 0, 6, 12, 18, 24, 30, 36
		const byteIdx = Math.floor(bitOffset / 8);
		const bitInByte = bitOffset % 8;
		// How many bits are available in byteIdx starting from bitInByte?
		const availBits = 8 - bitInByte;
		// Mask off the high bits we don't want from this byte.
		const lowBits = sasBytes[byteIdx] & ((1 << availBits) - 1);
		if (availBits >= 6) {
			// All 6 bits come from this byte.
			indices.push(lowBits >> (availBits - 6));
		} else {
			// Need (6 - availBits) bits from the next byte's MSB.
			const needed = 6 - availBits;
			const highBits = sasBytes[byteIdx + 1] >> (8 - needed);
			indices.push((lowBits << needed) | highBits);
		}
	}
	return indices.map((idx) => SAS_EMOJI_TABLE[idx]);
}

// ---- Top-level ------------------------------------------------------------

/**
 * Compute the full SAS (decimal + emoji) from a DH shared secret.
 *
 * This is the top-level entry point. It derives 6 bytes from `dhSecret` via
 * HKDF-SHA-256, then generates both the decimal and emoji representations.
 *
 * SECURITY: `dhSecret` MUST be the same DH secret used to wrap/unwrap the
 * ChainKey. The caller (RoomRatchet) enforces this by passing the `shared`
 * variable that feeds both `deriveWrapKey` and this function.
 */
export async function computeSas(dhSecret: Uint8Array): Promise<SasData> {
	const sasBytes = await deriveSasBytes(dhSecret);
	return {
		decimal: generateDecimalSas(sasBytes),
		emoji: generateEmojiSas(sasBytes),
	};
}
