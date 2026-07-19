// RFC 9605 §5.2 MLS Key ID format + KID codec abstraction.
//
// The MLS Key ID layout (§5.2):
//   64-S-E bits   S bits   E bits
//  <-----------> <------> <------>
// | Context ID  | Index  | Epoch |
// +-------------+--------+-------+
//
// - E = epoch bits  (least significant bits of the MLS epoch)
// - S = index bits  (MLS member index of the sender; group size ≤ 2^S)
// - Context ID = sender-chosen context value (0 → shortest Key ID)
//
// Constraints: E ≥ 1, S ≥ 1, E < 63, S < 64 − E, E + S < 64.
//
// This module provides:
//   1. A pure bigint codec (encodeMlsKid / decodeMlsKid) per §5.2.
//   2. A KidCodec abstraction that unifies the 'fixed' (§6.1 32-bit split)
//      and 'mls' (§5.2) formats behind a single encode/decode interface,
//      so the ratchet / worker / sframe layers can be format-agnostic.
//
// SECURITY CONTRACT: all parties in a room MUST agree on kidFormat + bit
// widths (signaling concern — same as suite agreement). No auto-negotiation.
// The KID interpretation is the ONLY thing that changes — AEAD, IV derivation,
// and the ratchet state machine are untouched.

import type { PeerIndex } from './types.ts';
import { makeKid, splitKid } from './ratchet-ids.ts';

// --- Types -----------------------------------------------------------------

/** KID encoding format: 'fixed' = §6.1 32-bit split, 'mls' = §5.2 MLS layout. */
export type KidFormat = 'fixed' | 'mls';

/** Bit-width range for the MLS Key ID format (RFC 9605 §5.2). */
export interface MlsKidBitRange {
	/** Number of epoch bits (E). Must be ≥ 1 and < 63. */
	nEpochBits: number;
	/** Number of index bits (S). Must be ≥ 1 and < 64 − E. */
	nIndexBits: number;
}

/** Full configuration for the MLS Key ID format. */
export interface MlsKidConfig {
	/** Number of epoch bits (E). Must be ≥ 1 and < 63. */
	nEpochBits: number;
	/** Number of index bits (S). Must be ≥ 1 and < 64 − E. */
	nIndexBits: number;
	/** Sender-chosen context value (0 → shortest Key ID). */
	contextId: bigint;
}

// --- Validation ------------------------------------------------------------

/**
 * Validate the MLS Key ID bit-width constraints (RFC 9605 §5.2).
 *
 * Throws RangeError if any constraint is violated:
 *   - E < 1         (each field must be ≥ 1 bit)
 *   - S < 1         (each field must be ≥ 1 bit)
 *   - E ≥ 63        (epoch bits must be < 63)
 *   - S ≥ 64 − E    (index bits must leave room for context + epoch)
 *   - E + S ≥ 64    (total field bits must be < 64, leaving ≥ 1 context bit)
 */
export function validateMlsBitRange(nEpochBits: number, nIndexBits: number): void {
	if (!Number.isInteger(nEpochBits) || nEpochBits < 1) {
		throw new RangeError(`mls-kid: nEpochBits must be an integer ≥ 1, got ${nEpochBits}`);
	}
	if (!Number.isInteger(nIndexBits) || nIndexBits < 1) {
		throw new RangeError(`mls-kid: nIndexBits must be an integer ≥ 1, got ${nIndexBits}`);
	}
	if (nEpochBits >= 63) {
		throw new RangeError(`mls-kid: nEpochBits must be < 63, got ${nEpochBits}`);
	}
	if (nIndexBits >= 64 - nEpochBits) {
		throw new RangeError(
			`mls-kid: nIndexBits must be < 64 - nEpochBits (${64 - nEpochBits}), got ${nIndexBits}`,
		);
	}
	if (nEpochBits + nIndexBits >= 64) {
		throw new RangeError(
			`mls-kid: nEpochBits + nIndexBits must be < 64, got ${nEpochBits + nIndexBits}`,
		);
	}
}

// --- Pure bigint codec -----------------------------------------------------

/**
 * Encode an MLS Key ID per RFC 9605 §5.2.
 *
 * Layout: `contextId` in the high (64−S−E) bits, `index` in the next S bits,
 * `epoch` in the low E bits. Returns a bigint because the KID can exceed
 * 32 bits (up to 64 bits total).
 *
 * Throws RangeError if epoch or index overflow their bit widths, or if
 * contextId overflows the remaining context bits.
 */
export function encodeMlsKid(epoch: number, index: number, config: MlsKidConfig): bigint {
	validateMlsBitRange(config.nEpochBits, config.nIndexBits);
	const { nEpochBits: E, nIndexBits: S, contextId } = config;

	const epochMax = (1n << BigInt(E)) - 1n;
	if (!Number.isInteger(epoch) || epoch < 0 || BigInt(epoch) > epochMax) {
		throw new RangeError(`mls-kid: epoch out of range [0, 2^${E} - 1 = ${epochMax}]: ${epoch}`);
	}
	const indexMax = (1n << BigInt(S)) - 1n;
	if (!Number.isInteger(index) || index < 0 || BigInt(index) > indexMax) {
		throw new RangeError(`mls-kid: index out of range [0, 2^${S} - 1 = ${indexMax}]: ${index}`);
	}

	const contextBits = 64 - E - S;
	const contextMax = (1n << BigInt(contextBits)) - 1n;
	if (contextId < 0n || contextId > contextMax) {
		throw new RangeError(
			`mls-kid: contextId out of range [0, 2^${contextBits} - 1 = ${contextMax}]: ${contextId}`,
		);
	}

	return (
		(contextId << BigInt(E + S)) |
		(BigInt(index) << BigInt(E)) |
		BigInt(epoch)
	);
}

/**
 * Decode an MLS Key ID per RFC 9605 §5.2.
 *
 * Inverse of {@link encodeMlsKid}. Extracts epoch (low E bits), index (next S
 * bits), and contextId (high 64−S−E bits) from the 64-bit KID.
 *
 * Throws RangeError if `kid` is outside [0, 2^64 − 1].
 */
export function decodeMlsKid(
	kid: bigint,
	config: MlsKidConfig,
): { epoch: number; index: number; contextId: bigint } {
	validateMlsBitRange(config.nEpochBits, config.nIndexBits);
	const { nEpochBits: E, nIndexBits: S } = config;

	if (kid < 0n || kid > 0xffffffffffffffffn) {
		throw new RangeError(`mls-kid: kid out of range [0, 2^64 - 1]: ${kid}`);
	}

	const epochMask = (1n << BigInt(E)) - 1n;
	const indexMask = (1n << BigInt(S)) - 1n;

	const epoch = Number(kid & epochMask);
	const index = Number((kid >> BigInt(E)) & indexMask);
	const contextId = kid >> BigInt(E + S);

	return { epoch, index, contextId };
}

// --- KidCodec abstraction --------------------------------------------------

/**
 * Unified KID codec interface. Abstracts over the 'fixed' (§6.1) and 'mls'
 * (§5.2) formats so the ratchet / worker / sframe layers are format-agnostic.
 *
 * `encode` produces a `number` for the wire (serializeHeader expects a
 * number). For the 'mls' format, if the encoded KID exceeds 32 bits a
 * RangeError is thrown — the wire serialization layer (sframe-header.ts)
 * currently supports up to 32-bit KIDs. The pure bigint codec
 * ({@link encodeMlsKid}) handles the full 64-bit range.
 */
export interface KidCodec {
	/** The format this codec implements. */
	readonly format: KidFormat;
	/** Encode (epoch, peerIndex) → KID integer for the wire. */
	encode(epoch: number, peerIndex: PeerIndex): number;
	/** Decode a KID integer → (epoch, peerIndex). */
	decode(kid: number): { epoch: number; peerIndex: PeerIndex };
}

/**
 * The fixed 32-bit KID codec (RFC 9605 §6.1).
 * KID = (epoch << 16) | peerIndex. This is the default and the historical
 * format — unchanged, existing tests stay green.
 */
export const FIXED_KID_CODEC: KidCodec = {
	format: 'fixed',
	encode: (epoch, peerIndex) => makeKid(epoch, peerIndex),
	decode: (kid) => splitKid(kid),
};

/**
 * Build a {@link KidCodec} from a format + optional MLS config.
 *
 * - `'fixed'` (default): returns {@link FIXED_KID_CODEC}.
 * - `'mls'`: validates the bit range and returns a codec that uses
 *   {@link encodeMlsKid} / {@link decodeMlsKid}. The `contextId` from
 *   `mlsConfig` is baked into every encode/decode. If the encoded KID
 *   exceeds 32 bits, `encode` throws (wire layer limitation — the pure
 *   bigint codec handles the full 64-bit range).
 */
export function makeKidCodec(
	format: KidFormat = 'fixed',
	mlsConfig?: MlsKidConfig,
): KidCodec {
	if (format === 'fixed') {
		return FIXED_KID_CODEC;
	}
	if (format === 'mls') {
		if (!mlsConfig) {
			throw new Error('kid-format: mlsConfig is required when kidFormat is "mls"');
		}
		validateMlsBitRange(mlsConfig.nEpochBits, mlsConfig.nIndexBits);
		const config: MlsKidConfig = {
			nEpochBits: mlsConfig.nEpochBits,
			nIndexBits: mlsConfig.nIndexBits,
			contextId: mlsConfig.contextId,
		};
		return {
			format: 'mls',
			encode: (epoch, peerIndex) => {
				const big = encodeMlsKid(epoch, peerIndex, config);
				if (big > 0xffffffffn) {
					throw new RangeError(
						`kid-format: MLS KID ${big}n exceeds 32-bit wire width ` +
							`(serializeHeader supports up to 32 bits); use a smaller config or contextId`,
					);
				}
				return Number(big);
			},
			decode: (kid) => {
				const { epoch, index } = decodeMlsKid(BigInt(kid), config);
				return { epoch, peerIndex: index };
			},
		};
	}
	throw new Error(`kid-format: unknown kidFormat "${String(format)}"`);
}
