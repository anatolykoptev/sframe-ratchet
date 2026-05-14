// Public API barrel for sframe-ratchet.
// Conservative export: types, top-level classes, and functions exercised
// by the bundled test suite. Internals (worker-state, worker-frame, buffer)
// are NOT re-exported — they are implementation details.

// ---- Types ----------------------------------------------------------------
export type {
	EpochAnnouncement,
	EpochKey,
	IdentityKeyPair,
	MemberChange,
	PeerIdentity,
	PeerIndex,
	SFrameDecryptEvent,
	SFrameKey,
	SFrameKeyLookup,
	SFrameKeyResolver,
	SFrameSupport,
} from './types.js';

// ---- Typed error hierarchy ------------------------------------------------
export {
	SFrameError,
	KeyNotFoundError,
	StaleEpochError,
	AEADAuthError,
	RatchetWindowExhaustedError,
	HeaderParseError,
	QueueFullError,
} from './errors.js';

// ---- SFrame AEAD ----------------------------------------------------------
export { sframeEncrypt, sframeDecrypt } from './sframe.js';
export { parseHeader, serializeHeader } from './sframe-header.js';
export type { SFrameHeader } from './sframe-header.js';

// ---- Ratchet (epoch / key management) ------------------------------------
export { RoomRatchet } from './ratchet.js';
export type { RoomRatchetOptions } from './ratchet.js';

// ---- Ratchet IDs / KID helpers -------------------------------------------
export {
	makeKid,
	splitKid,
	joinKid,
	newIdentity,
	validatePeerIndexMap,
	buildPeerIndexMap,
	hkdfInfo,
	peerIndexBe16,
	SFRAME_INFO_KEY,
	SFRAME_INFO_SALT,
} from './ratchet-ids.js';
export type { PeerIndexMapValidation } from './ratchet-ids.js';

// ---- Ratchet crypto primitives -------------------------------------------
export {
	deriveSenderKeys,
	deriveEpochKeyTable,
	deriveWrapKey,
	randomChainKey,
	generateX25519Keypair,
	x25519Dh,
	wrapChainKey,
	unwrapChainKey,
	X25519_KEY_BYTES,
	CHAIN_KEY_BYTES,
	SFRAME_SALT_BYTES,
} from './ratchet-crypto.js';

// ---- Frame cryptor (main-thread glue) ------------------------------------
export { FrameCryptor, supportsSFrame } from './frame-cryptor.js';
export type { FrameCryptorOptions, EpochParams } from './frame-cryptor.js';

// ---- Codec-aware partial encryption --------------------------------------
export { getUnencryptedBytes } from './codec-partial.js';
export type { Codec, FrameKind } from './worker-types.js';

// ---- SIF trailer (mixed-room support) ------------------------------------
export { DEFAULT_SIF_TRAILER, getDefaultSifTrailer } from './sif-trailer.js';
export type { SetSifTrailerMsg } from './worker-types.js';
