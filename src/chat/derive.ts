// HKDF chat-mode key derivation with per-provider LRU cache.
//
// Derives per-(roomId, senderUid) AES-128-GCM key + 12-byte salt from a
// caller-supplied HKDF base-key. Uses WebCrypto throughout; all derived
// AES-GCM keys are non-extractable.
//
// Cache: Map-of-Map keyed (roomId → senderUid → DerivedKeys), max 256 total
// entries across the provider. LRU eviction via insertion-order tracking.
//
// State is instance-scoped via KeyDerivationCache — no module-level singletons.
//
// See design doc §B.1.

import { toArrayBuffer, concat2, textEncoder } from '../internal/buffer.ts';

const enc = textEncoder;

export interface DerivedKeys {
	/** Non-extractable AES-128-GCM CryptoKey for encrypt+decrypt. */
	aesCryptoKey: CryptoKey;
	/** 12-byte IV salt; XOR'd with CTR to produce per-frame IV (per RFC 9605). */
	salt: Uint8Array;
}

// ---------------------------------------------------------------------------
// Per-provider LRU cache
// ---------------------------------------------------------------------------

const CACHE_MAX = 256;

/**
 * LRU cache for derived keys, scoped to a single provider instance.
 * Keyed as nested Map<roomId, Map<senderUid, DerivedKeys>> for correct
 * room-level eviction (no separator collision issues).
 */
export class KeyDerivationCache {
	/** Insertion-order map for LRU tracking. Key = cacheKey string. */
	private readonly lruOrder = new Map<string, string>();
	/** Nested map: roomId → senderUid → DerivedKeys. */
	private readonly cache = new Map<string, Map<string, DerivedKeys>>();

	private cacheKey(roomId: string, senderUid: string): string {
		// Composite key for lruOrder tracking only; actual storage uses 2-level map.
		return `${roomId}\x00${senderUid}`;
	}

	get(roomId: string, senderUid: string): DerivedKeys | undefined {
		return this.cache.get(roomId)?.get(senderUid);
	}

	set(roomId: string, senderUid: string, value: DerivedKeys): void {
		const k = this.cacheKey(roomId, senderUid);
		// Evict oldest if at capacity (only when inserting a new entry)
		if (!this.lruOrder.has(k) && this.lruOrder.size >= CACHE_MAX) {
			const oldestKey = this.lruOrder.keys().next().value;
			if (oldestKey !== undefined) {
				this.lruOrder.delete(oldestKey);
				const nullIdx = oldestKey.indexOf('\x00');
				const oldRoom = oldestKey.slice(0, nullIdx);
				const oldUid = oldestKey.slice(nullIdx + 1);
				const roomMap = this.cache.get(oldRoom);
				if (roomMap) {
					roomMap.delete(oldUid);
					if (roomMap.size === 0) this.cache.delete(oldRoom);
				}
			}
		}
		// Refresh LRU position (delete + re-insert = move to most-recent)
		this.lruOrder.delete(k);
		this.lruOrder.set(k, k);
		let roomMap = this.cache.get(roomId);
		if (!roomMap) {
			roomMap = new Map();
			this.cache.set(roomId, roomMap);
		}
		roomMap.set(senderUid, value);
	}

	/**
	 * Evict all cached entries for a given roomId.
	 * Called by provider.rotate(roomId).
	 */
	evictRoom(roomId: string): void {
		const roomMap = this.cache.get(roomId);
		if (!roomMap) return;
		for (const uid of roomMap.keys()) {
			this.lruOrder.delete(this.cacheKey(roomId, uid));
		}
		this.cache.delete(roomId);
	}
}

// ---------------------------------------------------------------------------
// HKDF derivation
// ---------------------------------------------------------------------------

/**
 * Derive AES-128-GCM key + 12-byte salt for a (userKey, roomId, senderUid) triple.
 * Result is stored in the provided cache.
 *
 * Derivation (design doc §B.1):
 *   salt_hkdf  = SHA-256(utf8(roomId))  — 32-byte stable HKDF salt
 *   info_key   = utf8("sframe-chat/v1/aead|") || utf8(senderUid)
 *   info_salt  = utf8("sframe-chat/v1/salt|") || utf8(senderUid)
 *   aesCryptoKey = HKDF(hash=SHA-256, salt=salt_hkdf, info=info_key) → AES-128-GCM key
 *   salt        = deriveBits(hash=SHA-256, salt=salt_hkdf, info=info_salt, 96 bits) → 12 B
 */
export async function deriveAesKeyAndSalt(
	userKey: CryptoKey,
	roomId: string,
	senderUid: string,
	keyCache: KeyDerivationCache,
): Promise<DerivedKeys> {
	const cached = keyCache.get(roomId, senderUid);
	if (cached) return cached;

	// Compute HKDF salt = SHA-256(utf8(roomId))
	const roomIdBytes = enc.encode(roomId);
	const saltBuf = await crypto.subtle.digest('SHA-256', toArrayBuffer(roomIdBytes));
	const hkdfSalt = new Uint8Array(saltBuf);

	// Build info byte strings
	const infoKey = concat2(enc.encode('sframe-chat/v1/aead|'), enc.encode(senderUid));
	const infoSalt = concat2(enc.encode('sframe-chat/v1/salt|'), enc.encode(senderUid));

	// Derive AES-128-GCM key (non-extractable)
	const aesCryptoKey = await crypto.subtle.deriveKey(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: toArrayBuffer(hkdfSalt),
			info: toArrayBuffer(infoKey),
		},
		userKey,
		{ name: 'AES-GCM', length: 128 },
		false, // non-extractable
		['encrypt', 'decrypt'],
	);

	// Derive 12-byte salt via deriveBits (96 bits)
	const saltBits = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: toArrayBuffer(hkdfSalt),
			info: toArrayBuffer(infoSalt),
		},
		userKey,
		12 * 8,
	);
	const salt = new Uint8Array(saltBits);

	const result: DerivedKeys = { aesCryptoKey, salt };
	keyCache.set(roomId, senderUid, result);
	return result;
}

// ---------------------------------------------------------------------------
// Utility — concat2 is now imported from ../internal/buffer.ts
// ---------------------------------------------------------------------------
