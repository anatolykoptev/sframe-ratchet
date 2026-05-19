// Tests for HKDF chat-mode derivation — determinism, domain separation.
// TDD GREEN phase.

import { describe, it, expect } from 'vitest';
import { deriveAesKeyAndSalt, KeyDerivationCache } from '../derive.ts';

async function makeKey(): Promise<CryptoKey> {
	const raw = crypto.getRandomValues(new Uint8Array(32));
	return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits']);
}

describe('deriveAesKeyAndSalt', () => {
	it('same (userKey, roomId, senderUid) produces same AES salt bytes', async () => {
		const key = await makeKey();
		// Use fresh caches to bypass LRU (test determinism of derivation, not cache)
		const { salt: salt1 } = await deriveAesKeyAndSalt(key, 'room-1', 'alice', new KeyDerivationCache());
		const { salt: salt2 } = await deriveAesKeyAndSalt(key, 'room-1', 'alice', new KeyDerivationCache());
		expect(salt1).toEqual(salt2);
		expect(salt1.length).toBe(12);
	});

	it('different roomId produces different salt', async () => {
		const key = await makeKey();
		const cache = new KeyDerivationCache();
		const { salt: salt1 } = await deriveAesKeyAndSalt(key, 'room-A', 'alice', cache);
		const { salt: salt2 } = await deriveAesKeyAndSalt(key, 'room-B', 'alice', new KeyDerivationCache());
		expect(salt1).not.toEqual(salt2);
	});

	it('different senderUid produces different salt', async () => {
		const key = await makeKey();
		const cache1 = new KeyDerivationCache();
		const cache2 = new KeyDerivationCache();
		const { salt: salt1 } = await deriveAesKeyAndSalt(key, 'room-C', 'alice', cache1);
		const { salt: salt2 } = await deriveAesKeyAndSalt(key, 'room-C', 'bob', cache2);
		expect(salt1).not.toEqual(salt2);
	});

	it('aesCryptoKey is usable for encryption', async () => {
		const key = await makeKey();
		const { aesCryptoKey } = await deriveAesKeyAndSalt(key, 'room-D', 'alice', new KeyDerivationCache());
		expect(aesCryptoKey.type).toBe('secret');
		expect(aesCryptoKey.usages).toContain('encrypt');
		expect(aesCryptoKey.usages).toContain('decrypt');
		expect(aesCryptoKey.extractable).toBe(false);
	});

	it('data encrypted with derived key can be decrypted with same derived key', async () => {
		const key = await makeKey();
		const { aesCryptoKey, salt } = await deriveAesKeyAndSalt(key, 'room-E', 'alice', new KeyDerivationCache());
		const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
		const iv = new Uint8Array(12);
		const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesCryptoKey, plaintext);
		const { aesCryptoKey: key2 } = await deriveAesKeyAndSalt(key, 'room-E', 'alice', new KeyDerivationCache());
		const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext);
		expect(new Uint8Array(decrypted)).toEqual(plaintext);
		// salt is deterministic
		expect(salt.length).toBe(12);
	});

	it('cache hit returns same object reference', async () => {
		const key = await makeKey();
		const cache = new KeyDerivationCache();
		const result1 = await deriveAesKeyAndSalt(key, 'room-F', 'alice', cache);
		const result2 = await deriveAesKeyAndSalt(key, 'room-F', 'alice', cache);
		expect(result1).toBe(result2); // same reference (cache hit)
	});

	it('evictRoom clears entries for that room only', async () => {
		const key = await makeKey();
		const cache = new KeyDerivationCache();
		const r1 = await deriveAesKeyAndSalt(key, 'room-G', 'alice', cache);
		const r2 = await deriveAesKeyAndSalt(key, 'room-H', 'alice', cache);
		cache.evictRoom('room-G');
		// room-G miss (evicted)
		const r1after = await deriveAesKeyAndSalt(key, 'room-G', 'alice', cache);
		expect(r1after).not.toBe(r1); // new derivation
		// room-H still cached
		const r2after = await deriveAesKeyAndSalt(key, 'room-H', 'alice', cache);
		expect(r2after).toBe(r2); // same reference
	});
});
