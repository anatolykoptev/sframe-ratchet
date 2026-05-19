// Tests for createChatProvider — round-trip, replay, rotation, cross-uid/room isolation.
// TDD RED phase: all fail until src/chat/index.ts is implemented.

import { describe, it, expect } from 'vitest';
import { createChatProvider, ReplayError } from '../index.ts';

// Helper: create a fresh HKDF base-key for tests.
async function makeKey(): Promise<CryptoKey> {
	const raw = crypto.getRandomValues(new Uint8Array(32));
	return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits']);
}

const enc = new TextEncoder();

describe('createChatProvider', () => {
	it('seal → unseal round-trip (same uid, same room)', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key });
		const plaintext = enc.encode('hello world');
		const ctx = { roomId: 'room-1', senderUid: 'alice' };
		const sealed = await provider.seal(plaintext, ctx);
		const recovered = await provider.unseal(sealed, ctx);
		expect(recovered).toEqual(plaintext);
	});

	it('unseal fails with AEAD error when cross-uid decrypts', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key });
		const plaintext = enc.encode('secret message');
		const sealCtx = { roomId: 'room-1', senderUid: 'alice' };
		const unsealCtx = { roomId: 'room-1', senderUid: 'bob' }; // different uid
		const sealed = await provider.seal(plaintext, sealCtx);
		await expect(provider.unseal(sealed, unsealCtx)).rejects.toThrow();
	});

	it('unseal fails with AEAD error when cross-room decrypts', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key });
		const plaintext = enc.encode('room message');
		const sealCtx = { roomId: 'room-1', senderUid: 'alice' };
		const unsealCtx = { roomId: 'room-2', senderUid: 'alice' };
		const sealed = await provider.seal(plaintext, sealCtx);
		await expect(provider.unseal(sealed, unsealCtx)).rejects.toThrow();
	});

	it('replay: same sealed message rejected on second unseal (random-64 strategy)', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key, replayWindow: 1024 });
		const plaintext = enc.encode('replay test');
		const ctx = { roomId: 'room-1', senderUid: 'alice' };
		const sealed = await provider.seal(plaintext, ctx);
		// First unseal succeeds
		await provider.unseal(sealed, ctx);
		// Second unseal should throw ReplayError
		await expect(provider.unseal(sealed, ctx)).rejects.toBeInstanceOf(ReplayError);
	});

	it('replayWindow=0 disables replay protection', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key, replayWindow: 0 });
		const plaintext = enc.encode('no replay check');
		const ctx = { roomId: 'room-1', senderUid: 'alice' };
		const sealed = await provider.seal(plaintext, ctx);
		await provider.unseal(sealed, ctx);
		// Should NOT throw
		const recovered = await provider.unseal(sealed, ctx);
		expect(recovered).toEqual(plaintext);
	});

	it('rotate(roomId) clears replay state — same sealed message accepted again', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key, replayWindow: 1024 });
		const plaintext = enc.encode('rotate test');
		const ctx = { roomId: 'room-1', senderUid: 'alice' };
		const sealed = await provider.seal(plaintext, ctx);
		await provider.unseal(sealed, ctx);
		// Replay rejected
		await expect(provider.unseal(sealed, ctx)).rejects.toBeInstanceOf(ReplayError);
		// After rotate, replay state cleared
		provider.rotate('room-1');
		// Should succeed again (derive cache evicted too)
		const recovered = await provider.unseal(sealed, ctx);
		expect(recovered).toEqual(plaintext);
	});

	it('rotate(roomId) fires onKeyRotated callback', async () => {
		const key = await makeKey();
		const rotated: string[] = [];
		const provider = createChatProvider({
			getKey: async () => key,
			onKeyRotated: (r) => rotated.push(r),
		});
		provider.rotate('room-42');
		expect(rotated).toContain('room-42');
	});

	it('rotate(roomId) does not affect other rooms', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key, replayWindow: 1024 });
		const plaintext = enc.encode('multi-room');
		const ctx1 = { roomId: 'room-1', senderUid: 'alice' };
		const ctx2 = { roomId: 'room-2', senderUid: 'alice' };
		const sealed1 = await provider.seal(plaintext, ctx1);
		const sealed2 = await provider.seal(plaintext, ctx2);
		await provider.unseal(sealed1, ctx1);
		await provider.unseal(sealed2, ctx2);
		// Rotate only room-1
		provider.rotate('room-1');
		// room-2 replay still active
		await expect(provider.unseal(sealed2, ctx2)).rejects.toBeInstanceOf(ReplayError);
	});

	it('getKey validates usages — throws if missing deriveKey', async () => {
		const badKey = await crypto.subtle.generateKey(
			{ name: 'AES-GCM', length: 128 },
			false,
			['encrypt', 'decrypt'],
		);
		const provider = createChatProvider({ getKey: async () => badKey });
		const ctx = { roomId: 'room-1', senderUid: 'alice' };
		await expect(provider.seal(enc.encode('test'), ctx)).rejects.toThrow(
			'chat-provider: getKey must return HKDF base-key with usages [deriveKey,deriveBits]',
		);
	});

	it('multiple senders in same room have isolated key derivation', async () => {
		const key = await makeKey();
		const provider = createChatProvider({ getKey: async () => key });
		const ctxAlice = { roomId: 'room-1', senderUid: 'alice' };
		const ctxBob = { roomId: 'room-1', senderUid: 'bob' };
		const sealedByAlice = await provider.seal(enc.encode('from alice'), ctxAlice);
		// Bob cannot unseal Alice's message (different HKDF key)
		await expect(provider.unseal(sealedByAlice, ctxBob)).rejects.toThrow();
	});

	it('dispose() is a no-op and does not throw', () => {
		const provider = createChatProvider({ getKey: async () => undefined as unknown as CryptoKey });
		expect(() => provider.dispose()).not.toThrow();
	});
});
