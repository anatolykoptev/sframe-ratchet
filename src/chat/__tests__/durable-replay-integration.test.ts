// Integration test: durable cross-reload replay through createChatProvider.
//
// Verifies the end-to-end path: createChatProvider with durableReplay enabled
// → unseal → reload (fresh provider, same key + namespace) → replayed frame
// is REJECTED with ReplayError.
//
// TDD: this test is RED against main (the replay is ACCEPTED after reload),
// GREEN once the durable receiver-side replay window is wired into the chat
// provider.

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
import { createChatProvider, ReplayError } from '../index.ts';

// navigator.locks polyfill — same as durable-replay.test.ts.
beforeAll(() => {
	if (typeof navigator === 'undefined') {
		(globalThis as Record<string, unknown>).navigator = {};
	}
	const nav = globalThis.navigator as unknown as Record<string, unknown>;
	if (!nav.locks) {
		const held = new Map<string, Promise<void>>();
		const locksApi = {
			request: async (
				name: string,
				optionsOrCallback: unknown,
				maybeCallback?: () => Promise<void>,
			): Promise<void> => {
				const callback =
					typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
				if (typeof callback !== 'function') {
					throw new Error('navigator.locks.request: callback required');
				}
				while (held.has(name)) {
					await held.get(name);
				}
				let resolve!: () => void;
				const p = new Promise<void>((r) => {
					resolve = r;
				});
				held.set(name, p);
				try {
					return await callback();
				} finally {
					held.delete(name);
					resolve();
				}
			},
		};
		Object.defineProperty(nav, 'locks', { value: locksApi, configurable: true, writable: true });
	}
});

// Each test uses a FRESH namespace to avoid cross-test interference —
// deleting IDB databases between tests hangs because the chat provider's
// DurableReplayGuard keeps its IDB connection open.
let nsCounter = 0;
function freshNs(): string {
	return `integration-ns-${nsCounter++}`;
}

const enc = new TextEncoder();
function pt(s: string): Uint8Array {
	return enc.encode(s);
}

async function makeHkdfKey(): Promise<CryptoKey> {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits']);
}

const ROOM_ID = 'room-durable-1';
const SENDER_UID = 'sender-durable-1';

describe('createChatProvider — durable cross-reload replay (CWE-294)', () => {
	it('rejects a replayed frame after a simulated reload (fresh provider, same key + namespace)', async () => {
		const key = await makeHkdfKey();
		const ns = freshNs();

		// Session 1: receiver unseals an authentic frame.
		const sender = createChatProvider({ getKey: async () => key });
		const oldFrame = await sender.seal(pt('approve payment'), { roomId: ROOM_ID, senderUid: SENDER_UID });

		const session1 = createChatProvider({
			getKey: async () => key,
			durableReplay: true,
			namespace: ns,
		});
		const firstView = await session1.unseal(oldFrame, { roomId: ROOM_ID, senderUid: SENDER_UID });
		expect(new Uint8Array(firstView)).toEqual(enc.encode('approve payment'));

		// Reload: fresh provider (empty in-memory window) — durable IDB persists.
		const session2 = createChatProvider({
			getKey: async () => key,
			durableReplay: true,
			namespace: ns,
		});

		// Server replays the SAME authentic frame. Must be REJECTED.
		await expect(
			session2.unseal(oldFrame, { roomId: ROOM_ID, senderUid: SENDER_UID }),
		).rejects.toBeInstanceOf(ReplayError);
	});

	it('accepts a genuinely-new frame after a reload', async () => {
		const key = await makeHkdfKey();
		const ns = freshNs();
		const sender = createChatProvider({ getKey: async () => key });
		const oldFrame = await sender.seal(pt('old'), { roomId: ROOM_ID, senderUid: SENDER_UID });
		const newFrame = await sender.seal(pt('new-and-legit'), { roomId: ROOM_ID, senderUid: SENDER_UID });

		const session1 = createChatProvider({
			getKey: async () => key,
			durableReplay: true,
			namespace: ns,
		});
		await session1.unseal(oldFrame, { roomId: ROOM_ID, senderUid: SENDER_UID });

		// Reload.
		const session2 = createChatProvider({
			getKey: async () => key,
			durableReplay: true,
			namespace: ns,
		});
		const out = await session2.unseal(newFrame, { roomId: ROOM_ID, senderUid: SENDER_UID });
		expect(new Uint8Array(out)).toEqual(enc.encode('new-and-legit'));
	});

	it('regression: normal in-order delivery still works with durableReplay enabled', async () => {
		const key = await makeHkdfKey();
		const sender = createChatProvider({ getKey: async () => key });
		const receiver = createChatProvider({
			getKey: async () => key,
			durableReplay: true,
			namespace: freshNs(),
		});

		for (const msg of ['one', 'two', 'three']) {
			const frame = await sender.seal(pt(msg), { roomId: ROOM_ID, senderUid: SENDER_UID });
			const out = await receiver.unseal(frame, { roomId: ROOM_ID, senderUid: SENDER_UID });
			expect(new Uint8Array(out)).toEqual(enc.encode(msg));
		}
	});

	it('regression: durableReplay disabled (default) — no IDB usage, replay only in-memory', async () => {
		const key = await makeHkdfKey();
		const sender = createChatProvider({ getKey: async () => key });
		const frame = await sender.seal(pt('test'), { roomId: ROOM_ID, senderUid: SENDER_UID });

		const session1 = createChatProvider({ getKey: async () => key });
		await session1.unseal(frame, { roomId: ROOM_ID, senderUid: SENDER_UID });

		// Reload — no durable replay, so the old frame is ACCEPTED (in-memory window wiped).
		const session2 = createChatProvider({ getKey: async () => key });
		// This is the VULNERABLE behavior (CWE-294) — documented as the default.
		const out = await session2.unseal(frame, { roomId: ROOM_ID, senderUid: SENDER_UID });
		expect(new Uint8Array(out)).toEqual(enc.encode('test'));
	});

	it('throws when durableReplay is true but namespace is missing', () => {
		expect(() =>
			createChatProvider({ getKey: async () => ({} as CryptoKey), durableReplay: true }),
		).toThrow('namespace is required');
	});

	it('throws when durableReplayWindow > replayWindow', () => {
		expect(() =>
			createChatProvider({
				getKey: async () => ({} as CryptoKey),
				durableReplay: true,
				namespace: freshNs(),
				replayWindow: 64,
				durableReplayWindow: 128,
			}),
		).toThrow('must be <= replayWindow');
	});

	it('rotate(roomId) clears durable replay state — stale CTRs do not false-reject after rotation', async () => {
		const key = await makeHkdfKey();
		const sender = createChatProvider({ getKey: async () => key });
		const frame = await sender.seal(pt('before-rotate'), { roomId: ROOM_ID, senderUid: SENDER_UID });

		const receiver = createChatProvider({
			getKey: async () => key,
			durableReplay: true,
			namespace: freshNs(),
		});
		await receiver.unseal(frame, { roomId: ROOM_ID, senderUid: SENDER_UID });

		// Rotate — clears durable state for all senders in the room.
		receiver.rotate(ROOM_ID);

		// After rotation, the durable window for this (room, sender) is
		// cleared. A fresh frame (with a new random CTR under the default
		// random-64 allocator) should be accepted — this verifies the clear()
		// path did not corrupt the guard's state or leave it in a state that
		// rejects all subsequent frames. A true "same CTR after clear" test
		// would require mocking the allocator to force a CTR collision; that
		// is covered by the unit test in durable-replay.test.ts (clear()
		// test suite) which directly calls check() after clear().
		const newFrame = await sender.seal(pt('after-rotate'), { roomId: ROOM_ID, senderUid: SENDER_UID });
		const out = await receiver.unseal(newFrame, { roomId: ROOM_ID, senderUid: SENDER_UID });
		expect(new Uint8Array(out)).toEqual(enc.encode('after-rotate'));
	});
});
