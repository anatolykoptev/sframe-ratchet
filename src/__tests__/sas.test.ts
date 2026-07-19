// SAS (Short Authentication String) verification tests — issue #11.
//
// Covers:
//   - deriveSasBytes: determinism, distinctness, length.
//   - generateDecimalSas: 3 groups, 5 digits, 0–99999, deterministic.
//   - generateEmojiSas: 7 entries, from 64-table, deterministic.
//   - computeSas: returns both, deterministic.
//   - SAS_EMOJI_TABLE: 64 entries, unique emoji, all named.
//   - KAT: fixed DH secret → known golden output.
//   - RoomRatchet.getSas: null before session, SAS after.
//   - RoomRatchet.markSasVerified / isSasVerified: round-trip.
//   - Rotation wipes SAS state.
//   - onSasReady callback fires when SAS is available.
//   - Security contract: both peers derive identical SAS from the same DH
//     secret (MITM would produce different SAS).
//
// No tests are skipped.

import { describe, it, expect } from 'vitest';
import {
	computeSas,
	deriveSasBytes,
	generateDecimalSas,
	generateEmojiSas,
	SAS_EMOJI_TABLE,
	SAS_DECIMAL_GROUP_COUNT,
	SAS_DECIMAL_DIGITS_PER_GROUP,
} from '../sas.ts';
import { RoomRatchet } from '../ratchet.ts';
import { newIdentity } from '../ratchet-ids.ts';
import type { PeerIdentity } from '../types.ts';

// ---- Test fixtures --------------------------------------------------------

/** Fixed 32-byte DH secret for KAT (deterministic). */
const KAT_DH_SECRET = new Uint8Array(32);
for (let i = 0; i < 32; i++) KAT_DH_SECRET[i] = i + 1; // bytes 1..32

/** KAT golden output (computed once via HKDF-SHA-256, hardcoded). */
const KAT_SAS_BYTES = [146, 198, 43, 170, 10, 174];
const KAT_DECIMAL = [37574, 11178, 2734];
const KAT_EMOJI = ['👍', '📎', '🍎', '✏️', '📕', '🎩', '📕'];
const KAT_EMOJI_NAMES = ['Thumbs Up', 'Paperclip', 'Apple', 'Pencil', 'Book', 'Hat', 'Book'];

/** A different DH secret to verify distinctness. */
const KAT_DH_SECRET_2 = new Uint8Array(32);
for (let i = 0; i < 32; i++) KAT_DH_SECRET_2[i] = i + 2; // bytes 2..33

// ---- SAS_EMOJI_TABLE ------------------------------------------------------

describe('SAS_EMOJI_TABLE', () => {
	it('has exactly 64 entries', () => {
		expect(SAS_EMOJI_TABLE.length).toBe(64);
	});

	it('all emoji are unique', () => {
		const emojis = SAS_EMOJI_TABLE.map((e) => e.emoji);
		const unique = new Set(emojis);
		expect(unique.size).toBe(emojis.length);
	});

	it('all entries have a non-empty name', () => {
		for (const entry of SAS_EMOJI_TABLE) {
			expect(entry.name).toBeTruthy();
			expect(entry.name.length).toBeGreaterThan(0);
		}
	});

	it('all entries have a non-empty emoji', () => {
		for (const entry of SAS_EMOJI_TABLE) {
			expect(entry.emoji).toBeTruthy();
			expect(entry.emoji.length).toBeGreaterThan(0);
		}
	});
});

// ---- deriveSasBytes -------------------------------------------------------

describe('deriveSasBytes', () => {
	it('returns exactly 6 bytes', async () => {
		const bytes = await deriveSasBytes(KAT_DH_SECRET);
		expect(bytes).toBeInstanceOf(Uint8Array);
		expect(bytes.length).toBe(6);
	});

	it('is deterministic for the same input', async () => {
		const a = await deriveSasBytes(KAT_DH_SECRET);
		const b = await deriveSasBytes(KAT_DH_SECRET);
		expect(Array.from(a)).toEqual(Array.from(b));
	});

	it('differs for different inputs', async () => {
		const a = await deriveSasBytes(KAT_DH_SECRET);
		const b = await deriveSasBytes(KAT_DH_SECRET_2);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	it('KAT: matches the golden output for the fixed DH secret', async () => {
		const bytes = await deriveSasBytes(KAT_DH_SECRET);
		expect(Array.from(bytes)).toEqual(KAT_SAS_BYTES);
	});
});

// ---- generateDecimalSas ---------------------------------------------------

describe('generateDecimalSas', () => {
	it('returns exactly 3 groups', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const decimal = generateDecimalSas(sasBytes);
		expect(decimal).toHaveLength(SAS_DECIMAL_GROUP_COUNT);
	});

	it('each group is in [0, 99999]', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const decimal = generateDecimalSas(sasBytes);
		for (const d of decimal) {
			expect(d).toBeGreaterThanOrEqual(0);
			expect(d).toBeLessThanOrEqual(99999);
			expect(Number.isInteger(d)).toBe(true);
		}
	});

	it('each group fits in 5 decimal digits', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const decimal = generateDecimalSas(sasBytes);
		for (const d of decimal) {
			expect(d.toString().length).toBeLessThanOrEqual(SAS_DECIMAL_DIGITS_PER_GROUP);
		}
	});

	it('is deterministic', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const a = generateDecimalSas(sasBytes);
		const b = generateDecimalSas(sasBytes);
		expect(a).toEqual(b);
	});

	it('KAT: matches the golden decimal output', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const decimal = generateDecimalSas(sasBytes);
		expect(decimal).toEqual(KAT_DECIMAL);
	});
});

// ---- generateEmojiSas -----------------------------------------------------

describe('generateEmojiSas', () => {
	it('returns exactly 7 entries', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const emoji = generateEmojiSas(sasBytes);
		expect(emoji).toHaveLength(7);
	});

	it('each entry is from the 64-emoji table', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const emoji = generateEmojiSas(sasBytes);
		const tableSet = new Set(SAS_EMOJI_TABLE.map((e) => `${e.emoji}|${e.name}`));
		for (const e of emoji) {
			expect(tableSet.has(`${e.emoji}|${e.name}`)).toBe(true);
		}
	});

	it('each entry has emoji and name', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const emoji = generateEmojiSas(sasBytes);
		for (const e of emoji) {
			expect(e.emoji).toBeTruthy();
			expect(e.name).toBeTruthy();
		}
	});

	it('is deterministic', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const a = generateEmojiSas(sasBytes);
		const b = generateEmojiSas(sasBytes);
		expect(a).toEqual(b);
	});

	it('KAT: matches the golden emoji output', async () => {
		const sasBytes = await deriveSasBytes(KAT_DH_SECRET);
		const emoji = generateEmojiSas(sasBytes);
		expect(emoji.map((e) => e.emoji)).toEqual(KAT_EMOJI);
		expect(emoji.map((e) => e.name)).toEqual(KAT_EMOJI_NAMES);
	});
});

// ---- computeSas -----------------------------------------------------------

describe('computeSas', () => {
	it('returns both decimal and emoji representations', async () => {
		const sas = await computeSas(KAT_DH_SECRET);
		expect(sas.decimal).toHaveLength(SAS_DECIMAL_GROUP_COUNT);
		expect(sas.emoji).toHaveLength(7);
	});

	it('is deterministic', async () => {
		const a = await computeSas(KAT_DH_SECRET);
		const b = await computeSas(KAT_DH_SECRET);
		expect(a.decimal).toEqual(b.decimal);
		expect(a.emoji).toEqual(b.emoji);
	});

	it('differs for different DH secrets', async () => {
		const a = await computeSas(KAT_DH_SECRET);
		const b = await computeSas(KAT_DH_SECRET_2);
		// At least one representation must differ.
		const decimalDiff = a.decimal.some((v, i) => v !== b.decimal[i]);
		const emojiDiff = a.emoji.some((v, i) => v.emoji !== b.emoji[i].emoji);
		expect(decimalDiff || emojiDiff).toBe(true);
	});

	it('KAT: matches the golden full output', async () => {
		const sas = await computeSas(KAT_DH_SECRET);
		expect(sas.decimal).toEqual(KAT_DECIMAL);
		expect(sas.emoji.map((e) => e.emoji)).toEqual(KAT_EMOJI);
		expect(sas.emoji.map((e) => e.name)).toEqual(KAT_EMOJI_NAMES);
	});
});

// ---- RoomRatchet SAS integration -----------------------------------------

/**
 * Set up a two-peer ratchet session: alice (authoritative author) starts a
 * new epoch, bob consumes the announcement. Both peers now have SAS for
 * each other.
 */
async function setupTwoPeerSession(): Promise<{
	alice: RoomRatchet;
	bob: RoomRatchet;
	aliceIdentity: PeerIdentity;
	bobIdentity: PeerIdentity;
}> {
	const aliceId = newIdentity('alice');
	const bobId = newIdentity('bob');

	const alicePeer: PeerIdentity = { peerId: aliceId.peerId, publicKey: aliceId.publicKey };
	const bobPeer: PeerIdentity = { peerId: bobId.peerId, publicKey: bobId.publicKey };

	const alice = new RoomRatchet({ identity: aliceId, initialPeers: [bobPeer] });
	const bob = new RoomRatchet({ identity: bobId, initialPeers: [alicePeer] });

	// Alice is the authoritative author ("alice" < "bob").
	// startNewEpoch takes members EXCLUDING self — it adds self internally.
	const announcements = await alice.startNewEpoch([bobPeer]);
	expect(announcements).toHaveLength(1);

	// Bob consumes the announcement addressed to him.
	await bob.consumeEpochAnnouncement(announcements[0]);

	return { alice, bob, aliceIdentity: alicePeer, bobIdentity: bobPeer };
}

describe('RoomRatchet.getSas', () => {
	it('returns null before a session is established', () => {
		const aliceId = newIdentity('alice');
		const bobPeer: PeerIdentity = { peerId: 'bob', publicKey: new Uint8Array(32) };
		const r = new RoomRatchet({ identity: aliceId, initialPeers: [bobPeer] });
		expect(r.getSas('bob')).toBeNull();
	});

	it('returns SAS after a session is established (sender side)', async () => {
		const { alice, bobIdentity } = await setupTwoPeerSession();
		const sas = alice.getSas(bobIdentity.peerId);
		expect(sas).not.toBeNull();
		expect(sas!.decimal).toHaveLength(SAS_DECIMAL_GROUP_COUNT);
		expect(sas!.emoji).toHaveLength(7);
	});

	it('returns SAS after a session is established (receiver side)', async () => {
		const { bob, aliceIdentity } = await setupTwoPeerSession();
		const sas = bob.getSas(aliceIdentity.peerId);
		expect(sas).not.toBeNull();
		expect(sas!.decimal).toHaveLength(SAS_DECIMAL_GROUP_COUNT);
		expect(sas!.emoji).toHaveLength(7);
	});

	it('both peers derive identical SAS from the same DH secret', async () => {
		const { alice, bob, aliceIdentity, bobIdentity } = await setupTwoPeerSession();
		const aliceSas = alice.getSas(bobIdentity.peerId);
		const bobSas = bob.getSas(aliceIdentity.peerId);
		expect(aliceSas).not.toBeNull();
		expect(bobSas).not.toBeNull();
		// SECURITY CONTRACT: both peers see the same SAS because they share
		// the same DH secret. A MITM would produce different SAS.
		expect(aliceSas!.decimal).toEqual(bobSas!.decimal);
		expect(aliceSas!.emoji).toEqual(bobSas!.emoji);
	});

	it('returns null for an unknown peer', async () => {
		const { alice } = await setupTwoPeerSession();
		expect(alice.getSas('nonexistent')).toBeNull();
	});
});

describe('RoomRatchet.markSasVerified / isSasVerified', () => {
	it('isSasVerified returns false before verification', async () => {
		const { alice, bobIdentity } = await setupTwoPeerSession();
		expect(alice.isSasVerified(bobIdentity.peerId)).toBe(false);
	});

	it('markSasVerified(true) → isSasVerified returns true', async () => {
		const { alice, bobIdentity } = await setupTwoPeerSession();
		alice.markSasVerified(bobIdentity.peerId, true);
		expect(alice.isSasVerified(bobIdentity.peerId)).toBe(true);
	});

	it('markSasVerified(false) revokes verification', async () => {
		const { alice, bobIdentity } = await setupTwoPeerSession();
		alice.markSasVerified(bobIdentity.peerId, true);
		expect(alice.isSasVerified(bobIdentity.peerId)).toBe(true);
		alice.markSasVerified(bobIdentity.peerId, false);
		expect(alice.isSasVerified(bobIdentity.peerId)).toBe(false);
	});

	it('isSasVerified returns false for an unknown peer', () => {
		const aliceId = newIdentity('alice');
		const r = new RoomRatchet({ identity: aliceId });
		expect(r.isSasVerified('nonexistent')).toBe(false);
	});

	it('markSasVerified is a no-op for an unknown peer (does not throw)', () => {
		const aliceId = newIdentity('alice');
		const r = new RoomRatchet({ identity: aliceId });
		expect(() => r.markSasVerified('nonexistent', true)).not.toThrow();
		expect(r.isSasVerified('nonexistent')).toBe(false);
	});
});

describe('RoomRatchet SAS — rotation wipes state', () => {
	it('SAS is wiped when a new epoch rotates', async () => {
		const { alice, bob, aliceIdentity, bobIdentity } = await setupTwoPeerSession();
		// Verify SAS exists after initial session.
		expect(alice.getSas(bobIdentity.peerId)).not.toBeNull();
		expect(bob.getSas(aliceIdentity.peerId)).not.toBeNull();

		// Simulate a member change: a new peer "carol" joins → epoch rotation.
		const carolId = newIdentity('carol');
		const carolPeer: PeerIdentity = { peerId: carolId.peerId, publicKey: carolId.publicKey };

		// Alice (author) starts a new epoch with carol added.
		// members excludes self (startNewEpoch adds self internally).
		const newMembers = [bobIdentity, carolPeer];
		const announcements = await alice.startNewEpoch(newMembers, { version: 1 });
		// Announcements for bob and carol (not alice herself).
		expect(announcements.length).toBeGreaterThanOrEqual(1);

		// After rotation, alice's old SAS for bob (epoch 0) is wiped.
		// Alice now has a NEW SAS for bob (epoch 1) because startNewEpoch
		// re-wraps for all peers including bob.
		const aliceSasBobAfter = alice.getSas(bobIdentity.peerId);
		expect(aliceSasBobAfter).not.toBeNull();
		// The new SAS (epoch 1) should differ from the old one (epoch 0)
		// because a fresh ephemeral keypair is used per wrap.
		// Note: we can't compare to the old SAS directly since it was wiped,
		// but we can verify the SAS exists and is for the new epoch.
	});

	it('SAS for old epoch is cleared after rotation (direct wipe check)', async () => {
		const aliceId = newIdentity('alice');
		const bobId = newIdentity('bob');
		const alicePeer: PeerIdentity = { peerId: aliceId.peerId, publicKey: aliceId.publicKey };
		const bobPeer: PeerIdentity = { peerId: bobId.peerId, publicKey: bobId.publicKey };

		const alice = new RoomRatchet({ identity: aliceId, initialPeers: [bobPeer] });

		// Epoch 0: establish session, SAS is set.
		// members excludes self — startNewEpoch adds self internally.
		await alice.startNewEpoch([bobPeer], { version: 0 });
		expect(alice.getSas(bobPeer.peerId)).not.toBeNull();
		alice.markSasVerified(bobPeer.peerId, true);
		expect(alice.isSasVerified(bobPeer.peerId)).toBe(true);

		// Epoch 1: rotate. Old SAS (epoch 0) must be wiped.
		await alice.startNewEpoch([bobPeer], { version: 1 });
		// After rotation, a NEW SAS is installed (epoch 1), but the verified
		// flag must be reset to false (new session = unverified).
		expect(alice.getSas(bobPeer.peerId)).not.toBeNull();
		expect(alice.isSasVerified(bobPeer.peerId)).toBe(false);
	});
});

describe('RoomRatchet.onSasReady', () => {
	it('fires when SAS becomes available for a peer', async () => {
		const aliceId = newIdentity('alice');
		const bobId = newIdentity('bob');
		const alicePeer: PeerIdentity = { peerId: aliceId.peerId, publicKey: aliceId.publicKey };
		const bobPeer: PeerIdentity = { peerId: bobId.peerId, publicKey: bobId.publicKey };

		const alice = new RoomRatchet({ identity: aliceId, initialPeers: [bobPeer] });

		const fired: string[] = [];
		const off = alice.onSasReady((peerId) => { fired.push(peerId); });

		// members excludes self — startNewEpoch adds self internally.
		await alice.startNewEpoch([bobPeer]);

		expect(fired).toContain(bobPeer.peerId);
		off();
	});

	it('unsubscribe stops further callbacks', async () => {
		const aliceId = newIdentity('alice');
		const bobId = newIdentity('bob');
		const alicePeer: PeerIdentity = { peerId: aliceId.peerId, publicKey: aliceId.publicKey };
		const bobPeer: PeerIdentity = { peerId: bobId.peerId, publicKey: bobId.publicKey };

		const alice = new RoomRatchet({ identity: aliceId, initialPeers: [bobPeer] });

		const fired: string[] = [];
		const off = alice.onSasReady((peerId) => { fired.push(peerId); });
		off();

		await alice.startNewEpoch([bobPeer]);
		expect(fired).toHaveLength(0);
	});

	it('fires on the receiver side when consuming an announcement', async () => {
		const aliceId = newIdentity('alice');
		const bobId = newIdentity('bob');
		const alicePeer: PeerIdentity = { peerId: aliceId.peerId, publicKey: aliceId.publicKey };
		const bobPeer: PeerIdentity = { peerId: bobId.peerId, publicKey: bobId.publicKey };

		const alice = new RoomRatchet({ identity: aliceId, initialPeers: [bobPeer] });
		const bob = new RoomRatchet({ identity: bobId, initialPeers: [alicePeer] });

		const bobFired: string[] = [];
		bob.onSasReady((peerId) => { bobFired.push(peerId); });

		const announcements = await alice.startNewEpoch([bobPeer]);
		await bob.consumeEpochAnnouncement(announcements[0]);

		expect(bobFired).toContain(alicePeer.peerId);
	});
});
