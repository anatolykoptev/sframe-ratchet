// Tests for the MLS chat provider — MLS epoch material → SFrame AEAD (no Worker).
//
// These tests create a REAL MLS group with ts-mls (2 members: Alice + Bob),
// advance an epoch, derive ChainKeys via the MLS ratchet provider, and verify
// that createMlsChatProvider:
//   1. seal/unseal round-trips with MLS-derived keys.
//   2. Both members derive compatible keys from the same epoch.
//   3. Epoch advance (re-key) produces a new key space — old ciphertext fails.
//   4. Replay protection: same CTR rejected.
//   5. Stale-epoch guard: frame from old epoch rejected.
//   6. ChainKey is zeroized after setEpoch.
//   7. clearEpoch resets state.
//   8. uidToPeerId mapping works for non-identity peerIds.

import 'fake-indexeddb/auto';
import { describe, it, expect } from 'vitest';
import { createCommit, type ClientState, type CiphersuiteImpl } from 'ts-mls';
import {
	deriveMlsEpochMaterial,
} from '../../mls/index.ts';
import {
	createMlsChatProvider,
} from '../mls.ts';
import { StaleEpochError } from '../../errors.ts';
import {
	getCiphersuiteImpl,
	makeMember,
	createTwoMemberGroup,
} from '../../__tests__/mls-helpers.ts';

// ---- Test helpers ---------------------------------------------------------

/** Derive epoch material from a ClientState using deriveMlsEpochMaterial. */
async function deriveChainKey(
	state: ClientState,
	cs: CiphersuiteImpl,
	groupId: Uint8Array,
): Promise<{ epoch: number; peerIndexMap: Record<string, number>; chainKey: Uint8Array; epochAuthenticator: Uint8Array }> {
	// deriveMlsEpochMaterial does NOT zeroize — the caller is responsible.
	// We copy the chainKey so the test's reference survives setEpoch's zeroization.
	const material = await deriveMlsEpochMaterial(state, cs, 'AES_128_GCM_SHA256', groupId);
	return {
		epoch: material.epoch,
		peerIndexMap: material.peerIndexMap,
		chainKey: new Uint8Array(material.chainKey), // copy for test inspection
		epochAuthenticator: material.epochAuthenticator,
	};
}

// ---- Tests ----------------------------------------------------------------

describe('MlsChatProvider', () => {
	it('seal/unseal round-trips with MLS-derived keys (2 members)', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, bobState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		// Derive ChainKeys for both members.
		const aliceEpoch = await deriveChainKey(aliceState, cs, groupId);
		const bobEpoch = await deriveChainKey(bobState, cs, groupId);

		// Both should have the same ChainKey and peerIndexMap.
		expect(aliceEpoch.chainKey).toEqual(bobEpoch.chainKey);
		expect(aliceEpoch.peerIndexMap).toEqual(bobEpoch.peerIndexMap);

		// Create MLS chat providers for both.
		// The peerIndexMap keys are base64(identity) — we need a uidToPeerId
		// mapping that converts senderUid → base64(identity).
		const { bytesToBase64 } = await import('ts-mls');
		const uidToPeerId = (uid: string) => bytesToBase64(new TextEncoder().encode(uid));
		const aliceProvider = createMlsChatProvider({ uidToPeerId });
		const bobProvider = createMlsChatProvider({ uidToPeerId });

		await aliceProvider.setEpoch('room-1', aliceEpoch);
		await bobProvider.setEpoch('room-1', bobEpoch);

		// Alice encrypts, Bob decrypts.
		const plaintext = new TextEncoder().encode('hello from alice via mls chat');
		const sealed = await aliceProvider.seal(plaintext, { roomId: 'room-1', senderUid: 'alice' });
		const opened = await bobProvider.unseal(sealed, { roomId: 'room-1', senderUid: 'alice' });
		expect(new TextDecoder().decode(opened)).toBe('hello from alice via mls chat');
	});

	it('both members can send and receive (bidirectional)', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, bobState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		const aliceEpoch = await deriveChainKey(aliceState, cs, groupId);
		const bobEpoch = await deriveChainKey(bobState, cs, groupId);

		const { bytesToBase64 } = await import('ts-mls');
		const uidToPeerId = (uid: string) => bytesToBase64(new TextEncoder().encode(uid));

		const aliceProvider = createMlsChatProvider({ uidToPeerId });
		const bobProvider = createMlsChatProvider({ uidToPeerId });

		await aliceProvider.setEpoch('room-1', aliceEpoch);
		await bobProvider.setEpoch('room-1', bobEpoch);

		// Alice → Bob
		const msg1 = new TextEncoder().encode('alice to bob');
		const sealed1 = await aliceProvider.seal(msg1, { roomId: 'room-1', senderUid: 'alice' });
		const opened1 = await bobProvider.unseal(sealed1, { roomId: 'room-1', senderUid: 'alice' });
		expect(new TextDecoder().decode(opened1)).toBe('alice to bob');

		// Bob → Alice
		const msg2 = new TextEncoder().encode('bob to alice');
		const sealed2 = await bobProvider.seal(msg2, { roomId: 'room-1', senderUid: 'bob' });
		const opened2 = await aliceProvider.unseal(sealed2, { roomId: 'room-1', senderUid: 'bob' });
		expect(new TextDecoder().decode(opened2)).toBe('bob to alice');
	});

	it('epoch advance produces a new key space — old ciphertext is stale', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState: aliceEpoch1State, bobState: bobEpoch1State, groupId } =
			await createTwoMemberGroup(cs, alice, bob);

		const aliceEpoch1 = await deriveChainKey(aliceEpoch1State, cs, groupId);
		const bobEpoch1 = await deriveChainKey(bobEpoch1State, cs, groupId);

		const { bytesToBase64 } = await import('ts-mls');
		const uidToPeerId = (uid: string) => bytesToBase64(new TextEncoder().encode(uid));

		const aliceProvider = createMlsChatProvider({ uidToPeerId });
		const bobProvider = createMlsChatProvider({ uidToPeerId });

		await aliceProvider.setEpoch('room-1', aliceEpoch1);
		await bobProvider.setEpoch('room-1', bobEpoch1);

		// Seal under epoch 1.
		const plaintext = new TextEncoder().encode('epoch 1 message');
		const sealedEpoch1 = await aliceProvider.seal(plaintext, { roomId: 'room-1', senderUid: 'alice' });

		// Advance to epoch 2 by adding Carol to the SAME group.
		const carol = await makeMember('carol', cs);
		const commit2 = await createCommit(
			{ state: aliceEpoch1State, cipherSuite: cs },
			{
				extraProposals: [{ proposalType: 'add', add: { keyPackage: carol.publicPackage } }],
				ratchetTreeExtension: true,
				wireAsPublicMessage: true,
			},
		);
		const aliceState2 = commit2.newState;
		expect(Number(aliceState2.groupContext.epoch)).toBe(2);

		const aliceEpoch2 = await deriveChainKey(aliceState2, cs, groupId);
		await aliceProvider.setEpoch('room-1', aliceEpoch2);

		// Now decrypting the epoch-1 ciphertext should fail with StaleEpochError
		// (current epoch is 2, frame's KID encodes epoch 1).
		await expect(
			aliceProvider.unseal(sealedEpoch1, { roomId: 'room-1', senderUid: 'alice' }),
		).rejects.toThrow(StaleEpochError);
	});

	it('replay protection: same CTR rejected', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, bobState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		const aliceEpoch = await deriveChainKey(aliceState, cs, groupId);
		const bobEpoch = await deriveChainKey(bobState, cs, groupId);

		const { bytesToBase64 } = await import('ts-mls');
		const uidToPeerId = (uid: string) => bytesToBase64(new TextEncoder().encode(uid));

		const aliceProvider = createMlsChatProvider({ uidToPeerId });
		const bobProvider = createMlsChatProvider({ uidToPeerId });

		await aliceProvider.setEpoch('room-1', aliceEpoch);
		await bobProvider.setEpoch('room-1', bobEpoch);

		const plaintext = new TextEncoder().encode('replay me');
		const sealed = await aliceProvider.seal(plaintext, { roomId: 'room-1', senderUid: 'alice' });

		// First unseal succeeds.
		const opened = await bobProvider.unseal(sealed, { roomId: 'room-1', senderUid: 'alice' });
		expect(new TextDecoder().decode(opened)).toBe('replay me');

		// Second unseal of the same bytes → replay error.
		await expect(
			bobProvider.unseal(sealed, { roomId: 'room-1', senderUid: 'alice' }),
		).rejects.toThrow('replay detected');
	});

	it('ChainKey is zeroized after setEpoch', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		const aliceEpoch = await deriveChainKey(aliceState, cs, groupId);
		// deriveChainKey copies the chainKey before zeroization by createMlsRatchetProvider.
		// Now setEpoch should zeroize ITS copy.
		const chainKeyCopy = new Uint8Array(aliceEpoch.chainKey);
		const provider = createMlsChatProvider();
		await provider.setEpoch('room-1', aliceEpoch);

		// The chainKey passed to setEpoch should now be zeroized.
		expect(aliceEpoch.chainKey).toEqual(new Uint8Array(aliceEpoch.chainKey.length));
		// The copy we made before setEpoch is still intact.
		expect(chainKeyCopy.some((b) => b !== 0)).toBe(true);
	});

	it('clearEpoch resets state — subsequent seal throws', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		const aliceEpoch = await deriveChainKey(aliceState, cs, groupId);
		const provider = createMlsChatProvider();
		await provider.setEpoch('room-1', aliceEpoch);

		expect(provider.getEpoch('room-1')).toBe(aliceEpoch.epoch);

		provider.clearEpoch('room-1');
		expect(provider.getEpoch('room-1')).toBeNull();

		await expect(
			provider.seal(new TextEncoder().encode('x'), { roomId: 'room-1', senderUid: 'alice' }),
		).rejects.toThrow('no epoch installed');
	});

	it('seal throws when sender is not in the epoch peerIndexMap', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		const aliceEpoch = await deriveChainKey(aliceState, cs, groupId);
		const { bytesToBase64 } = await import('ts-mls');
		const uidToPeerId = (uid: string) => bytesToBase64(new TextEncoder().encode(uid));

		const provider = createMlsChatProvider({ uidToPeerId });
		await provider.setEpoch('room-1', aliceEpoch);

		// carol is not a member of this epoch.
		await expect(
			provider.seal(new TextEncoder().encode('x'), { roomId: 'room-1', senderUid: 'carol' }),
		).rejects.toThrow('not a member');
	});

	it('unseal on a room with no epoch installed throws', async () => {
		const provider = createMlsChatProvider();
		await expect(
			provider.unseal(new Uint8Array([0, 1, 2]), { roomId: 'room-1', senderUid: 'alice' }),
		).rejects.toThrow('no epoch installed');
	});

	it('getEpoch returns null for unknown room', () => {
		const provider = createMlsChatProvider();
		expect(provider.getEpoch('unknown')).toBeNull();
	});

	it('default uidToPeerId uses senderUid directly', async () => {
		const cs = await getCiphersuiteImpl();
		const alice = await makeMember('alice', cs);
		const bob = await makeMember('bob', cs);
		const { aliceState, bobState, groupId } = await createTwoMemberGroup(cs, alice, bob);

		// Override the peerIndexMap to use plain identity strings as peerIds
		// (instead of base64) so the default uidToPeerId works.
		const aliceEpochRaw = await deriveChainKey(aliceState, cs, groupId);
		const bobEpochRaw = await deriveChainKey(bobState, cs, groupId);

		// Remap peerIndexMap: base64(identity) → identity string
		const { base64ToBytes } = await import('ts-mls/util/byteArray.js');
		const remap = (epoch: typeof aliceEpochRaw) => ({
			...epoch,
			peerIndexMap: Object.fromEntries(
				Object.entries(epoch.peerIndexMap).map(([k, v]) => [
					new TextDecoder().decode(base64ToBytes(k)),
					v,
				]),
			),
		});
		const aliceEpoch = remap(aliceEpochRaw);
		const bobEpoch = remap(bobEpochRaw);

		const aliceProvider = createMlsChatProvider(); // default uidToPeerId = identity
		const bobProvider = createMlsChatProvider();

		await aliceProvider.setEpoch('room-1', aliceEpoch);
		await bobProvider.setEpoch('room-1', bobEpoch);

		const plaintext = new TextEncoder().encode('default mapping works');
		const sealed = await aliceProvider.seal(plaintext, { roomId: 'room-1', senderUid: 'alice' });
		const opened = await bobProvider.unseal(sealed, { roomId: 'room-1', senderUid: 'alice' });
		expect(new TextDecoder().decode(opened)).toBe('default mapping works');
	});

	it('durable replay namespace option is accepted', () => {
		// Just verify construction doesn't throw with durable replay options.
		const provider = createMlsChatProvider({
			durableReplay: true,
			durableReplayNamespace: 'test-tenant',
		});
		expect(provider).toBeDefined();
	});

	it('durableReplay true without namespace throws', () => {
		expect(() => createMlsChatProvider({ durableReplay: true })).toThrow(
			'durableReplayNamespace is required',
		);
	});

	it('monotonic-idb without ctrKeyspace throws', () => {
		expect(() => createMlsChatProvider({ ctrStrategy: 'monotonic-idb' })).toThrow(
			'ctrKeyspace is required',
		);
	});
});
