// Shared MLS test helpers — imported by MLS-related test suites.
// Consolidated from per-file copies in mls-provider.test.ts and
// mls-chat-provider.test.ts to avoid duplication.

import {
	generateKeyPackage,
	type ClientState,
	type CiphersuiteImpl,
	type KeyPackage,
	type PrivateKeyPackage,
} from 'ts-mls';

export const CS_NAME = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' as const;

export async function getCiphersuiteImpl(): Promise<CiphersuiteImpl> {
	const { nobleCryptoProvider, getCiphersuiteImpl: getImpl } = await import('ts-mls');
	return getImpl(CS_NAME, nobleCryptoProvider);
}

export async function makeBasicCredential(identity: string): Promise<{ credentialType: number; identity: Uint8Array }> {
	const { defaultCredentialTypes } = await import('ts-mls');
	return { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) };
}

export async function makeMember(
	identity: string,
	cs: CiphersuiteImpl,
): Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }> {
	const { defaultCapabilities, defaultLifetime, defaultCredentialTypes } = await import('ts-mls');
	return generateKeyPackage({
		credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
		capabilities: defaultCapabilities(),
		lifetime: defaultLifetime(),
		cipherSuite: cs,
	});
}

/** Create a 2-member MLS group: Alice creates, adds Bob via commit. */
export async function createTwoMemberGroup(
	cs: CiphersuiteImpl,
	alice: { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage },
	bob: { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage },
): Promise<{ aliceState: ClientState; bobState: ClientState; groupId: Uint8Array }> {
	const { createGroup, joinGroup, createCommit, defaultProposalTypes, unsafeTestingAuthenticationService } = await import('ts-mls');
	const ctx = { cipherSuite: cs, authService: unsafeTestingAuthenticationService };
	const groupId = new TextEncoder().encode('test-group');
	let aliceState = await createGroup({ context: ctx, groupId, keyPackage: alice.publicPackage, privateKeyPackage: alice.privatePackage });
	const commitResult = await createCommit({
		context: ctx,
		state: aliceState,
		extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
		ratchetTreeExtension: true,
		wireAsPublicMessage: true,
	});
	aliceState = commitResult.newState;
	if (!commitResult.welcome) throw new Error('createCommit did not produce a welcome');
	const bobState = await joinGroup({
		context: ctx,
		welcome: commitResult.welcome.welcome,
		keyPackage: bob.publicPackage,
		privateKeys: bob.privatePackage,
	});
	return { aliceState, bobState, groupId };
}
