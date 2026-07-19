// MLS adapter — bridges ts-mls (RFC 9420) group key schedule → SFrame AEAD.
//
// Provides a factory `createMlsRatchetProvider` that extracts epoch material
// (ChainKey + peerIndexMap) from a ts-mls ClientState and delivers it directly
// into FrameCryptor.setEpoch — the same seam RoomRatchet (ECIES) uses.
//
// No new provider interface: FrameCryptor.setEpoch IS the key-exchange/AEAD
// boundary. ECIES and MLS are peer callers of the same entry point.
//
// ChainKey derivation:
//   mlsExporter(exporterSecret, 'sframe-ratchet/epoch', groupId||suiteByte, chainKeyBytes)
//
// RFC 9420 §8.5 deriveSecret prepends 'MLS 1.0 ' to the label, yielding full
// domain separation. The context binds group_id + suite to prevent
// cross-group / cross-suite key reuse.
//
// SECURITY CONTRACT:
//   - ChainKey derives from the MLS exporter_secret for the current epoch.
//   - Raw ChainKey bytes are zeroized via zeroOutUint8Array after setEpoch
//     posts derived CryptoKeys to the worker.
//   - MLS credential verification is the CALLER's responsibility (via ts-mls
//     AuthenticationService). The provider surfaces epochAuthenticator for
//     optional out-of-band verification. There is NO SAS for the MLS path.
//   - MLS group state zeroization on dispose/leave is the caller's responsibility.

import {
	mlsExporter,
	zeroOutUint8Array,
	bytesToBase64,
	getCiphersuiteFromName,
	nobleCryptoProvider,
	type ClientState,
	type CiphersuiteImpl,
	type LeafNode,
	type Credential,
} from 'ts-mls';
import { getGroupMembers } from 'ts-mls/clientState.js';
import { buildPeerIndexMap, validatePeerIndexMap } from '../ratchet-ids.ts';
import { suiteParams, type CipherSuite } from '../ratchet-crypto.ts';
import type { PeerIndex } from '../types.ts';
import type { FrameCryptor } from '../frame-cryptor.ts';

// ---- Constants ------------------------------------------------------------

/**
 * HKDF info label for MLS exporter → SFrame ChainKey derivation.
 * RFC 9420 §8.5 `deriveSecret` prepends `'MLS 1.0 '` to this label,
 * yielding the full domain-separated string `'MLS 1.0 sframe-ratchet/epoch'`.
 */
const MLS_EXPORTER_LABEL = 'sframe-ratchet/epoch';

/**
 * Suite byte used in the exporter context (RFC 9605 §4.5 suite IDs).
 * Appended after groupId to bind the cipher suite into the derivation.
 */
function suiteByte(suite: CipherSuite): number {
	return suite === 'AES_128_GCM_SHA256' ? 4 : 5;
}

// ---- Types ----------------------------------------------------------------

/** Options for {@link createMlsRatchetProvider}. */
export interface MlsRatchetProviderOptions {
	/** The FrameCryptor to deliver epoch material to (via setEpoch). */
	frameCryptor: FrameCryptor;
	/** SFrame cipher suite — determines chainKeyBytes (32 or 64). */
	suite: CipherSuite;
	/** MLS group ID — bound into the exporter context for key separation. */
	groupId: Uint8Array;
	/**
	 * Maximum SFrame epoch number (inclusive). Defaults to 0xFFFF (16-bit,
	 * fixed KID format). For MLS KID format, set to `2^nEpochBits - 1`.
	 * The provider throws RangeError if the MLS epoch exceeds this.
	 */
	maxEpoch?: number;
	/**
	 * Maps an MLS LeafNode credential to a peerId string. The default uses
	 * base64(credential.identity) for basic credentials, base64(signaturePublicKey)
	 * for X509. Override for custom credential → peerId mapping.
	 */
	credentialToPeerId?: (leaf: LeafNode) => string;
	/** Called after each epoch is applied to FrameCryptor. */
	onEpochApplied?: (epoch: number, peerIndexMap: Record<string, PeerIndex>) => void;
	/** Called with the MLS epoch authenticator (32 bytes) for out-of-band verification. */
	onEpochAuthenticator?: (authenticator: Uint8Array) => void;
}

/** The MLS ratchet provider — bridges ts-mls ClientState → FrameCryptor.setEpoch. */
export interface MlsRatchetProvider {
	/**
	 * Extract epoch material from a ts-mls ClientState and deliver it to
	 * FrameCryptor. Call this after createGroup, joinGroup, or processMessage
	 * (on epoch advance).
	 *
	 * @param state  The current ts-mls ClientState (after epoch advance).
	 * @param cs     The CiphersuiteImpl matching the MLS group's cipher suite.
	 */
	applyEpoch(state: ClientState, cs: CiphersuiteImpl): Promise<void>;
	/** Get the current epoch authenticator (for out-of-band verification). */
	getEpochAuthenticator(state: ClientState): Uint8Array;
	/** Mark the provider as disposed; subsequent applyEpoch calls throw. */
	dispose(): void;
}

// ---- Default credential → peerId mapping ----------------------------------

/**
 * Default credential → peerId mapping.
 * Basic credential → base64(identity).
 * X509 credential → base64(signaturePublicKey) (certificate subject is not used).
 */
export function defaultCredentialToPeerId(leaf: LeafNode): string {
	const cred = leaf.credential as Credential;
	if (cred.credentialType === 'basic') {
		return bytesToBase64(cred.identity);
	}
	// X509 or custom: use signature public key as a stable, unique peerId.
	return bytesToBase64(leaf.signaturePublicKey);
}

// ---- Factory --------------------------------------------------------------

/**
 * Create an MLS ratchet provider that bridges ts-mls group state → SFrame AEAD.
 *
 * The provider is stateless regarding MLS group state — the caller manages the
 * ts-mls group lifecycle (createGroup, joinGroup, processMessage) and calls
 * `applyEpoch` after each epoch advance.
 *
 * @example
 * ```ts
 * const cs = await nobleCryptoProvider.getCiphersuiteImpl(
 *   getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
 * );
 * const state = await createGroup(groupId, keyPackage, privateKeyPackage, [], cs);
 * const provider = createMlsRatchetProvider({
 *   frameCryptor, suite: 'AES_128_GCM_SHA256', groupId,
 * });
 * await provider.applyEpoch(state, cs);
 * ```
 */
export function createMlsRatchetProvider(opts: MlsRatchetProviderOptions): MlsRatchetProvider {
	const {
		frameCryptor,
		suite,
		groupId,
		maxEpoch = 0xFFFF,
		credentialToPeerId = defaultCredentialToPeerId,
		onEpochApplied,
		onEpochAuthenticator,
	} = opts;

	const { chainKeyBytes } = suiteParams(suite);
	let disposed = false;

	return {
		async applyEpoch(state: ClientState, cs: CiphersuiteImpl): Promise<void> {
			if (disposed) throw new Error('MlsRatchetProvider: disposed');

			// 1. Guard epoch overflow (KID bit width).
			const epoch = Number(state.groupContext.epoch);
			if (epoch > maxEpoch) {
				throw new RangeError(
					`MlsRatchetProvider: MLS epoch ${epoch} exceeds maxEpoch ${maxEpoch} ` +
					`(KID format bit width). Use a larger nEpochBits or rotate the room.`,
				);
			}

			// 2. Extract member peerIds from MLS group.
			const members = getGroupMembers(state);
			if (members.length === 0) {
				throw new Error('MlsRatchetProvider: MLS group has no members');
			}
			const peerIds = members.map(credentialToPeerId);

			// 3. Build gap-free peerIndexMap (lex-sorted, §7.8-valid).
			//    Reuses buildPeerIndexMap from ratchet-ids.ts — same function
			//    the ECIES path uses. No leaf-index compaction needed.
			const peerIndexMap = buildPeerIndexMap(peerIds);
			validatePeerIndexMap(peerIndexMap);

			// 4. Derive ChainKey via MLS exporter (RFC 9420 §8.5).
			//    Context = groupId || suiteByte for cross-group/cross-suite separation.
			//    The label is domain-separated by deriveSecret ('MLS 1.0 ' prefix).
			const context = new Uint8Array(groupId.length + 1);
			context.set(groupId, 0);
			context[groupId.length] = suiteByte(suite);

			const chainKey = await mlsExporter(
				state.keySchedule.exporterSecret,
				MLS_EXPORTER_LABEL,
				context,
				chainKeyBytes,
				cs,
			);

			// 5. Deliver to FrameCryptor (calls deriveEpochKeyTable internally).
			//    This is the SAME seam RoomRatchet.installEpoch uses — no new interface.
			await frameCryptor.setEpoch({ epoch, peerIndexMap, chainKey });

			// 6. Surface epoch authenticator for out-of-band verification.
			if (onEpochAuthenticator) {
				onEpochAuthenticator(state.keySchedule.epochAuthenticator);
			}
			if (onEpochApplied) {
				onEpochApplied(epoch, peerIndexMap);
			}

			// 7. Zeroize the raw ChainKey (we extracted it; ts-mls still owns
			//    the exporterSecret in its KeySchedule).
			zeroOutUint8Array(chainKey);
		},

		getEpochAuthenticator(state: ClientState): Uint8Array {
			return state.keySchedule.epochAuthenticator;
		},

		dispose(): void {
			disposed = true;
		},
	};
}

// ---- Re-exports for convenience -------------------------------------------

export {
	getCiphersuiteFromName,
	nobleCryptoProvider,
	type CiphersuiteImpl,
	type ClientState,
};
