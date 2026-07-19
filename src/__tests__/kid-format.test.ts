// Tests for RFC 9605 §5.2 MLS Key ID format + KID codec abstraction.
// Covers: validation, encode/decode round-trip, overflow detection, known
// vectors, backward compat with the fixed format, and RoomRatchet integration
// with kidFormat='mls'. No tests skipped.

import { describe, it, expect } from 'vitest';
import {
	validateMlsBitRange,
	encodeMlsKid,
	decodeMlsKid,
	makeKidCodec,
	FIXED_KID_CODEC,
	type MlsKidConfig,
} from '../kid-format.ts';
import { makeKid, splitKid, joinKid, newIdentity } from '../ratchet-ids.ts';
import { deriveSenderKeys, randomChainKey } from '../ratchet-crypto.ts';
import { sframeEncrypt, sframeDecrypt } from '../sframe.ts';
import { RoomRatchet } from '../ratchet.ts';
import type { PeerIdentity } from '../types.ts';

// ---- validateMlsBitRange --------------------------------------------------

describe('validateMlsBitRange', () => {
	it('accepts valid bit ranges', () => {
		// Each of these satisfies: E ≥ 1, S ≥ 1, E < 63, S < 64 − E, E + S < 64.
		const valid: Array<[number, number]> = [
			[1, 1],
			[8, 8],
			[4, 16],
			[16, 4],
			[32, 31],
			[62, 1],
			[1, 62],
			[10, 50],
		];
		for (const [E, S] of valid) {
			expect(() => validateMlsBitRange(E, S)).not.toThrow();
		}
	});

	it('rejects E < 1', () => {
		expect(() => validateMlsBitRange(0, 8)).toThrow(RangeError);
		expect(() => validateMlsBitRange(-1, 8)).toThrow(RangeError);
	});

	it('rejects S < 1', () => {
		expect(() => validateMlsBitRange(8, 0)).toThrow(RangeError);
		expect(() => validateMlsBitRange(8, -1)).toThrow(RangeError);
	});

	it('rejects E ≥ 63', () => {
		expect(() => validateMlsBitRange(63, 1)).toThrow(RangeError);
		expect(() => validateMlsBitRange(64, 1)).toThrow(RangeError);
	});

	it('rejects S ≥ 64 − E', () => {
		// E=8 → 64−E=56; S=56 should fail, S=55 should pass.
		expect(() => validateMlsBitRange(8, 56)).toThrow(RangeError);
		expect(() => validateMlsBitRange(8, 55)).not.toThrow();
	});

	it('rejects E + S ≥ 64', () => {
		// E=32, S=32 → E+S=64 → fail.
		expect(() => validateMlsBitRange(32, 32)).toThrow(RangeError);
		// E=32, S=31 → E+S=63 → pass (boundary).
		expect(() => validateMlsBitRange(32, 31)).not.toThrow();
	});

	it('rejects non-integer bit widths', () => {
		expect(() => validateMlsBitRange(8.5, 8)).toThrow(RangeError);
		expect(() => validateMlsBitRange(8, 8.5)).toThrow(RangeError);
	});
});

// ---- encodeMlsKid / decodeMlsKid round-trip -------------------------------

describe('encodeMlsKid / decodeMlsKid round-trip', () => {
	const configs: Array<{ name: string; config: MlsKidConfig; epoch: number; index: number }> = [
		{ name: 'E=8, S=8', config: { nEpochBits: 8, nIndexBits: 8, contextId: 0n }, epoch: 42, index: 21 },
		{ name: 'E=4, S=16', config: { nEpochBits: 4, nIndexBits: 16, contextId: 0n }, epoch: 7, index: 1000 },
		{ name: 'E=1, S=1', config: { nEpochBits: 1, nIndexBits: 1, contextId: 0n }, epoch: 1, index: 1 },
		{ name: 'E=32, S=31', config: { nEpochBits: 32, nIndexBits: 31, contextId: 0n }, epoch: 0xdeadbeef, index: 0x1234567 },
		{ name: 'E=8, S=8, contextId=0x1234', config: { nEpochBits: 8, nIndexBits: 8, contextId: 0x1234n }, epoch: 42, index: 21 },
		{ name: 'E=16, S=16, contextId=1n', config: { nEpochBits: 16, nIndexBits: 16, contextId: 1n }, epoch: 0x1234, index: 0x5678 },
	];

	for (const { name, config, epoch, index } of configs) {
		it(`round-trips ${name}`, () => {
			const kid = encodeMlsKid(epoch, index, config);
			const decoded = decodeMlsKid(kid, config);
			expect(decoded.epoch).toBe(epoch);
			expect(decoded.index).toBe(index);
			expect(decoded.contextId).toBe(config.contextId);
		});
	}

	it('round-trips max values for E=8, S=8', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const kid = encodeMlsKid(0xff, 0xff, config);
		const decoded = decodeMlsKid(kid, config);
		expect(decoded.epoch).toBe(0xff);
		expect(decoded.index).toBe(0xff);
		expect(decoded.contextId).toBe(0n);
	});

	it('round-trips max values for E=32, S=31', () => {
		const config: MlsKidConfig = { nEpochBits: 32, nIndexBits: 31, contextId: 0n };
		const epochMax = (1n << 32n) - 1n; // 0xffffffff
		const indexMax = (1n << 31n) - 1n; // 0x7fffffff
		const kid = encodeMlsKid(Number(epochMax), Number(indexMax), config);
		const decoded = decodeMlsKid(kid, config);
		expect(decoded.epoch).toBe(Number(epochMax));
		expect(decoded.index).toBe(Number(indexMax));
		expect(decoded.contextId).toBe(0n);
	});
});

// ---- shortest Key ID (contextId=0, epoch=0, index=0) ---------------------

describe('shortest Key ID', () => {
	it('epoch=0, index=0, contextId=0 → KID=0n', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		expect(encodeMlsKid(0, 0, config)).toBe(0n);
	});

	it('contextId=0 → context bits are zero (shortest per §5.2)', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const kid = encodeMlsKid(42, 21, config);
		// Context bits = high (64−8−8) = 48 bits. With contextId=0, the high
		// 48 bits must be zero, so kid < 2^16.
		expect(kid).toBeLessThan(1n << 16n);
		// And the decoded contextId is 0.
		expect(decodeMlsKid(kid, config).contextId).toBe(0n);
	});

	it('contextId=0 for E=1, S=1 → KID fits in 2 bits', () => {
		const config: MlsKidConfig = { nEpochBits: 1, nIndexBits: 1, contextId: 0n };
		expect(encodeMlsKid(0, 0, config)).toBe(0n);
		expect(encodeMlsKid(1, 0, config)).toBe(1n);
		expect(encodeMlsKid(0, 1, config)).toBe(2n);
		expect(encodeMlsKid(1, 1, config)).toBe(3n);
	});
});

// ---- overflow detection ---------------------------------------------------

describe('encodeMlsKid overflow', () => {
	it('epoch exceeds 2^E − 1 → throws', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		expect(() => encodeMlsKid(256, 0, config)).toThrow(RangeError); // 2^8 = 256
		expect(() => encodeMlsKid(255, 0, config)).not.toThrow(); // 2^8 − 1 = 255 OK
	});

	it('index exceeds 2^S − 1 → throws', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		expect(() => encodeMlsKid(0, 256, config)).toThrow(RangeError); // 2^8 = 256
		expect(() => encodeMlsKid(0, 255, config)).not.toThrow(); // 2^8 − 1 = 255 OK
	});

	it('contextId exceeds context bits → throws', () => {
		// E=8, S=8 → contextBits=48. contextId=2^48 should fail.
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: (1n << 48n) };
		expect(() => encodeMlsKid(0, 0, config)).toThrow(RangeError);
	});

	it('negative epoch → throws', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		expect(() => encodeMlsKid(-1, 0, config)).toThrow(RangeError);
	});

	it('negative index → throws', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		expect(() => encodeMlsKid(0, -1, config)).toThrow(RangeError);
	});

	it('negative contextId → throws', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: -1n };
		expect(() => encodeMlsKid(0, 0, config)).toThrow(RangeError);
	});
});

// ---- known vector (hand-computed) -----------------------------------------

describe('decodeMlsKid known vector', () => {
	it('E=8, S=8, contextId=0x1234, epoch=0x2a, index=0x15', () => {
		// Hand-computed:
		//   KID = (0x1234 << 16) | (0x15 << 8) | 0x2a
		//       = 0x12340000 | 0x1500 | 0x002a
		//       = 0x1234152a
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0x1234n };
		const kid = encodeMlsKid(0x2a, 0x15, config);
		expect(kid).toBe(0x1234152an);

		const decoded = decodeMlsKid(kid, config);
		expect(decoded.epoch).toBe(0x2a);
		expect(decoded.index).toBe(0x15);
		expect(decoded.contextId).toBe(0x1234n);
	});

	it('E=4, S=16, contextId=0, epoch=0xa, index=0xbeef', () => {
		// KID = (0 << 20) | (0xbeef << 4) | 0xa
		//     = 0xbeef0 | 0xa
		//     = 0xbeefa
		const config: MlsKidConfig = { nEpochBits: 4, nIndexBits: 16, contextId: 0n };
		const kid = encodeMlsKid(0xa, 0xbeef, config);
		expect(kid).toBe(0xbeefan);
		const decoded = decodeMlsKid(kid, config);
		expect(decoded.epoch).toBe(0xa);
		expect(decoded.index).toBe(0xbeef);
		expect(decoded.contextId).toBe(0n);
	});

	it('decode rejects kid > 2^64 − 1', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		expect(() => decodeMlsKid(0x10000000000000000n, config)).toThrow(RangeError);
	});
});

// ---- KidCodec abstraction -------------------------------------------------

describe('KidCodec / makeKidCodec', () => {
	it('FIXED_KID_CODEC wraps makeKid/splitKid', () => {
		expect(FIXED_KID_CODEC.format).toBe('fixed');
		const kid = FIXED_KID_CODEC.encode(3, 7);
		expect(kid).toBe(makeKid(3, 7));
		expect(FIXED_KID_CODEC.decode(kid)).toEqual({ epoch: 3, peerIndex: 7 });
	});

	it('makeKidCodec("fixed") returns FIXED_KID_CODEC', () => {
		expect(makeKidCodec('fixed')).toBe(FIXED_KID_CODEC);
	});

	it('makeKidCodec() defaults to fixed', () => {
		expect(makeKidCodec().format).toBe('fixed');
	});

	it('makeKidCodec("mls") without mlsConfig throws', () => {
		expect(() => makeKidCodec('mls')).toThrow();
	});

	it('makeKidCodec("mls") encodes/decodes via MLS format', () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const codec = makeKidCodec('mls', config);
		expect(codec.format).toBe('mls');
		const kid = codec.encode(42, 21);
		expect(kid).toBe(Number(encodeMlsKid(42, 21, config)));
		expect(codec.decode(kid)).toEqual({ epoch: 42, peerIndex: 21 });
	});

	it('makeKidCodec("mls") with KID > 32 bits throws on encode (wire limit)', () => {
		// E=32, S=31, contextId=0 → max KID is 63 bits, exceeds 32-bit wire.
		const config: MlsKidConfig = { nEpochBits: 32, nIndexBits: 31, contextId: 0n };
		const codec = makeKidCodec('mls', config);
		// epoch=1, index=0 → KID = 1 (fits). But epoch=0x10000, index=0 → KID = 0x10000 (fits in 32 bits).
		// epoch=0x100000000 (2^32) → exceeds E=32, so encodeMlsKid throws first.
		// Let's use a config where the KID genuinely exceeds 32 bits:
		// E=20, S=20, contextId=1 → KID = (1 << 40) | ... which is > 2^32.
		const bigConfig: MlsKidConfig = { nEpochBits: 20, nIndexBits: 20, contextId: 1n };
		const bigCodec = makeKidCodec('mls', bigConfig);
		expect(() => bigCodec.encode(0, 0)).toThrow(RangeError);
	});

	it('makeKidCodec with unknown format throws', () => {
		expect(() => makeKidCodec('unknown' as never)).toThrow();
	});
});

// ---- Backward compat: fixed format unchanged ------------------------------

describe('backward compat: fixed format unchanged', () => {
	it('makeKid / splitKid / joinKid are unchanged', () => {
		// The historical 32-bit split: KID = (epoch << 16) | peerIndex.
		expect(makeKid(1, 0)).toBe(0x00010000);
		expect(makeKid(0, 1)).toBe(0x00000001);
		expect(makeKid(0xffff, 0xffff)).toBe(0xffffffff);

		expect(splitKid(0x00010000)).toEqual({ epoch: 1, peerIndex: 0 });
		expect(splitKid(0x00000001)).toEqual({ epoch: 0, peerIndex: 1 });
		expect(splitKid(0xffffffff)).toEqual({ epoch: 0xffff, peerIndex: 0xffff });

		expect(joinKid({ epoch: 1, peerIndex: 0 })).toBe(0x00010000);
		expect(joinKid({ epoch: 0, peerIndex: 1 })).toBe(0x00000001);
	});

	it('deriveSenderKeys without codec uses fixed format', async () => {
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 3, 7);
		expect(key.kid).toBe(makeKid(3, 7));
		expect(key.epoch).toBe(3);
		expect(key.peerIndex).toBe(7);
	});

	it('sframeEncrypt/sframeDecrypt without codec uses fixed format', async () => {
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 1, 0);
		const plaintext = new TextEncoder().encode('fixed format');
		const sealed = await sframeEncrypt(plaintext, key, 1n);
		const opened = await sframeDecrypt(sealed, ({ kid }) => (kid === key.kid ? key : null));
		expect(new TextDecoder().decode(opened)).toBe('fixed format');
	});
});

// ---- End-to-end MLS format encrypt/decrypt --------------------------------

describe('MLS format encrypt/decrypt round-trip', () => {
	it('deriveSenderKeys + sframeEncrypt/sframeDecrypt with MLS codec', async () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const codec = makeKidCodec('mls', config);
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 42, 21, undefined, codec);

		// KID is MLS-encoded, not the fixed (epoch << 16 | peerIndex).
		expect(key.kid).toBe(Number(encodeMlsKid(42, 21, config)));
		expect(key.kid).not.toBe(makeKid(42, 21));

		const plaintext = new TextEncoder().encode('mls format');
		const sealed = await sframeEncrypt(plaintext, key, 3n);

		// Decrypt with the MLS codec so the KID is split correctly.
		const opened = await sframeDecrypt(
			sealed,
			({ kid }) => (kid === key.kid ? key : null),
			{ kidCodec: codec },
		);
		expect(new TextDecoder().decode(opened)).toBe('mls format');
	});

	it('decrypt without codec fails to find the key (wrong split)', async () => {
		const config: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const codec = makeKidCodec('mls', config);
		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 42, 21, undefined, codec);

		const plaintext = new TextEncoder().encode('mls no codec');
		const sealed = await sframeEncrypt(plaintext, key, 3n);

		// Without the MLS codec, sframeDecrypt uses the fixed splitKid, which
		// interprets the KID as (epoch << 16 | peerIndex) — producing wrong
		// epoch/peerIndex. A resolver that looks up by (epoch, peerIndex)
		// (like the real worker does) will not find the key.
		await expect(
			sframeDecrypt(sealed, ({ epoch, peerIndex }) =>
				epoch === key.epoch && peerIndex === key.peerIndex ? key : null,
			),
		).rejects.toBeDefined();
	});
});

// ---- RoomRatchet integration ----------------------------------------------

describe('RoomRatchet kidFormat integration', () => {
	function makePeers(count: number): { identities: PeerIdentity[]; identity: ReturnType<typeof newIdentity> } {
		const identity = newIdentity('aaa-self'); // lex-smallest → authoritative author
		const identities: PeerIdentity[] = [];
		for (let i = 0; i < count; i++) {
			const p = newIdentity(`bbb-peer-${i}`);
			identities.push({ peerId: p.peerId, publicKey: p.publicKey });
		}
		return { identities, identity };
	}

	it('default kidFormat="fixed" — existing behavior unchanged', async () => {
		const { identities, identity } = makePeers(1);
		const ratchet = new RoomRatchet({ identity, initialPeers: identities });
		expect(ratchet.kidCodec.format).toBe('fixed');

		const announcements = await ratchet.startNewEpoch(identities);
		expect(announcements.length).toBe(1);

		const key = ratchet.advanceSending();
		// Fixed format: KID = (epoch << 16) | peerIndex.
		expect(key.kid).toBe(makeKid(ratchet.epoch, 0));
		expect(key.epoch).toBe(ratchet.epoch);
		expect(key.peerIndex).toBe(0);
	});

	it('kidFormat="fixed" explicit — same as default', async () => {
		const { identities, identity } = makePeers(1);
		const ratchet = new RoomRatchet({ identity, initialPeers: identities, kidFormat: 'fixed' });
		expect(ratchet.kidCodec.format).toBe('fixed');

		await ratchet.startNewEpoch(identities);
		const key = ratchet.advanceSending();
		expect(key.kid).toBe(makeKid(ratchet.epoch, 0));
	});

	it('kidFormat="mls" — KID encodes via MLS format', async () => {
		const { identities, identity } = makePeers(1);
		const mlsConfig: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const ratchet = new RoomRatchet({
			identity, initialPeers: identities,
			kidFormat: 'mls', mlsConfig,
		});
		expect(ratchet.kidCodec.format).toBe('mls');

		// Use a non-zero epoch so the MLS KID differs from the fixed KID
		// (at epoch=0, peerIndex=0 both encode to 0).
		await ratchet.startNewEpoch(identities, { version: 1 });
		const key = ratchet.advanceSending();

		// MLS-encoded KID: epoch in low 8 bits, index in next 8 bits.
		const expectedKid = Number(encodeMlsKid(1, 0, mlsConfig));
		expect(key.kid).toBe(expectedKid);
		// Fixed format would be (1 << 16) | 0 = 0x10000; MLS is just 1.
		expect(key.kid).not.toBe(makeKid(1, 0));
		expect(key.epoch).toBe(1);
		expect(key.peerIndex).toBe(0);
	});

	it('kidFormat="mls" with contextId — KID includes context bits', async () => {
		const { identities, identity } = makePeers(1);
		const mlsConfig: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0x42n };
		const ratchet = new RoomRatchet({
			identity, initialPeers: identities,
			kidFormat: 'mls', mlsConfig,
		});

		await ratchet.startNewEpoch(identities, { version: 1 });
		const key = ratchet.advanceSending();

		const expectedKid = Number(encodeMlsKid(1, 0, mlsConfig));
		expect(key.kid).toBe(expectedKid);

		// Decode via the ratchet's codec to verify round-trip.
		const decoded = ratchet.kidCodec.decode(key.kid);
		expect(decoded.epoch).toBe(1);
		expect(decoded.peerIndex).toBe(0);
	});

	it('kidFormat="mls" — getReceivingKey works with MLS-encoded KID', async () => {
		const { identities, identity } = makePeers(1);
		const mlsConfig: MlsKidConfig = { nEpochBits: 8, nIndexBits: 8, contextId: 0n };
		const ratchet = new RoomRatchet({
			identity, initialPeers: identities,
			kidFormat: 'mls', mlsConfig,
		});

		await ratchet.startNewEpoch(identities, { version: 1 });
		const sendKey = ratchet.advanceSending();

		// The receiving key for the same (epoch, peerIndex) should match.
		const recvKey = ratchet.getReceivingKey(sendKey.epoch, sendKey.peerIndex);
		expect(recvKey).not.toBeNull();
		expect(recvKey!.kid).toBe(sendKey.kid);
	});

	it('kidFormat="mls" without mlsConfig throws', () => {
		const { identities, identity } = makePeers(1);
		expect(() => new RoomRatchet({ identity, initialPeers: identities, kidFormat: 'mls' })).toThrow();
	});
});
