// Tests for strict-FIPS mode flag.
//
// Global singleton — each test must call disableStrictFips() in afterEach
// to avoid state leaking into other test files.

import { afterEach, describe, expect, it } from 'vitest';
import {
	FipsModeViolationError,
	SFrameError,
	disableStrictFips,
	enableStrictFips,
	getStrictFips,
} from '../index.ts';
import { SimpleKex } from '../kex-simple.ts';
import { assertNotSimpleKex, assertSuiteAllowed } from '../strict-fips.ts';
import { newIdentity } from '../ratchet-ids.ts';
import { RoomRatchet } from '../ratchet.ts';

// ---- Cleanup ---------------------------------------------------------------

afterEach(() => {
	disableStrictFips();
});

// ---- Default off ------------------------------------------------------------

describe('default state — strict mode off', () => {
	it('getStrictFips() returns null', () => {
		expect(getStrictFips()).toBeNull();
	});

	it('assertSuiteAllowed does not throw for suite 4', () => {
		expect(() => assertSuiteAllowed('AES_128_GCM_SHA256')).not.toThrow();
	});

	it('assertSuiteAllowed does not throw for suite 5', () => {
		expect(() => assertSuiteAllowed('AES_256_GCM_SHA512')).not.toThrow();
	});

	it('assertNotSimpleKex does not throw', () => {
		expect(() => assertNotSimpleKex()).not.toThrow();
	});

	it('SimpleKex construction works', () => {
		expect(() => new SimpleKex({ sharedSecret: 'demo' })).not.toThrow();
	});

	it('RoomRatchet with suite 4 works', async () => {
		const id = await newIdentity('peer-a');
		expect(() => new RoomRatchet({ identity: id, suite: 'AES_128_GCM_SHA256' })).not.toThrow();
	});
});

// ---- enableStrictFips() defaults -------------------------------------------

describe('enableStrictFips() — all defaults true', () => {
	it('getStrictFips() returns full config', () => {
		enableStrictFips();
		expect(getStrictFips()).toStrictEqual({
			requireSuite5: true,
			forbidSimpleKex: true,
			requireNonExtractable: true,
		});
	});

	it('suite 4 → assertSuiteAllowed throws FipsModeViolationError', () => {
		enableStrictFips();
		expect(() => assertSuiteAllowed('AES_128_GCM_SHA256')).toThrow(FipsModeViolationError);
	});

	it('suite 4 error has code FIPS_VIOLATION', () => {
		enableStrictFips();
		try {
			assertSuiteAllowed('AES_128_GCM_SHA256');
			expect.fail('should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(FipsModeViolationError);
			expect((err as FipsModeViolationError).code).toBe('FIPS_VIOLATION');
			expect(err).toBeInstanceOf(SFrameError);
		}
	});

	it('suite 5 still passes assertSuiteAllowed', () => {
		enableStrictFips();
		expect(() => assertSuiteAllowed('AES_256_GCM_SHA512')).not.toThrow();
	});

	it('SimpleKex constructor throws FipsModeViolationError', () => {
		enableStrictFips();
		expect(() => new SimpleKex({ sharedSecret: 'demo' })).toThrow(FipsModeViolationError);
	});

	it('SimpleKex error has code FIPS_VIOLATION', () => {
		enableStrictFips();
		try {
			new SimpleKex({ sharedSecret: 'demo' });
			expect.fail('should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(FipsModeViolationError);
			expect((err as FipsModeViolationError).code).toBe('FIPS_VIOLATION');
			expect(err).toBeInstanceOf(SFrameError);
		}
	});

	it('RoomRatchet with suite 4 throws FipsModeViolationError', async () => {
		enableStrictFips();
		const id = await newIdentity('peer-a');
		expect(() => new RoomRatchet({ identity: id, suite: 'AES_128_GCM_SHA256' })).toThrow(FipsModeViolationError);
	});

	it('RoomRatchet with suite 5 still works', async () => {
		enableStrictFips();
		const id = await newIdentity('peer-a');
		expect(() => new RoomRatchet({ identity: id, suite: 'AES_256_GCM_SHA512' })).not.toThrow();
	});
});

// ---- Granular flags --------------------------------------------------------

describe('enableStrictFips({ requireSuite5: false })', () => {
	it('suite 4 allowed', () => {
		enableStrictFips({ requireSuite5: false });
		expect(() => assertSuiteAllowed('AES_128_GCM_SHA256')).not.toThrow();
	});

	it('SimpleKex still forbidden (forbidSimpleKex defaults true)', () => {
		enableStrictFips({ requireSuite5: false });
		expect(() => new SimpleKex({ sharedSecret: 'demo' })).toThrow(FipsModeViolationError);
	});
});

describe('enableStrictFips({ forbidSimpleKex: false })', () => {
	it('SimpleKex construction allowed', () => {
		enableStrictFips({ forbidSimpleKex: false });
		expect(() => new SimpleKex({ sharedSecret: 'demo' })).not.toThrow();
	});

	it('suite 4 still forbidden (requireSuite5 defaults true)', () => {
		enableStrictFips({ forbidSimpleKex: false });
		expect(() => assertSuiteAllowed('AES_128_GCM_SHA256')).toThrow(FipsModeViolationError);
	});
});

// ---- disableStrictFips() ---------------------------------------------------

describe('disableStrictFips()', () => {
	it('restores suite 4 after enable+disable', () => {
		enableStrictFips();
		disableStrictFips();
		expect(() => assertSuiteAllowed('AES_128_GCM_SHA256')).not.toThrow();
	});

	it('restores SimpleKex after enable+disable', () => {
		enableStrictFips();
		disableStrictFips();
		expect(() => new SimpleKex({ sharedSecret: 'demo' })).not.toThrow();
	});

	it('getStrictFips() returns null after disable', () => {
		enableStrictFips();
		disableStrictFips();
		expect(getStrictFips()).toBeNull();
	});
});

// ---- Error properties -------------------------------------------------------

describe('FipsModeViolationError properties', () => {
	it('is instanceof FipsModeViolationError', () => {
		const err = new FipsModeViolationError('test');
		expect(err).toBeInstanceOf(FipsModeViolationError);
	});

	it('is instanceof SFrameError', () => {
		const err = new FipsModeViolationError('test');
		expect(err).toBeInstanceOf(SFrameError);
	});

	it('is instanceof Error', () => {
		const err = new FipsModeViolationError('test');
		expect(err).toBeInstanceOf(Error);
	});

	it('code is FIPS_VIOLATION', () => {
		const err = new FipsModeViolationError('test');
		expect(err.code).toBe('FIPS_VIOLATION');
	});

	it('message preserved', () => {
		const err = new FipsModeViolationError('strict violation');
		expect(err.message).toBe('strict violation');
	});

	it('context preserved', () => {
		const err = new FipsModeViolationError('test', { suite: 'AES_128_GCM_SHA256' });
		expect(err.context).toStrictEqual({ suite: 'AES_128_GCM_SHA256' });
	});
});
