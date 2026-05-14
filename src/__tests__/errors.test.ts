// Unit tests for the typed error hierarchy (src/errors.ts).
// Each test asserts:
//   - the error is an instance of the specific class
//   - the error is an instance of SFrameError (base)
//   - `.code` is set to the expected string constant
//   - `.context` carries the expected structured fields
//   - `.name` matches the class name (important for stack traces)

import { describe, expect, it } from 'vitest';
import {
	AEADAuthError,
	HeaderParseError,
	KeyNotFoundError,
	QueueFullError,
	RatchetWindowExhaustedError,
	SFrameError,
	StaleEpochError,
} from '../errors.ts';

// ---- Base class ------------------------------------------------------------

describe('SFrameError (abstract base)', () => {
	it('all typed errors are instanceof SFrameError', () => {
		const errors = [
			new KeyNotFoundError('test', {}),
			new StaleEpochError('test', { frameEpoch: 0, minValidEpoch: 1 }),
			new AEADAuthError('test', {}),
			new RatchetWindowExhaustedError('test', { epoch: 0, peerIndex: 0, attempts: 8 }),
			new HeaderParseError('test'),
			new QueueFullError('test'),
		];
		for (const err of errors) {
			expect(err instanceof SFrameError).toBe(true);
			expect(err instanceof Error).toBe(true);
		}
	});
});

// ---- KeyNotFoundError ------------------------------------------------------

describe('KeyNotFoundError', () => {
	it('has code KEY_NOT_FOUND and carries context', () => {
		const err = new KeyNotFoundError('no key for epoch=3 peer=2', { epoch: 3, peerIndex: 2 });
		expect(err instanceof KeyNotFoundError).toBe(true);
		expect(err.code).toBe('KEY_NOT_FOUND');
		expect(err.context.epoch).toBe(3);
		expect(err.context.peerIndex).toBe(2);
		expect(err.name).toBe('KeyNotFoundError');
		expect(err.message).toContain('epoch=3');
	});

	it('carries kid when provided', () => {
		const err = new KeyNotFoundError('missing', { kid: 0xaabb, epoch: 0, peerIndex: 0 });
		expect(err.context.kid).toBe(0xaabb);
	});
});

// ---- StaleEpochError -------------------------------------------------------

describe('StaleEpochError', () => {
	it('has code STALE_EPOCH and carries epoch context', () => {
		const err = new StaleEpochError('stale epoch 2 (min: 5)', { frameEpoch: 2, minValidEpoch: 5 });
		expect(err instanceof StaleEpochError).toBe(true);
		expect(err.code).toBe('STALE_EPOCH');
		expect(err.context.frameEpoch).toBe(2);
		expect(err.context.minValidEpoch).toBe(5);
		expect(err.name).toBe('StaleEpochError');
	});

	it('carries optional kid', () => {
		const err = new StaleEpochError('stale', { frameEpoch: 1, minValidEpoch: 3, kid: 99 });
		expect(err.context.kid).toBe(99);
	});
});

// ---- AEADAuthError ---------------------------------------------------------

describe('AEADAuthError', () => {
	it('has code AEAD_AUTH_FAIL', () => {
		const err = new AEADAuthError('auth failed', { kid: 5, epoch: 1, peerIndex: 0, ctr: 42n });
		expect(err instanceof AEADAuthError).toBe(true);
		expect(err.code).toBe('AEAD_AUTH_FAIL');
		expect(err.context.ctr).toBe(42n);
		expect(err.name).toBe('AEADAuthError');
	});

	it('accepts empty context', () => {
		const err = new AEADAuthError('auth failed', {});
		expect(err.code).toBe('AEAD_AUTH_FAIL');
		expect(err.context).toEqual({});
	});
});

// ---- RatchetWindowExhaustedError -------------------------------------------

describe('RatchetWindowExhaustedError', () => {
	it('has code RATCHET_WINDOW_EXHAUSTED and carries attempts', () => {
		const err = new RatchetWindowExhaustedError('window exhausted', {
			epoch: 3, peerIndex: 1, attempts: 8,
		});
		expect(err instanceof RatchetWindowExhaustedError).toBe(true);
		expect(err.code).toBe('RATCHET_WINDOW_EXHAUSTED');
		expect(err.context.attempts).toBe(8);
		expect(err.context.epoch).toBe(3);
		expect(err.context.peerIndex).toBe(1);
		expect(err.name).toBe('RatchetWindowExhaustedError');
	});
});

// ---- HeaderParseError ------------------------------------------------------

describe('HeaderParseError', () => {
	it('has code HEADER_PARSE', () => {
		const err = new HeaderParseError('empty buffer', { bufferLength: 0 });
		expect(err instanceof HeaderParseError).toBe(true);
		expect(err.code).toBe('HEADER_PARSE');
		expect(err.context?.bufferLength).toBe(0);
		expect(err.name).toBe('HeaderParseError');
	});

	it('works without context', () => {
		const err = new HeaderParseError('short ctr');
		expect(err.code).toBe('HEADER_PARSE');
		expect(err.context).toBeUndefined();
	});
});

// ---- QueueFullError --------------------------------------------------------

describe('QueueFullError', () => {
	it('has code QUEUE_FULL', () => {
		const err = new QueueFullError('queue overflow', { queueLength: 50 });
		expect(err instanceof QueueFullError).toBe(true);
		expect(err.code).toBe('QUEUE_FULL');
		expect(err.name).toBe('QueueFullError');
	});
});

// ---- instanceof across error hierarchy edge cases --------------------------

describe('instanceof hierarchy', () => {
	it('StaleEpochError is NOT instanceof KeyNotFoundError', () => {
		const err = new StaleEpochError('x', { frameEpoch: 0, minValidEpoch: 1 });
		expect(err instanceof KeyNotFoundError).toBe(false);
	});

	it('error thrown from throw site is catchable via base class', () => {
		const fn = (): void => {
			throw new AEADAuthError('fail', {});
		};
		expect(() => fn()).toThrow(AEADAuthError);
		// Also verify base class membership manually (toThrow can't accept abstract Ctor).
		let caught: unknown;
		try { fn(); } catch (e) { caught = e; }
		expect(caught instanceof SFrameError).toBe(true);
	});
});
