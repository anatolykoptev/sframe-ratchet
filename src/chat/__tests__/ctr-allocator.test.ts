// Tests for CTR allocators — random-64 distribution, monotonic-idb increment.
// TDD RED phase.
// fake-indexeddb is imported at top for monotonic-idb tests.

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { RandomCtrAllocator, MonotonicIdbCtrAllocator } from '../ctr-allocator.ts';

describe('RandomCtrAllocator', () => {
	it('returns bigint', async () => {
		const alloc = new RandomCtrAllocator();
		const ctr = await alloc.next('room-1', 'alice');
		expect(typeof ctr).toBe('bigint');
	});

	it('returns distinct values (distribution sanity — 100 samples)', async () => {
		const alloc = new RandomCtrAllocator();
		const values = new Set<bigint>();
		for (let i = 0; i < 100; i++) {
			values.add(await alloc.next('room-1', 'alice'));
		}
		// Extremely unlikely to have collisions in 100 random 64-bit values
		expect(values.size).toBeGreaterThan(95);
	});

	it('values are non-negative (unsigned 64-bit)', async () => {
		const alloc = new RandomCtrAllocator();
		for (let i = 0; i < 20; i++) {
			const v = await alloc.next('room-1', 'alice');
			expect(v >= 0n).toBe(true);
		}
	});
});

describe('MonotonicIdbCtrAllocator', () => {
	it('throws on construction without ctrKeyspace', () => {
		expect(() => new MonotonicIdbCtrAllocator(undefined as unknown as string)).toThrow();
	});

	it('starts at 0 for fresh (room, uid) pair', async () => {
		const alloc = new MonotonicIdbCtrAllocator('test-keyspace-fresh');
		const ctr = await alloc.next('room-new', 'user-new');
		expect(ctr).toBe(0n);
	});

	it('increments monotonically', async () => {
		const alloc = new MonotonicIdbCtrAllocator('test-keyspace-mono');
		const v0 = await alloc.next('room-mono', 'user-a');
		const v1 = await alloc.next('room-mono', 'user-a');
		const v2 = await alloc.next('room-mono', 'user-a');
		expect(v1).toBe(v0 + 1n);
		expect(v2).toBe(v0 + 2n);
	});

	it('different (room, uid) pairs have independent counters', async () => {
		const alloc = new MonotonicIdbCtrAllocator('test-keyspace-iso');
		const a0 = await alloc.next('room-iso', 'user-x');
		const b0 = await alloc.next('room-iso', 'user-y');
		// Both start from 0 independently
		expect(a0).toBe(0n);
		expect(b0).toBe(0n);
		const a1 = await alloc.next('room-iso', 'user-x');
		expect(a1).toBe(1n);
	});

	it('works in Node env without navigator.locks (fallback path)', async () => {
		// In vitest/Node, navigator is undefined → single-tab fallback
		const alloc = new MonotonicIdbCtrAllocator('test-keyspace-nolock');
		// Should not throw even without navigator.locks
		const v = await alloc.next('room-nolock', 'user-nolock');
		expect(typeof v).toBe('bigint');
	});
});
