/**
 * Generic nested-Map lazy-creation helper.
 *
 * Replaces the duplicated `getReplayWindow()` pattern in `worker-frame.ts`
 * and `chat/index.ts` (repo-review-council NOISE finding).
 */

/**
 * Get-or-create a value in a two-level Map structure.
 *
 * @param outer  The outer Map<K1, Map<K2, V>>
 * @param key1   Outer key
 * @param key2   Inner key
 * @param factory  Called to create V when neither level exists
 */
export function getOrCreateNested<K1, K2, V>(
	outer: Map<K1, Map<K2, V>>,
	key1: K1,
	key2: K2,
	factory: () => V,
): V {
	let inner = outer.get(key1);
	if (!inner) {
		inner = new Map<K2, V>();
		outer.set(key1, inner);
	}
	let value = inner.get(key2);
	if (value === undefined) {
		value = factory();
		inner.set(key2, value);
	}
	return value;
}
