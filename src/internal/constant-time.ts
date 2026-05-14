/**
 * Constant-time byte comparison utilities.
 *
 * "Constant-time" here means no data-dependent branches in the comparison
 * loop — the XOR-OR fold always visits every byte regardless of where (or
 * whether) a mismatch occurs. It does NOT guarantee wall-clock constant time
 * in a JS runtime: the JIT compiler, garbage collector, CPU branch predictor,
 * and cache effects all introduce noise that can still leak timing information
 * in a sufficiently close observer. The goal is to remove the most obvious
 * branch-predictable oracle (early return on first differing byte) that an
 * in-process or same-origin attacker could exploit statistically. For
 * cryptographic proof of constant time, a hardware-attested runtime with a
 * formally-verified crypto library (e.g. a FIPS 140-3 module) is required.
 */

/**
 * Branchless equality for two fixed-length byte arrays.
 * Returns `true` iff every byte of `a` matches the corresponding byte of `b`.
 * Does NOT short-circuit on mismatch — all bytes are always compared.
 *
 * Length mismatch is detected before the loop and returns `false` immediately;
 * the length values themselves are not secret in SFrame use-cases (trailer
 * length is fixed and public).
 */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let acc = 0;
	for (let i = 0; i < a.length; i++) acc |= a[i]! ^ b[i]!;
	return acc === 0;
}

/**
 * Constant-time check that `frame` ends with `trailer`.
 *
 * The length comparison is plain (lengths are public). The byte comparison
 * of the suffix region is constant-time via {@link ctEqual}.
 *
 * Returns `false` if `frame.length < trailer.length`.
 * Returns `true` if `trailer.length === 0` (empty trailer always matches).
 */
export function ctEndsWith(frame: Uint8Array, trailer: Uint8Array): boolean {
	if (frame.length < trailer.length) return false;
	const suffix = frame.subarray(frame.length - trailer.length);
	return ctEqual(suffix, trailer);
}
