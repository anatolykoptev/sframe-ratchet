# Compliance map

This document describes the compliance posture of `sframe-ratchet` against
FIPS 140-3, HIPAA Security Rule, and CNSA 2.0. It is written for auditors
and compliance officers evaluating whether this library is appropriate as
one component of a regulated deployment. It is informational. It is not a
certification, and it does not constitute legal advice.

## 1. Scope and limitations

`sframe-ratchet` is a TypeScript library that implements RFC 9605 SFrame
AEAD, an epoch ratchet for group key rotation, and a Web Worker pipeline
that keeps WebCrypto `CryptoKey` handles off the main thread. It performs
no cryptography of its own: every AEAD, KDF, and DH operation is dispatched
to the host platform's WebCrypto provider (`crypto.subtle`), with a single
documented `@noble/curves` fallback for X25519 on runtimes that do not
expose it. The library is not, and cannot be, a FIPS 140-3 validated
cryptographic module — FIPS 140-3 validates modules, not source libraries,
and the module here is whichever WebCrypto provider the runtime exposes.

Compliance is a property of *deployments*, not of libraries. The library
provides necessary conditions for several controls (NIST-approved
primitives, AEAD authentication, non-extractable key handles, runtime
guardrails against weaker configurations) but never sufficient ones.
Whether a given deployment satisfies FIPS, HIPAA, or any other regime
depends on the host runtime, the key-exchange protocol the caller wires
in, the signaling channel's transport security, administrative controls,
and a Business Associate Agreement where applicable. Where this document
is silent on a control, treat it as out of scope.

## 2. Cryptographic primitives used

Every primitive in use, with provenance:

| Primitive | Standard | Used for | Source |
|---|---|---|---|
| AES-128-GCM | NIST SP 800-38D / FIPS 197 | RFC 9605 suite 4 AEAD | WebCrypto `subtle.encrypt` |
| AES-256-GCM | NIST SP 800-38D / FIPS 197 | RFC 9605 suite 5 AEAD; chain-key wrap | WebCrypto `subtle.encrypt` |
| HKDF-SHA-256 | RFC 5869 / NIST SP 800-56C | Suite 4 key derivation; wrap-key derivation | WebCrypto `subtle.deriveBits` |
| HKDF-SHA-512 | RFC 5869 / NIST SP 800-56C | Suite 5 key derivation | WebCrypto `subtle.deriveBits` |
| X25519 | RFC 7748 | ECIES wrap of `EpochAnnouncement` chain keys | WebCrypto / `@noble/curves` fallback |
| PBKDF2-HMAC-SHA-256 | NIST SP 800-132 | `SimpleKex` only — demo KEX, NOT for production | WebCrypto `subtle.deriveBits` |

Every primitive in this table is either NIST-approved (AES, SHA-2 family,
HKDF, PBKDF2) or NIST-allowed for use (X25519 is allowed for key
agreement under NIST SP 800-186). The library does not ship any
cryptographic implementation of its own for AES-GCM, HKDF, or PBKDF2.

## 3. FIPS 140-3 alignment

### What this library does to support FIPS deployments

- Uses only NIST-approved or NIST-allowed algorithms for all production
  code paths.
- Wraps WebCrypto `importKey` calls to enforce `extractable: false` on
  every derived key. Raw key bytes are not reachable from JavaScript
  after import.
- Provides `enableStrictFips()`, a runtime guardrail that:
  - Rejects RFC 9605 suite 4 (AES-128-GCM), forcing suite 5
    (AES-256-GCM + HKDF-SHA-512).
  - Rejects `SimpleKex` construction. Real deployments must supply an
    out-of-band KEX (MLS, X3DH, etc.).
  - Documents the non-extractable-key enforcement that the library
    applies unconditionally.
  - Raises `FipsModeViolationError` (a typed subclass of `SFrameError`
    with `code === 'FIPS_VIOLATION'`) on any violation.
- Ships NIST CAVP test vectors (`src/__tests__/cavp.test.ts`) that verify
  the host WebCrypto provider's AES-GCM and HKDF implementations produce
  the expected output for SP 800-38D and RFC 5869 vectors. This is not a
  validation, but it lets a deployment confirm the runtime matches the
  spec on the host where it will run.

### What FIPS 140-3 requires that this library cannot itself provide

- Validated cryptographic module status. FIPS 140-3 validates a module
  with a fixed boundary; here the boundary is the WebCrypto provider
  (Node.js OpenSSL, browser BoringSSL, etc.), not this library.
- Power-on self-tests, known-answer tests at startup, and continuous
  self-tests. These are the host runtime's responsibility.
- Physical security controls (Levels 2+).
- Module boundary documentation and security policy.
- Operational environment certification.

### Deployment path to FIPS-aligned operation

1. Run on a runtime whose WebCrypto provider is FIPS 140-3 validated —
   for example, Node.js built against FIPS-mode OpenSSL, or a controlled
   browser build with FIPS BoringSSL.
2. Call `enableStrictFips()` once, at application startup, before
   constructing any `RoomRatchet` or `FrameCryptor`.
3. Use `AES_256_GCM_SHA512` (suite 5) exclusively.
4. Supply a real KEX (MLS or equivalent). `SimpleKex` is for demos only
   and is rejected by strict mode.
5. Verify on the target runtime that `src/__tests__/cavp.test.ts` passes.

## 4. HIPAA Security Rule alignment

The HIPAA Security Rule for electronic Protected Health Information is
defined in 45 CFR Part 164, Subpart C. The mapping below identifies which
sections this library contributes to and which are entirely the caller's
responsibility.

| HIPAA section | Requirement | sframe-ratchet contribution | Caller responsibility |
|---|---|---|---|
| §164.312(a)(2)(iv) | Encryption and decryption (addressable) | Provides RFC 9605 AEAD for encoded media frames passing through the SFU | Key management lifecycle; signed BAA with each business associate |
| §164.312(e)(2)(ii) | Encryption (transmission security) | Frames are encrypted at the browser before they leave the endpoint | TLS for signaling; DTLS-SRTP for the media transport hop |
| §164.312(c)(1) | Integrity | AES-GCM authentication tag covers ciphertext and SFrame header (KID + CTR) | None for frame body; out of scope for non-media data |
| §164.312(b) | Audit controls | Worker emits structured `MetricsEvent`s (`encrypt`, `decrypt`, `decrypt_fail`, `ratchet_retry`, `queue_drop`, `epoch_advance`) for SIEM ingestion | Wiring metrics to a tamper-resistant log; retention policy |
| §164.312(a)(2)(i) | Unique user identification | (out of scope) | Caller's identity layer; library treats `peerId` as opaque |
| §164.312(a)(2)(iii) | Automatic logoff | (out of scope) | Application session management |
| §164.312(d) | Person or entity authentication | (out of scope) | Caller's auth layer must bind `peerId` to an authenticated identity |
| §164.308(a)(4) | Information access management | (out of scope) | Caller's membership policy decides who is admitted to an epoch |
| §164.308(a)(1)(ii)(D) | Information system activity review | Telemetry events available for review | Caller's review process |
| §164.308(b)(1) | Business associate contracts | (out of scope — OSS library, no service relationship) | Caller's vendor management |
| §164.310 | Physical safeguards | (out of scope) | Caller's facility and workstation controls |
| §164.314(a) | Organizational requirements | (out of scope) | Caller's policies |

HIPAA is largely administrative process. The library covers the
encryption-in-transit primitives at the media layer; the rest of the
Security Rule is outside its surface.

## 5. CNSA 2.0 and post-quantum

The NSA's Commercial National Security Algorithm Suite 2.0 sets a
migration window of 2027 onward for symmetric primitives and 2031 onward
for key-establishment and signature primitives in National Security
Systems.

- The SFrame protocol itself has no post-quantum profile. IETF AVTCORE
  WG has not specified one as of this writing.
- Suite 5 (`AES_256_GCM_SHA512`) uses AES-256 and SHA-512 — both are
  CNSA 2.0 symmetric primitives at the 256-bit security level. Strict
  FIPS mode forces suite 5.
- The X25519 ECIES path used to wrap epoch chain keys is *not*
  post-quantum. When SFrame gains a hybrid PQC key-establishment
  profile, this is the seam that will need replacing.
- No current regulatory regime mandates post-quantum cryptography
  today. CNSA 2.0 is forward-looking guidance, not a present obligation.

## 6. Side channels

### What the library does

- Constant-time SIF trailer comparison
  (`src/internal/constant-time.ts`) using a branchless XOR-OR fold; every
  byte of the suffix region is visited regardless of where a mismatch
  occurs.
- AES-GCM authentication tag verification is delegated entirely to
  WebCrypto; no plaintext bytes are returned to the worker until the tag
  has verified.
- Header parsing branches only on non-secret header fields (KID, CTR);
  these are public metadata.

### What the library does not, and in JavaScript cannot, do

- Wall-clock constant time. The V8/SpiderMonkey JIT, garbage collector,
  CPU branch predictor, and cache effects all introduce timing variance
  that a sufficiently precise observer could exploit.
- Memory zeroization of raw `ChainKey` bytes on the main thread. The
  chain key briefly exists as bytes during `deriveEpochKeyTable` and
  persists in JS until GC reclaims it. WebCrypto handles `CryptoKey`
  zeroization for non-extractable keys.
- Formal side-channel analysis. No published proof of constant-time
  behaviour exists for this library.

## 7. Key management guarantees

- **Chain keys** are derived on the main thread and used immediately to
  derive the per-sender key table. They are never serialized over
  `postMessage` as raw bytes.
- **Per-sender AEAD keys** are imported via WebCrypto with
  `extractable: false`. Their raw bytes are not reachable from JS after
  import. Only `CryptoKey` handles cross the worker boundary.
- **Epoch rotation** advances the room to a fresh chain key on every
  membership change. The retired epoch's keys are held for a 5-second
  grace window so in-flight frames decode, then forgotten.
- **Authoritative author rule**: the lexicographically smallest `peerId`
  in the current member set mints new epochs. This prevents split-brain
  on simultaneous membership changes.
- **Key zeroization**: WebCrypto handles destruction of `CryptoKey`
  objects when they become unreachable. Raw `ChainKey` bytes on the
  main thread persist until JS GC reclaims them; the library cannot
  zero JS memory directly.

## 8. Test vectors used

- RFC 9605 §C (SFrame end-to-end vectors) —
  `src/__tests__/sframe.vectors.test.ts`
- NIST SP 800-38D (AES-GCM known-answer vectors) —
  `src/__tests__/cavp.test.ts`
- RFC 5869 (HKDF-SHA-256 and HKDF-SHA-512 test cases) —
  `src/__tests__/cavp.test.ts`

These vectors verify the host WebCrypto provider's output against the
expected reference output. A failing CAVP test on a target runtime is a
signal that the runtime's WebCrypto implementation does not match the
specification and should not be used for compliance-sensitive work.

## 9. Audit status

- **Internal review**: ongoing, conducted by the project maintainers.
- **Third-party audit**: none. The library is pre-1.0 open source.
  Organizations that require an audited cryptographic implementation
  for compliance should commission their own audit, wait for a
  community audit, or budget for one as part of their deployment.
- **Vulnerability reporting**: via GitHub Security Advisories on the
  project repository, or by email to the maintainer listed in
  `package.json`. Public issues should not be opened for unpatched
  vulnerabilities.

## 10. What this document does NOT promise

- This document is informational. It is not a certification, an
  attestation, or a substitute for one.
- The library has not been validated by an accredited testing lab under
  the FIPS 140-3 Cryptographic Module Validation Program or any
  equivalent program.
- The maintainers are not attorneys. Compliance officers must
  independently verify these claims against their own interpretation of
  the applicable regulations and against their auditors' expectations.
- Specific FIPS 140-3 validation status depends entirely on the host
  runtime's WebCrypto provider; this library cannot confer it.
- Nothing here constitutes a Business Associate Agreement or a
  representation that the maintainers are willing to enter into one.

---

Cross-references:
- See [`docs/SECURITY.md`](./SECURITY.md) for the threat model and
  non-goals.
- See [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) for the pipeline
  diagram, epoch state machine, and file-by-file map.
- See [`CHANGELOG.md`](../CHANGELOG.md) for version history.
