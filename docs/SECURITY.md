# Security model

This document describes what `sframe-ratchet` is designed to defend against, what it does not defend against, and the operational assumptions a caller is making when they deploy it.

## Threat model

### Adversary

A malicious or compromised SFU, plus a network attacker on any hop between peers. The adversary can:

- Observe every byte on the wire, including all SFrame ciphertext and header fields (KID, CTR).
- Drop, reorder, duplicate, or replay frames.
- Inject crafted frames into the receiver's input stream.
- Read all SFU-side metadata: RTP headers, packet timing, packet sizes, bandwidth estimation traces, member join/leave events.

The adversary cannot:

- Read or modify code running inside a victim's browser realm.
- Read the private side of the X25519 identity keypair held by an honest peer (no key extraction).
- Compromise WebCrypto's `CryptoKey` opacity (non-extractable keys remain non-extractable).

### Goals

1. **Confidentiality** of encoded media frames against the SFU and any network observer. AES-GCM with per-sender keys and unique 96-bit IVs per (sender, ctr).
2. **Authenticity and integrity** of frames against the SFU. The header is bound as AEAD additional-authenticated-data, so the SFU cannot rewrite KID/CTR without invalidating the tag.
3. **Forward secrecy across epochs.** Each membership change rotates the room to a fresh chain key; the prior chain key is wiped after a 5-second grace window. An attacker who later compromises a peer's identity key cannot decrypt frames from past epochs whose chain keys have been forgotten.
4. **Sender attribution within an epoch.** Each peer holds a distinct per-sender key, so a receiver can tell which member produced a given frame (assuming the membership map is honestly delivered).

### Non-goals

- **Metadata privacy.** Frame timing, frame sizes, RTP SSRCs, member counts, and join/leave timing are all visible to the SFU and on-path observers. SFrame is not a mixnet.
- **DoS resistance.** A malicious SFU can drop or corrupt every frame. The receiver will fail to decode and the call will degrade; this is detected but not prevented.
- **Post-compromise security beyond the next epoch.** Forward secrecy is achieved by epoch rotation. If an adversary captures a peer's current chain key, they can decrypt frames in the current epoch until the next membership change rotates it. There is no per-frame ratchet in v1.
- **Defense against a malicious group member.** Any member of an epoch has the chain key for that epoch and can decrypt every other member's frames. If you do not trust a peer to receive your media, do not admit them. `sframe-ratchet` enforces no membership policy.
- **Identity binding.** The package consumes `peerId` strings as opaque labels. Whether they correspond to authenticated users is the caller's concern.
- **Authentication of the unencrypted codec prefix (when codec-aware partial encryption is enabled).** When a `Codec` is configured on a `StreamsMsg`, the first N bytes of each encoded frame are left in the clear so the SFU can route by frame type and browser decoders can fail gracefully on key mismatch. These prefix bytes are **not** included in the AES-GCM additional-authenticated-data. An attacker who can modify wire bytes (e.g. the SFU itself, or an on-path observer) can corrupt the codec header without detection by the AEAD layer. The decoded prefix will be whatever the attacker substituted — the rest of the frame (everything after the prefix) remains authenticity-protected as usual. This trade-off is intentional and mirrors the approach taken by LiveKit's `FrameCryptor`. If you need every byte to be authenticated, do not set a codec (the default `N=0` full-encryption path remains unchanged and provides complete AEAD coverage).
- **SIF trailer as a security boundary.** The optional SIF trailer (see `src/sif-trailer.ts`, enabled via `set-sif-trailer` control message) is a **routing hint only**. It exists so a receiver in a mixed E2EE / non-E2EE room can distinguish encrypted frames from plain frames before attempting AEAD — it does not provide any cryptographic guarantee.

  Known limitations:
  - **Forgery.** Any adversary — including the SFU — can append the trailer bytes to a plain frame. The receiver will then attempt AEAD on those bytes. The AEAD will fail (authentication tag mismatch) and the frame will be dropped. This is a denial-of-service vector, not a confidentiality breach.
  - **Stripping.** An adversary can strip the trailer from an encrypted frame. The receiver will treat it as a plain frame and pass it through without decryption. The downstream decoder will receive corrupted bytes and produce garbage video/audio. No confidentiality is lost; the attack degrades quality only.
  - **False-positive collision.** If a plain frame's payload happens to end with the trailer byte pattern by coincidence, the receiver will attempt AEAD, fail, and drop the frame. The probability is 1 / 256^N (for N-byte trailer), negligible in practice for the default 9-byte trailer but nonzero. Callers operating in high-stakes environments should use a longer custom trailer.

  If you need per-frame authentication of the routing marker, include a MAC or HMAC over the trailer (keyed with a shared secret agreed out-of-band) before sending to this library as a custom trailer byte sequence — but note that this is outside the scope of `sframe-ratchet`.

- **Ratchet retry window (liveness feature, NOT a security feature).** The decode pipeline attempts up to `ratchetWindowSize` forward derivation steps on AEAD failure for a known epoch + known peer. This smooths over RTP delivery jitter when the sender has advanced their per-sender key slightly ahead of what the receiver has cached. It does **not** widen the attacker's ability to decrypt: every retried key is still derived from the same HKDF chain that originates in the shared ChainKey, which the attacker does not have. An attacker cannot produce a valid ciphertext for any step in the chain without the ChainKey, regardless of window size. The retry window is bounded to prevent unbounded computation (default 8 steps; set to 0 to disable entirely via `set-ratchet-window`). Frames from a completely different epoch, or with an unknown peer index, still fail immediately without consuming retry budget.

## FIPS / HIPAA conformance

`sframe-ratchet` provides two cipher suites (RFC 9605 §4.5) for environments with regulatory requirements:

| Suite | AEAD | KDF | FIPS relevance |
|-------|------|-----|----------------|
| `AES_128_GCM_SHA256` (default) | AES-128-GCM | HKDF-SHA-256 | NIST-approved: FIPS 197 (AES), NIST SP 800-56C (HKDF) |
| `AES_256_GCM_SHA512` | AES-256-GCM | HKDF-SHA-512 | NIST-approved: FIPS 197 (AES-256), NIST SP 800-56C (HKDF) |

**How to select a suite:**

```ts
import { RoomRatchet, newIdentity } from 'sframe-ratchet';

const ratchet = new RoomRatchet({
  identity: newIdentity('alice'),
  suite: 'AES_256_GCM_SHA512', // HIPAA / AES-256 requirement
});
```

**FIPS validation:** All cryptographic operations use the host platform's WebCrypto implementation (`crypto.subtle`). FIPS 140-2/140-3 validation status depends on the WebCrypto provider used by the runtime (browser, Node.js, Deno, etc.). The library does not bundle any cryptographic primitives for AES-GCM; it relies entirely on WebCrypto for AEAD. The X25519 DH step uses `@noble/curves` as a fallback when WebCrypto X25519 is unavailable; if FIPS-certified X25519 is required, the caller must ensure the WebCrypto X25519 path is available and operational in the target runtime.

**Breaking change from 0.1.0:** The default suite changed from an undocumented 32-byte-AES-256-SHA-256 combination (which matched no RFC 9605 suite) to AES-128-GCM + SHA-256 (RFC 9605 suite 4). Frames encrypted with the 0.1.0 code path cannot be decrypted with 0.2.0 code. See `CHANGELOG.md` for migration notes.

**Strict mode:** For deployments that need a runtime guardrail against weaker configurations, use `enableStrictFips()` (see [`docs/COMPLIANCE.md`](./COMPLIANCE.md) for the full compliance posture and an attestation template).

## Key handling guarantees

- **Chain keys are derived on the main thread** and held there for the lifetime of an epoch. They are never serialized over `postMessage` as raw bytes. The `FrameCryptor.setEpoch` API takes a chain key on main, derives the per-sender key table locally, and posts only the resulting `CryptoKey` handles to the worker.
- **Per-sender AEAD keys are non-extractable `CryptoKey` objects.** They flow to the worker as WebCrypto handles. Their raw bytes are not reachable from JavaScript after import.
- **Epoch rotation grace.** When a new epoch is installed, the prior epoch's keys are kept for ~5 seconds so frames already in flight on the wire still decrypt, then wiped. The stale-epoch gate rejects any frame whose `epoch < currentMinValidEpoch` before invoking AEAD, so an attacker cannot force decryption with retired key material.
- **Header is authenticated.** SFrame header bytes (KID + CTR) are passed as AEAD additional-authenticated-data. The SFU cannot rewrite KID to misattribute a frame, or rewrite CTR to force IV reuse, without invalidating the tag.
- **IV uniqueness.** Each AEAD operation uses `IV = salt XOR be96(ctr)` where `salt` is per-sender (distinct salts even with a shared chain key, by §2.2 of the protocol spec) and `ctr` is a sender-wide monotonic counter that spans all SSRCs from one sender. There is no per-SSRC counter reset.

## Operational assumptions

The caller is responsible for:

- **Delivering `EpochAnnouncement` messages** to the peers they are addressed to. The ratchet emits one announcement per recipient; if you drop or misdeliver them, peers will stall on epoch installation and frames will fail to decode (resolver returns `key_not_found`).
- **Refusing to admit unauthenticated identities.** The `IdentityKeyPair` API mints raw X25519 keypairs. Binding `peerId` to a real authenticated identity (and refusing to install epochs from impostors) is your job.
- **Enforcing membership policy.** The ratchet does not authorize joins. If you allow a peer in, they get the current chain key.
- **Versioning.** The on-wire format is `0.1.0` and may change. Pin your version across all peers in a call.

## Side channels

### SIF trailer comparison

The SIF trailer byte comparison uses a branchless XOR-OR fold
(`src/internal/constant-time.ts`). Every byte of the suffix region is always
visited regardless of where a mismatch occurs, removing the most obvious
branch-predictable timing oracle that would be exploitable by an in-process or
same-origin attacker.

**JS runtime limitation.** This does NOT guarantee wall-clock constant time.
The V8/SpiderMonkey JIT, garbage collector, CPU branch predictor, and cache
effects can all introduce timing variance that a sufficiently precise observer
can exploit. For cryptographic proof of constant time (e.g. FIPS 140-3), a
hardware-attested runtime with a formally-verified crypto library is required.
The practical risk here is low — the trailer is not a security boundary (it is
a routing hint; see the SIF trailer section of this file) — but the
branchless pattern is used as a defence-in-depth measure and as a template for
any future comparisons that do carry security weight.

### AEAD tag verification

AES-GCM tag verification is delegated entirely to the host WebCrypto
implementation (`crypto.subtle.decrypt`). Constant-time tag comparison is the
responsibility of the underlying platform AEAD implementation. No tag
comparison is performed in JavaScript.

### Known non-constant-time spots

- The SFrame header parse (`src/sframe-header.ts`) performs data-dependent
  branches on the header byte. Header fields (KID, CTR) are not secret; this
  is not a timing oracle for key material.
- Epoch selection and the stale-epoch gate (`worker-frame.ts`) branch on
  epoch numbers, which are public metadata in SFrame.
- `src/ratchet-crypto.ts` HKDF derivations go through WebCrypto; the
  constant-time guarantees of HKDF are the platform's responsibility.

## Reporting vulnerabilities

Please report security issues via GitHub Security Advisories on the repository, or by email to the maintainer listed in `package.json`. Do not open public issues for unpatched vulnerabilities.
