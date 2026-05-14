# 03-sfu-integration

How to wire `sframe-ratchet` against a real SFU. This is a guide with code
snippets, not a runnable example — it depends on a specific SFU SDK
(LiveKit-shaped API shown below).

## Architecture

```
   Browser A                        SFU                        Browser B
  ──────────────                ──────────                  ──────────────
  RTCRtpSender                                             RTCRtpReceiver
       │                         ┌──────┐                       │
       │ encoded frame            │      │  encoded frame        │
       ▼                         │      │                       ▼
  ┌─────────────┐   ciphertext   │      │   ciphertext   ┌─────────────┐
  │ SFrame wrap │ ─────────────► │ SFU  │ ─────────────► │SFrame unwrap│
  │  (worker)   │                │(opaque│                │  (worker)   │
  └─────────────┘                │bytes)│                └─────────────┘
       │                         └──────┘                       │
       │ FrameCryptor                                     FrameCryptor
       ▼                                                        ▼
  CryptoKey material                                    CryptoKey material
  (never leaves                                         (never leaves
   worker scope)                                         worker scope)
```

The SFU forwards opaque encrypted frames without decrypting them. Each browser
installs an `RTCRtpScriptTransform` on the sender and receiver sides. The
transform pipe feeds through the `sframe-ratchet` worker, which holds the
`CryptoKey` handles and performs AES-GCM in the worker thread.

## Wiring RTCRtpScriptTransform

### 1. Load the worker

```js
// main.js (or inside your framework component)
import { FrameCryptor, supportsSFrame } from 'sframe-ratchet';

const support = await supportsSFrame();
if (!support.scriptTransform && !support.encodedStreams) {
  console.warn('SFrame not supported in this browser');
}

// Worker script is the sframe-ratchet/worker export.
// Bundle it separately so it can be registered as a WorkerType="module".
const workerUrl = new URL('sframe-ratchet/worker', import.meta.url);
const cryptoWorker = new Worker(workerUrl, { type: 'module' });
```

### 2. Initialise the FrameCryptor

```js
import { FrameCryptor } from 'sframe-ratchet';
import { SimpleKex } from 'sframe-ratchet/kex-simple'; // demo only — replace with real KEX

const kex = new SimpleKex({ sharedSecret: roomSecret });
const chainKey = await kex.initialEpoch();

const cryptor = new FrameCryptor({
  worker: cryptoWorker,
  side: 'sender',        // 'sender' | 'receiver'
  codec: 'vp8',          // tell the worker to skip codec-specific header bytes
  epoch: 0,
  peerIndex: localPeerIndex,
  chainKey,
});
```

### 3. Attach to RTCRtpSender (sender side)

```js
// Called after pc.addTrack() and before pc.createOffer().
async function attachSender(sender) {
  if ('transform' in RTCRtpSender.prototype) {
    // RTCRtpScriptTransform path (Chrome 94+, Firefox 117+)
    sender.transform = new RTCRtpScriptTransform(
      cryptoWorker,
      { operation: 'encode', ...cryptor.workerInitMsg() },
    );
  } else {
    // Legacy createEncodedStreams path
    const { readable, writable } = sender.createEncodedStreams();
    cryptor.pipeThrough(readable, writable);
  }
}
```

### 4. Attach to RTCRtpReceiver (receiver side)

```js
// Called inside pc.ontrack handler.
pc.ontrack = ({ receiver, track }) => {
  const recvCryptor = new FrameCryptor({
    worker: cryptoWorker,
    side: 'receiver',
    codec: 'vp8',
    epoch: currentEpoch,
    peerIndex: remotePeerIndex,
    chainKey: currentChainKey,
  });

  if ('transform' in RTCRtpReceiver.prototype) {
    receiver.transform = new RTCRtpScriptTransform(
      cryptoWorker,
      { operation: 'decode', ...recvCryptor.workerInitMsg() },
    );
  } else {
    const { readable, writable } = receiver.createEncodedStreams();
    recvCryptor.pipeThrough(readable, writable);
  }
};
```

### 5. Epoch rotation on membership change

When a member joins or leaves, rotate the epoch so prior key material no longer
decrypts new frames:

```js
async function rotateMembership(newMembers) {
  const newEpoch = currentEpoch + 1;
  const newChainKey = kex.rotateEpoch(currentChainKey, newEpoch);

  // Announce to all receivers — this is your signalling responsibility.
  // The library is KEX-agnostic; deliver newChainKey out-of-band to each peer.
  await signalling.broadcast({
    type: 'epoch-announce',
    epoch: newEpoch,
    // encrypt newChainKey to each peer's public key here
  });

  // Advance the local sender.
  cryptor.rotateEpoch(newEpoch, newChainKey);
}
```

## Codec table reference

The `codec` option tells the worker how many unencrypted prefix bytes to
preserve so RTP/RTCP middleboxes can inspect codec-specific fields. See the
full table in [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md).

| Value | Codec | Unencrypted prefix |
|-------|-------|--------------------|
| `'vp8'` | VP8 | 1 byte (keyframe flag) |
| `'vp9'` | VP9 | 2 bytes |
| `'h264'` | H.264 | 1 byte |
| `'h265'` | H.265 | 2 bytes |
| `'av1'` | AV1 | 3 bytes |
| `'opus'` | Opus audio | 0 bytes |
| `undefined` | (default) | 0 bytes — full frame encrypted |

## Key delivery

The SFU must NOT see the `ChainKey`. Use a separate signalling channel
(e.g. a server-to-client WebSocket with per-user TLS, or direct peer-to-peer
WebRTC data channel) to deliver epoch key material encrypted to each
recipient's public key.

Recommended patterns:

- **Pairwise ECDH**: sender wraps `ChainKey` with `wrapChainKey(chainKey, recipientPublicKey)` from `sframe-ratchet` and delivers one ciphertext per peer.
- **Group KEX (MLS)**: use `@signalapp/libsignal-client` or `openmls` to negotiate epoch keys; extract the appropriate bytes via the MLS exporter and pass them as `chainKey`.

Never route epoch key material through the SFU signalling path — the SFU should
remain a black box for encrypted media payloads only.

## MLS adapter roadmap

A first-class `sframe-ratchet/mls` sub-package is on the roadmap. It will wrap
`mls-rs` (WASM) with a `RoomRatchetProvider` seam so MLS group state drives
epoch advancement automatically. Track progress in
[`ROADMAP.md`](../../ROADMAP.md) under "MLS adapter — L".
