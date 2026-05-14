/**
 * 02-mesh-browser — browser mesh demo.
 *
 * Two simulated peers (A and B) exchange SFrame-encrypted frames over a
 * MessageChannel. Peer A encrypts a random frame every 500 ms and sends the
 * raw bytes to Peer B, which decrypts and displays the result.
 *
 * Both peers share a SimpleKex instance keyed with a hard-coded demo password.
 * Toggle E2EE off to see unencrypted frames pass through as plain text.
 *
 * WARNING: SimpleKex is for demos only. Do not use in production.
 */

import { SimpleKex } from 'sframe-ratchet/kex-simple';
import { deriveSenderKeys, sframeEncrypt, sframeDecrypt } from 'sframe-ratchet';

// ── Config ───────────────────────────────────────────────────────────────────
const SHARED_PASSWORD = 'demo-password-not-for-production';
const EPOCH = 0;
const PEER_INDEX_A = 0;
const PEER_INDEX_B = 1;
const INTERVAL_MS = 500;
const HEX_TRUNCATE = 24; // bytes shown in the UI before "…"

// ── Key material ─────────────────────────────────────────────────────────────
const kexA = new SimpleKex({ sharedSecret: SHARED_PASSWORD });
const kexB = new SimpleKex({ sharedSecret: SHARED_PASSWORD });

const ckA = await kexA.initialEpoch();
const ckB = await kexB.initialEpoch();

// Peer A sends; derive its sending key on both sides.
const keyA_sender   = await deriveSenderKeys(ckA, EPOCH, PEER_INDEX_A);
const keyA_receiver = await deriveSenderKeys(ckB, EPOCH, PEER_INDEX_A);

// Peer B sends; derive its sending key on both sides.
const keyB_sender   = await deriveSenderKeys(ckB, EPOCH, PEER_INDEX_B);
const keyB_receiver = await deriveSenderKeys(ckA, EPOCH, PEER_INDEX_B);

// ── State ────────────────────────────────────────────────────────────────────
let e2eeEnabled = true;
let ctrA = 0n;
let ctrB = 0n;

// ── UI helpers ───────────────────────────────────────────────────────────────
const logA     = document.getElementById('log-a');
const logB     = document.getElementById('log-b');
const badgeA   = document.getElementById('badge-a');
const badgeB   = document.getElementById('badge-b');
const statusEl = document.getElementById('status');
const toggleEl = document.getElementById('toggle-e2ee');

function toHex(bytes) {
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.length > HEX_TRUNCATE * 2
    ? hex.slice(0, HEX_TRUNCATE * 2) + '…'
    : hex;
}

function appendLog(logEl, ts, label, cipherHex, plaintext) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML =
    `<span class="ts">${ts}</span>` +
    `<span class="label">${label}</span>` +
    (cipherHex ? `<span class="cipher">${cipherHex}</span>` : '') +
    (plaintext !== null
      ? `<span class="plain"> → ${plaintext}</span>`
      : `<span class="cipher"> (passthrough)</span>`);
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function nowTs() {
  return new Date().toLocaleTimeString('en', { hour12: false });
}

function updateBadges() {
  const cls   = e2eeEnabled ? 'badge-on'  : 'badge-off';
  const label = e2eeEnabled ? 'E2EE ON'   : 'E2EE OFF';
  [badgeA, badgeB].forEach(b => {
    b.className = `badge ${cls}`;
    b.textContent = label;
  });
  toggleEl.textContent = `E2EE: ${e2eeEnabled ? 'ON' : 'OFF'}`;
  toggleEl.className   = e2eeEnabled ? 'active' : '';
}

// ── Toggle ────────────────────────────────────────────────────────────────────
toggleEl.addEventListener('click', () => {
  e2eeEnabled = !e2eeEnabled;
  updateBadges();
});

// ── MessageChannel: A → B ────────────────────────────────────────────────────
const channelAtoB = new MessageChannel();

channelAtoB.port2.onmessage = async (ev) => {
  const bytes = new Uint8Array(ev.data);
  const ts = nowTs();

  if (!e2eeEnabled) {
    // Passthrough — frame arrives as plain bytes.
    appendLog(logB, ts, 'recv raw:', toHex(bytes), null);
    return;
  }

  try {
    const decrypted = await sframeDecrypt(
      bytes,
      ({ peerIndex }) => peerIndex === PEER_INDEX_A ? keyA_receiver : null,
    );
    appendLog(logB, ts, 'recv:', toHex(bytes), new TextDecoder().decode(decrypted));
  } catch (err) {
    appendLog(logB, ts, 'recv ERR:', toHex(bytes), `[${err.message}]`);
  }
};

// ── Sender loop ──────────────────────────────────────────────────────────────
let frameIndex = 0;

const MESSAGES = [
  'hello from peer A',
  'sframe is working',
  'RFC 9605 AES-GCM',
  'epoch ratchet active',
  'forward secrecy demo',
];

setInterval(async () => {
  const text = MESSAGES[frameIndex % MESSAGES.length];
  frameIndex++;
  const ts = nowTs();

  if (!e2eeEnabled) {
    const plain = new TextEncoder().encode(text);
    appendLog(logA, ts, 'send raw:', toHex(plain), text);
    channelAtoB.port1.postMessage(plain.buffer, [plain.buffer]);
    return;
  }

  const plaintext  = new TextEncoder().encode(text);
  const ciphertext = await sframeEncrypt(plaintext, keyA_sender, ctrA);
  ctrA++;

  appendLog(logA, ts, 'send:', toHex(ciphertext), text);
  // Transfer ArrayBuffer ownership to avoid copy.
  const copy = ciphertext.slice();
  channelAtoB.port1.postMessage(copy.buffer, [copy.buffer]);
}, INTERVAL_MS);

// ── Ready ─────────────────────────────────────────────────────────────────────
statusEl.textContent = 'Ready — frames exchanged every 500 ms';
