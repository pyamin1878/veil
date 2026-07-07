// Veil cryptography module.
//
// All encryption happens on the client. The server only ever relays the
// output of encryptMessage(), which is indistinguishable from random noise
// without the conversation key.
//
// Scheme:
//   identity   : ECDH keypair on P-256 (private key non-extractable)
//   agreement  : ECDH(myPrivate, theirPublic) -> 256 shared bits
//   KDF        : HKDF-SHA256, salt = sorted concat of both raw public keys,
//                info = "veil-conversation-v1"  -> AES-256-GCM key
//   messages   : AES-GCM with a fresh random 96-bit IV per message
//
// This module is pure ES + WebCrypto: it runs unchanged in browsers and in
// Node >= 19 (globalThis.crypto), which is how the test suite exercises it.

const subtle = globalThis.crypto.subtle;

const HKDF_INFO = new TextEncoder().encode('veil-conversation-v1');

// ---------- encoding helpers ----------

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- identity ----------

// The private key is non-extractable: it can be persisted as a CryptoKey in
// IndexedDB but its bytes can never be read out by script.
export async function generateIdentity() {
  return subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
}

export async function exportPublicKey(publicKey) {
  const raw = await subtle.exportKey('raw', publicKey);
  return bytesToBase64(raw);
}

export async function importPublicKey(b64) {
  return subtle.importKey(
    'raw',
    base64ToBytes(b64),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

// ---------- key agreement ----------

// Both parties derive the same key regardless of who calls this, because the
// HKDF salt is built from the two public keys in a canonical (sorted) order.
export async function deriveConversationKey(myPrivateKey, myPublicB64, theirPublicB64) {
  const theirPublic = await importPublicKey(theirPublicB64);

  const sharedBits = await subtle.deriveBits(
    { name: 'ECDH', public: theirPublic },
    myPrivateKey,
    256,
  );

  const [a, b] = [myPublicB64, theirPublicB64].sort();
  const salt = new Uint8Array([...base64ToBytes(a), ...base64ToBytes(b)]);

  const hkdfKey = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: HKDF_INFO },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ---------- messages ----------

export async function encryptMessage(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return { iv: bytesToBase64(iv), ct: bytesToBase64(ct) };
}

// Throws if the ciphertext or IV was tampered with (GCM auth failure).
export async function decryptMessage(key, ivB64, ctB64) {
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(ivB64) },
    key,
    base64ToBytes(ctB64),
  );
  return new TextDecoder().decode(pt);
}

// ---------- verification ----------

// A stable fingerprint of a public key, formatted for humans to compare
// out-of-band (in person, on a call, over another messenger).
export async function fingerprint(publicB64) {
  const digest = await subtle.digest('SHA-256', base64ToBytes(publicB64));
  const hex = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return hex.slice(0, 32).match(/.{4}/g).join(' ');
}
