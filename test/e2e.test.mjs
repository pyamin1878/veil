// Veil test suite. Runs with: node --test test/
//
// Part 1 exercises client/crypto.js directly (same WebCrypto API as browsers).
// Part 2 boots the real Python server and drives two simulated clients through
// the full join -> roster -> encrypt -> relay -> decrypt flow, asserting the
// server never handles plaintext.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  generateIdentity,
  exportPublicKey,
  deriveConversationKey,
  encryptMessage,
  decryptMessage,
  fingerprint,
} from '../client/crypto.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PORT = 8770 + Math.floor(Math.random() * 100);
const BASE = `http://127.0.0.1:${PORT}`;

// ---------------- crypto unit tests ----------------

test('both parties derive the same conversation key', async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const alicePub = await exportPublicKey(alice.publicKey);
  const bobPub = await exportPublicKey(bob.publicKey);

  const keyA = await deriveConversationKey(alice.privateKey, alicePub, bobPub);
  const keyB = await deriveConversationKey(bob.privateKey, bobPub, alicePub);

  const msg = 'the fjords are lovely this time of year';
  const { iv, ct } = await encryptMessage(keyA, msg);
  assert.equal(await decryptMessage(keyB, iv, ct), msg);

  // And the other direction.
  const back = await encryptMessage(keyB, 'agreed ✓ 🔒');
  assert.equal(await decryptMessage(keyA, back.iv, back.ct), 'agreed ✓ 🔒');
});

test('ciphertext is fresh per message and never contains plaintext', async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const key = await deriveConversationKey(
    alice.privateKey,
    await exportPublicKey(alice.publicKey),
    await exportPublicKey(bob.publicKey),
  );

  const msg = 'super secret rendezvous';
  const one = await encryptMessage(key, msg);
  const two = await encryptMessage(key, msg);
  assert.notEqual(one.iv, two.iv, 'IVs must be unique');
  assert.notEqual(one.ct, two.ct, 'same plaintext must yield different ciphertext');
  assert.ok(!Buffer.from(one.ct, 'base64').includes(msg));
});

test('tampered ciphertext fails to decrypt', async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const key = await deriveConversationKey(
    alice.privateKey,
    await exportPublicKey(alice.publicKey),
    await exportPublicKey(bob.publicKey),
  );

  const { iv, ct } = await encryptMessage(key, 'do not touch');
  const bytes = Buffer.from(ct, 'base64');
  bytes[0] ^= 0xff;
  await assert.rejects(decryptMessage(key, iv, bytes.toString('base64')));

  // A third party's key must not decrypt either.
  const eve = await generateIdentity();
  const eveKey = await deriveConversationKey(
    eve.privateKey,
    await exportPublicKey(eve.publicKey),
    await exportPublicKey(alice.publicKey),
  );
  await assert.rejects(decryptMessage(eveKey, iv, ct));
});

test('fingerprints are stable and distinct', async () => {
  const a = await exportPublicKey((await generateIdentity()).publicKey);
  const b = await exportPublicKey((await generateIdentity()).publicKey);
  assert.equal(await fingerprint(a), await fingerprint(a));
  assert.notEqual(await fingerprint(a), await fingerprint(b));
  assert.match(await fingerprint(a), /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
});

// ---------------- end-to-end against the real server ----------------

// Minimal SSE client over fetch streaming.
async function openEvents(id, token, onEvent) {
  const res = await fetch(
    `${BASE}/api/events?id=${encodeURIComponent(id)}&token=${encodeURIComponent(token)}`,
  );
  assert.equal(res.status, 200);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  (async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const chunk = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let event = 'message';
        let data = '';
        for (const line of chunk.split('\n')) {
          if (line.startsWith('event: ')) event = line.slice(7);
          if (line.startsWith('data: ')) data = line.slice(6);
        }
        if (data) onEvent(event, JSON.parse(data));
      }
    }
  })().catch(() => {});
  return () => reader.cancel();
}

async function post(pathname, body) {
  const res = await fetch(`${BASE}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

function waitFor(fn, what, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    (function poll() {
      const value = fn();
      if (value) return resolve(value);
      if (Date.now() - start > timeout) return reject(new Error(`timed out: ${what}`));
      setTimeout(poll, 25);
    })();
  });
}

test('full message flow through the relay server', async (t) => {
  const server = spawn('python3', [path.join(ROOT, 'server.py'), String(PORT)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => server.kill());

  // Wait for the server to accept connections.
  for (let i = 0; i < 40; i++) {
    try {
      await fetch(BASE + '/');
      break;
    } catch {
      await sleep(100);
    }
  }

  // The client must be served with its security headers.
  const page = await fetch(BASE + '/');
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy') || '', /default-src 'none'/);

  // --- Alice and Bob generate identities locally and join ---
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const alicePub = await exportPublicKey(alice.publicKey);
  const bobPub = await exportPublicKey(bob.publicKey);

  const aliceJoin = await post('/api/join', { name: 'Alice', pubKey: alicePub });
  const bobJoin = await post('/api/join', { name: 'Bob', pubKey: bobPub });
  assert.equal(aliceJoin.status, 200);
  assert.equal(bobJoin.status, 200);

  const aliceEvents = [];
  const bobEvents = [];
  const closeA = await openEvents(aliceJoin.body.id, aliceJoin.body.token, (e, d) =>
    aliceEvents.push([e, d]),
  );
  const closeB = await openEvents(bobJoin.body.id, bobJoin.body.token, (e, d) =>
    bobEvents.push([e, d]),
  );
  t.after(() => { closeA(); closeB(); });

  // --- Alice sees Bob in the roster with his real public key ---
  const bobEntry = await waitFor(() => {
    const rosters = aliceEvents.filter(([e]) => e === 'roster');
    const last = rosters.at(-1);
    return last && last[1].find((u) => u.id === bobJoin.body.id);
  }, 'Alice receives roster containing Bob');
  assert.equal(bobEntry.pubKey, bobPub, 'roster carries the untouched public key');

  // --- Alice encrypts locally and sends through the relay ---
  const secret = 'meet at the lighthouse at nine 🕯️';
  const aliceKey = await deriveConversationKey(alice.privateKey, alicePub, bobEntry.pubKey);
  const { iv, ct } = await encryptMessage(aliceKey, secret);
  assert.ok(!ct.includes(secret), 'wire payload must not contain plaintext');

  const send = await post('/api/send', {
    id: aliceJoin.body.id,
    token: aliceJoin.body.token,
    to: bobJoin.body.id,
    iv,
    ct,
  });
  assert.equal(send.status, 200);

  // --- Bob receives exactly the ciphertext and decrypts it ---
  const [, delivered] = await waitFor(
    () => bobEvents.find(([e]) => e === 'message'),
    'Bob receives the relayed message',
  );
  assert.equal(delivered.from, aliceJoin.body.id);
  assert.equal(delivered.ct, ct, 'server relayed ciphertext byte-for-byte');
  assert.ok(!JSON.stringify(delivered).includes(secret), 'server never saw plaintext');

  const bobKey = await deriveConversationKey(bob.privateKey, bobPub, alicePub);
  assert.equal(await decryptMessage(bobKey, delivered.iv, delivered.ct), secret);

  // --- auth is enforced ---
  const forged = await post('/api/send', {
    id: aliceJoin.body.id,
    token: 'wrong-token',
    to: bobJoin.body.id,
    iv,
    ct,
  });
  assert.equal(forged.status, 403);

  // --- leaving updates the roster for the other side ---
  const rosterCountBefore = bobEvents.filter(([e]) => e === 'roster').length;
  await post('/api/leave', { id: aliceJoin.body.id, token: aliceJoin.body.token });
  const lastRoster = await waitFor(() => {
    const rosters = bobEvents.filter(([e]) => e === 'roster');
    return rosters.length > rosterCountBefore ? rosters.at(-1)[1] : null;
  }, 'Bob receives updated roster after Alice leaves');
  assert.ok(!lastRoster.some((u) => u.id === aliceJoin.body.id));
});
