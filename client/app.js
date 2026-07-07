// Veil client. All plaintext lives only in this page's memory; the server
// receives nothing but ciphertext, IVs and public keys.

import {
  generateIdentity,
  exportPublicKey,
  deriveConversationKey,
  encryptMessage,
  decryptMessage,
  fingerprint,
} from '/crypto.js';

// ---------- identity persistence (IndexedDB) ----------
// The keypair is stored as a non-extractable CryptoKey: it survives reloads
// but its private bytes can never be read out, even by this page's own JS.

const DB_NAME = 'veil';
const STORE = 'identity';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE).objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadOrCreateIdentity() {
  let keyPair = await idbGet('keyPair');
  if (!keyPair) {
    keyPair = await generateIdentity();
    await idbSet('keyPair', keyPair);
  }
  return keyPair;
}

// ---------- state ----------

const state = {
  keyPair: null,
  myPubKey: null,     // base64
  id: null,
  token: null,
  name: null,
  peers: new Map(),   // id -> {id, name, pubKey}
  keys: new Map(),    // peerId -> Promise<CryptoKey>
  chats: new Map(),   // peerId -> [{mine, text, ts}]
  unread: new Map(),  // peerId -> count
  activePeer: null,
};

// ---------- helpers ----------

const $ = (id) => document.getElementById(id);

const AVATAR_COLORS = ['#4f46e5', '#0e9488', '#d97706', '#db2777', '#7c3aed', '#2563eb'];

function paintAvatar(el, name) {
  let hash = 0;
  for (const ch of name) hash = (hash * 31 + ch.codePointAt(0)) >>> 0;
  el.style.background = AVATAR_COLORS[hash % AVATAR_COLORS.length];
  el.textContent = name.trim()[0].toUpperCase();
}

function conversationKey(peer) {
  if (!state.keys.has(peer.id)) {
    state.keys.set(
      peer.id,
      deriveConversationKey(state.keyPair.privateKey, state.myPubKey, peer.pubKey),
    );
  }
  return state.keys.get(peer.id);
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ---------- join ----------

$('join-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('join-name').value.trim();
  if (!name) return;
  try {
    state.keyPair = await loadOrCreateIdentity();
    state.myPubKey = await exportPublicKey(state.keyPair.publicKey);

    const res = await fetch('/api/join', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, pubKey: state.myPubKey }),
    });
    if (!res.ok) throw new Error((await res.json()).error || 'join failed');
    const { id, token } = await res.json();

    Object.assign(state, { id, token, name });
    $('join-screen').hidden = true;
    $('app').hidden = false;
    $('me-name').textContent = name;
    paintAvatar($('me-avatar'), name);
    connectEvents();
  } catch (err) {
    const el = $('join-error');
    el.textContent = `Could not join: ${err.message}`;
    el.hidden = false;
  }
});

// ---------- server events ----------

function connectEvents() {
  const es = new EventSource(
    `/api/events?id=${encodeURIComponent(state.id)}&token=${encodeURIComponent(state.token)}`,
  );

  es.addEventListener('roster', (e) => {
    const roster = JSON.parse(e.data);
    state.peers = new Map(
      roster.filter((u) => u.id !== state.id).map((u) => [u.id, u]),
    );
    if (state.activePeer && !state.peers.has(state.activePeer)) {
      appendNotice(state.activePeer, 'This person went offline.');
    }
    renderRoster();
  });

  es.addEventListener('message', async (e) => {
    const { from, iv, ct, ts } = JSON.parse(e.data);
    const peer = state.peers.get(from);
    if (!peer) return;
    let text;
    try {
      text = await decryptMessage(await conversationKey(peer), iv, ct);
    } catch {
      appendNotice(from, '⚠ Received a message that failed decryption.');
      return;
    }
    pushMessage(from, { mine: false, text, ts });
    if (state.activePeer !== from) {
      state.unread.set(from, (state.unread.get(from) || 0) + 1);
      renderRoster();
    }
  });

  window.addEventListener('beforeunload', () => {
    navigator.sendBeacon(
      '/api/leave',
      new Blob([JSON.stringify({ id: state.id, token: state.token })], {
        type: 'application/json',
      }),
    );
  });
}

// ---------- rendering ----------

function renderRoster() {
  const list = $('roster');
  list.replaceChildren();
  for (const peer of state.peers.values()) {
    const li = document.createElement('li');
    li.classList.toggle('active', peer.id === state.activePeer);

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    paintAvatar(avatar, peer.name);

    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = peer.name;

    li.append(avatar, name);

    const unread = state.unread.get(peer.id);
    if (unread) {
      const badge = document.createElement('span');
      badge.className = 'unread';
      badge.textContent = unread;
      li.append(badge);
    }

    li.addEventListener('click', () => openChat(peer.id));
    list.append(li);
  }
  $('roster-empty').hidden = state.peers.size > 0;
}

function openChat(peerId) {
  const peer = state.peers.get(peerId);
  if (!peer) return;
  state.activePeer = peerId;
  state.unread.delete(peerId);

  $('chat-empty').hidden = true;
  $('chat-active').hidden = false;
  $('peer-name').textContent = peer.name;
  paintAvatar($('peer-avatar'), peer.name);

  renderMessages();
  renderRoster();
  $('composer-input').focus();
}

function renderMessages() {
  const box = $('messages');
  box.replaceChildren();

  const notice = document.createElement('div');
  notice.className = 'notice';
  notice.textContent =
    '🔒 Messages are end-to-end encrypted. No one outside this chat — not even the server — can read them.';
  box.append(notice);

  for (const msg of state.chats.get(state.activePeer) || []) {
    box.append(renderBubble(msg));
  }
  box.scrollTop = box.scrollHeight;
}

function renderBubble(msg) {
  if (msg.notice) {
    const div = document.createElement('div');
    div.className = 'notice';
    div.textContent = msg.text;
    return div;
  }
  const div = document.createElement('div');
  div.className = `bubble ${msg.mine ? 'mine' : 'theirs'}`;
  div.textContent = msg.text;
  const time = document.createElement('time');
  time.textContent = formatTime(msg.ts);
  div.append(time);
  return div;
}

function pushMessage(peerId, msg) {
  if (!state.chats.has(peerId)) state.chats.set(peerId, []);
  state.chats.get(peerId).push(msg);
  if (state.activePeer === peerId) {
    const box = $('messages');
    box.append(renderBubble(msg));
    box.scrollTop = box.scrollHeight;
  }
}

function appendNotice(peerId, text) {
  pushMessage(peerId, { notice: true, text, ts: Date.now() });
}

// ---------- sending ----------

$('composer').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('composer-input');
  const text = input.value.trim();
  const peer = state.peers.get(state.activePeer);
  if (!text || !peer) return;
  input.value = '';

  const { iv, ct } = await encryptMessage(await conversationKey(peer), text);
  const res = await fetch('/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: state.id, token: state.token, to: peer.id, iv, ct }),
  });
  if (res.ok) {
    pushMessage(peer.id, { mine: true, text, ts: Date.now() });
  } else {
    appendNotice(peer.id, '⚠ Could not deliver — they may have gone offline.');
  }
});

// ---------- verification ----------

async function showSafetyCodes(peer) {
  const codes = $('verify-codes');
  codes.replaceChildren();

  const entries = [{ owner: `You (${state.name})`, key: state.myPubKey }];
  if (peer) entries.push({ owner: peer.name, key: peer.pubKey });

  for (const { owner, key } of entries) {
    const block = document.createElement('div');
    block.className = 'code-block';
    const label = document.createElement('div');
    label.className = 'code-owner';
    label.textContent = owner;
    const code = document.createElement('code');
    code.textContent = await fingerprint(key);
    block.append(label, code);
    codes.append(block);
  }

  $('verify-title').textContent = peer ? `Verify ${peer.name}` : 'Your safety code';
  $('verify-dialog').showModal();
}

$('me-fingerprint-btn').addEventListener('click', () => showSafetyCodes(null));

// ---------- invite ----------

const inviteBtn = $('invite-btn');
const inviteHTML = inviteBtn.innerHTML;

inviteBtn.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(location.origin);
  } catch {
    prompt('Copy this invite link:', location.origin);
    return;
  }
  inviteBtn.textContent = 'Copied ✓';
  setTimeout(() => { inviteBtn.innerHTML = inviteHTML; }, 1600);
});

$('verify-btn').addEventListener('click', () => {
  const peer = state.peers.get(state.activePeer);
  if (peer) showSafetyCodes(peer);
});
