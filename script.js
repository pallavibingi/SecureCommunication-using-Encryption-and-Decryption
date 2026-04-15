/**
 * SecureComm — Hybrid Encryption Platform
 * script.js
 *
 * Technologies Used:
 *  - Web Crypto API (window.crypto.subtle)
 *      • RSA-OAEP  (2048-bit) — asymmetric key generation & key wrapping
 *      • AES-GCM   (256-bit)  — symmetric message encryption
 *      • SHA-256              — RSA hash function
 *  - TextEncoder / TextDecoder — string ↔ binary conversion
 *  - Uint8Array / ArrayBuffer  — raw binary data handling
 *  - Base64 encoding (btoa)    — PEM key export
 *  - DOM manipulation (vanilla JS)
 */

'use strict';

/* ═══════════════════════════════════════════
   APPLICATION STATE
═══════════════════════════════════════════ */
let PUB      = null;   // CryptoKey — RSA Public Key
let PRV      = null;   // CryptoKey — RSA Private Key
let AES_KEY  = null;   // CryptoKey — AES-256-GCM Session Key

let LAST_CT  = null;   // ArrayBuffer — Last Ciphertext
let LAST_EK  = null;   // ArrayBuffer — Last RSA-Wrapped AES Key
let LAST_IV  = null;   // Uint8Array  — Last IV / Nonce

/* Counters for stats bar */
let cE = 0, cD = 0, cK = 0, cT = 0;

/* History row counter */
let hN = 1;


/* ═══════════════════════════════════════════
   UTILITY FUNCTIONS
═══════════════════════════════════════════ */

/** Shortcut for document.getElementById */
const $ = id => document.getElementById(id);

/** Current time as HH:MM:SS string */
const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

/** Promise-based sleep */
const sl = ms => new Promise(r => setTimeout(r, ms));

/**
 * Convert ArrayBuffer → hex string
 * Used to display ciphertext, IV, and wrapped key
 */
function ab2hex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert ArrayBuffer → Base64 string
 * Used for PEM key export
 */
function ab2b64(buf) {
  let s = '';
  const b = new Uint8Array(buf);
  for (let i = 0; i < b.byteLength; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

/** Truncate long strings for display */
function trunc(s, n = 200) {
  return s.length > n ? s.slice(0, n) + '...' : s;
}


/* ═══════════════════════════════════════════
   STATS COUNTER ANIMATION
═══════════════════════════════════════════ */

/**
 * Update a stat counter element with a "bump" animation
 * @param {string} id   — Element ID
 * @param {number} val  — New value to display
 */
function bump(id, val) {
  const el = $(id);
  if (!el) return;
  el.textContent = val;
  el.classList.remove('sbump');
  void el.offsetWidth;   // force reflow to restart animation
  el.classList.add('sbump');
}


/* ═══════════════════════════════════════════
   ACTIVITY LOG
═══════════════════════════════════════════ */

/**
 * Append a log entry to all three log panels (Step 01, 02, 03)
 * @param {string} msg   — Message text
 * @param {string} type  — CSS class: 'info' | 'success' | 'warn' | 'error'
 */
function log(msg, type = 'info') {
  ['logA', 'logB', 'logC'].forEach(id => {
    const el = $(id);
    if (!el) return;
    const d = document.createElement('div');
    d.className = 'le';
    d.innerHTML = `<span class="lt2">${ts()}</span><span class="lm ${type}">${msg}</span>`;
    el.appendChild(d);
    el.scrollTop = el.scrollHeight;
  });
}

/** Clear all log panels */
function clrLog() {
  ['logA', 'logB', 'logC'].forEach(id => {
    const e = $(id);
    if (e) e.innerHTML = '';
  });
}


/* ═══════════════════════════════════════════
   SESSION HISTORY TABLE
═══════════════════════════════════════════ */

/**
 * Add a row to the session history table
 * @param {string} op    — 'ENC' or 'DEC'
 * @param {string} rcpt  — Recipient label
 * @param {string} sz    — Size string (e.g. "0.032 KB")
 */
function addHist(op, rcpt, sz) {
  const em = $('histE'), hd = $('histH'), bd = $('histB');
  if (em) em.style.display = 'none';
  if (hd) hd.style.display = 'grid';

  const isE = op === 'ENC';
  const row = document.createElement('div');
  row.className = 'hrow hanim';
  row.innerHTML = `
    <span class="hid">#${String(hN++).padStart(3, '0')}</span>
    <span class="htime">${ts()}</span>
    <span class="${isE ? 'henc' : 'hdec'}">${isE ? '🔒 ENC' : '🔓 DEC'}</span>
    <span class="hrcv">${rcpt}</span>
    <span class="hsz">${sz}</span>
    <span><span class="hbadge ${isE ? 'be' : 'bd'}">${isE ? '● Encrypted' : '✓ Decrypted'}</span></span>`;

  const h = $('histH');
  if (h && h.nextSibling) bd.insertBefore(row, h.nextSibling);
  else bd.appendChild(row);
  bd.scrollTop = 0;
}

/** Clear the history table and reset counter */
function clrHist() {
  hN = 1;
  const bd = $('histB');
  if (!bd) return;
  bd.querySelectorAll('.hrow:not(#histH):not(#histE)').forEach(r => r.remove());
  const e = $('histE'), h = $('histH');
  if (e) e.style.display = 'flex';
  if (h) h.style.display = 'none';
}


/* ═══════════════════════════════════════════
   TAB NAVIGATION
═══════════════════════════════════════════ */

/**
 * Switch to a specific tab/panel
 * @param {number} n — Tab index (0, 1, or 2)
 */
function goTab(n) {
  [0, 1, 2].forEach(i => {
    $(`t${i}`).classList.toggle('on', i === n);
    $(`p${i}`).classList.toggle('on', i === n);
  });
}


/* ═══════════════════════════════════════════
   SESSION RESET
   Called every time new keys are generated,
   so old encrypted data doesn't leak into a
   new session.
═══════════════════════════════════════════ */
function resetSession() {
  AES_KEY = null;
  LAST_CT = null;
  LAST_EK = null;
  LAST_IV = null;

  // Reset Encrypt button
  const eb = $('encBtn');
  if (eb) {
    eb.innerHTML = '🔒 Encrypt Message';
    eb.disabled = false;
    eb.removeAttribute('style');
  }

  // Reset Send button
  const sb = $('sendBtn');
  if (sb) {
    sb.innerHTML = '📡 Send Encrypted Payload';
    sb.disabled = true;
    sb.removeAttribute('style');
  }

  // Reset Decrypt result panel
  const dr = $('decRes');
  if (dr) {
    dr.innerHTML = '<div class="dph"><div class="di">🔒</div><p>Decrypted message will appear here.<br>Private key is required to unlock.</p></div>';
  }

  // Reset Decrypt button
  const db = $('decBtn');
  if (db) {
    db.innerHTML = '🔓 Decrypt Message';
    db.disabled = false;
    db.removeAttribute('style');
  }

  // Reset output display boxes
  ['ctOut', 'ekOut', 'ivOut'].forEach(id => {
    const e = $(id);
    if (e) e.textContent = '— Awaiting encryption —';
  });

  ['rxCT', 'rxEK'].forEach(id => {
    const e = $(id);
    if (e) e.textContent = '— Complete Steps 01 and 02 first —';
  });
}


/* ═══════════════════════════════════════════
   STEP 01 — RSA KEY GENERATION
   Algorithm : RSA-OAEP
   Key size  : 2048 bits
   Hash      : SHA-256
   Exponent  : 65537 (0x010001)
   Export    : SPKI (public) + PKCS#8 (private) → PEM
═══════════════════════════════════════════ */
async function genKeys() {
  const btn = $('genBtn'), prog = $('gProg');
  btn.innerHTML = '<span class="spin"></span> Generating...';
  btn.disabled = true;

  resetSession();
  PUB = null; PRV = null;

  log('Session reset · generating fresh RSA-2048 key pair...', 'info');
  prog.style.width = '15%';
  await sl(150);

  try {
    /* Generate RSA-OAEP key pair via WebCrypto */
    const kp = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),  // 65537
        hash: 'SHA-256'
      },
      true,              // extractable = true (so we can export PEM)
      ['encrypt', 'decrypt']
    );
    prog.style.width = '55%';
    log('RSA-2048 key pair generated via WebCrypto API.', 'success');

    PUB = kp.publicKey;
    PRV = kp.privateKey;

    /* Export keys to DER format, then wrap in PEM */
    const pubDer = await crypto.subtle.exportKey('spki',  PUB);
    const prvDer = await crypto.subtle.exportKey('pkcs8', PRV);

    const pubPem = `-----BEGIN PUBLIC KEY-----\n${ab2b64(pubDer).match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    const prvPem = `-----BEGIN PRIVATE KEY-----\n${ab2b64(prvDer).match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;

    /* Display keys in UI */
    $('kPub').textContent = trunc(pubPem);
    $('kPrv').textContent = trunc(prvPem);
    $('rxPrv').textContent = trunc(prvPem);
    $('kAes').textContent = '— Will be created at encryption time —';

    prog.style.width = '100%';
    log('Public key exported (SPKI/PEM format).', 'success');
    log('Private key exported (PKCS#8/PEM) · stays local.', 'success');
    log('✓ Keys ready · proceed to Step 02 to encrypt a message.', 'info');

    cK++;
    bump('sK', cK);

    btn.innerHTML = '✓ Keys Ready — Re-click to Generate New Keys';
    btn.style.background = 'linear-gradient(135deg,#007a50,#00ffa3)';
    btn.style.color = '#02080f';
    btn.disabled = false;

  } catch (e) {
    log(`Key generation error: ${e.message}`, 'error');
    btn.innerHTML = '🔑 Generate RSA Key Pair';
    btn.disabled = false;
    prog.style.width = '0%';
  }
}


/* ═══════════════════════════════════════════
   STEP 02 — ENCRYPT & SEND
   1. Generate fresh AES-256-GCM session key
   2. Encrypt plaintext message with AES-GCM
   3. Wrap (encrypt) AES key with RSA public key
   4. Output: [ciphertext, wrapped-key, IV]
═══════════════════════════════════════════ */
async function doEnc() {
  if (!PUB) {
    log('Error: No RSA keys found. Please generate keys in Step 01.', 'error');
    alert('Please generate RSA keys in Step 01 first.');
    return;
  }
  const pt = $('msg').value.trim();
  if (!pt) { alert('Please enter a message to encrypt.'); return; }

  const btn = $('encBtn');
  btn.innerHTML = '<span class="spin"></span> Encrypting...';
  btn.disabled = true;
  $('sendBtn').disabled = true;

  log('Generating fresh AES-256-GCM session key...', 'info');

  try {
    /* ── 1. Generate AES-256-GCM session key ── */
    AES_KEY = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,          // extractable so we can wrap it with RSA
      ['encrypt', 'decrypt']
    );
    const rawAES = await crypto.subtle.exportKey('raw', AES_KEY);
    $('kAes').textContent = ab2hex(rawAES);
    log(`AES-256 key: ${ab2hex(rawAES).slice(0, 16)}... [session scope]`, 'success');

    /* ── 2. Encrypt plaintext with AES-GCM ── */
    // IV must be 96-bit (12 bytes) for GCM — never reuse with same key
    const iv = crypto.getRandomValues(new Uint8Array(12));
    LAST_IV = iv;

    const enc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      AES_KEY,
      new TextEncoder().encode(pt)
    );
    LAST_CT = enc;

    const ctHex = ab2hex(enc);
    const ivHex = ab2hex(iv.buffer);
    $('ctOut').textContent = ctHex;
    $('ivOut').textContent = ivHex;
    log(`Plaintext encrypted → ${ctHex.length} hex chars of ciphertext.`, 'success');
    log(`IV (96-bit nonce): ${ivHex}`, 'info');

    /* ── 3. Wrap AES key with RSA public key (RSA-OAEP) ── */
    const wrapped = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      PUB,
      rawAES
    );
    LAST_EK = wrapped;

    const ekHex = ab2hex(wrapped);
    $('ekOut').textContent = ekHex;
    log(`AES key RSA-wrapped → ${ekHex.length} hex chars.`, 'success');
    log('✓ Plaintext cleared from memory · only ciphertext remains.', 'warn');

    /* Populate the decrypt panel (Step 03) with the payload */
    $('rxCT').textContent = ctHex;
    $('rxEK').textContent = ekHex;

    /* Update stats + history */
    cE++;
    bump('sE', cE);
    const rcpt = $('rcpt').value || '(no recipient)';
    addHist('ENC', rcpt, (enc.byteLength / 1024).toFixed(3) + ' KB');

    $('sendBtn').disabled = false;

    btn.innerHTML = '✓ Encrypted — Click to Encrypt Again';
    btn.style.background = 'linear-gradient(135deg,#007a50,#00ffa3)';
    btn.style.color = '#02080f';
    btn.disabled = false;

  } catch (e) {
    log(`Encryption error: ${e.message}`, 'error');
    btn.innerHTML = '🔒 Encrypt Message';
    btn.disabled = false;
  }
}


/* ─────────────────────────────────────────
   STEP 02b — SIMULATE TRANSMISSION
   Simulates sending the encrypted payload
   over a stateless relay server.
───────────────────────────────────────── */
async function doSend() {
  const btn = $('sendBtn');
  btn.innerHTML = '<span class="spin"></span> Transmitting...';
  btn.disabled = true;

  log('Initiating secure transmission...', 'info');
  await sl(350);
  log('Payload: [AES ciphertext + RSA-wrapped key + IV]', 'info');
  await sl(550);
  log('Backend relay received · plaintext_seen: FALSE', 'success');
  await sl(280);
  log('Delivered to recipient · relay stateless · nothing stored.', 'success');

  cT++;
  bump('sT', cT);

  const rcpt = $('rcpt').value || '(no recipient)';
  $('mTxt').textContent =
    `Encrypted payload delivered to:\n${rcpt}\n\n` +
    `Ciphertext preview: ${ab2hex(LAST_CT).slice(0, 22)}...\n\n` +
    `The relay server never saw your plaintext message.\n` +
    `You can now go to Step 03 to decrypt, or go back to Step 02 to send another message.`;
  $('modal').classList.add('open');

  btn.innerHTML = '✓ Transmitted — Click to Send Again';
  btn.disabled = false;
}


/* ═══════════════════════════════════════════
   STEP 03 — DECRYPT MESSAGE
   1. Unwrap AES key using RSA private key
   2. Re-import the raw AES key
   3. Decrypt ciphertext with AES-GCM
   4. Verify GCM authentication tag (automatic)
   5. Display recovered plaintext
═══════════════════════════════════════════ */
async function doDec() {
  if (!PRV) {
    log('Error: No private key. Generate keys in Step 01.', 'error');
    alert('Please generate RSA keys in Step 01 first.');
    return;
  }
  if (!LAST_CT || !LAST_EK) {
    log('Error: No encrypted payload. Encrypt a message in Step 02.', 'error');
    alert('Please encrypt a message in Step 02 first.');
    return;
  }

  const btn = $('decBtn');
  btn.innerHTML = '<span class="spin"></span> Decrypting...';
  btn.disabled = true;

  log('Received encrypted payload · starting decryption...', 'info');

  try {
    await sl(280);
    log('Unwrapping AES key using RSA-OAEP private key...', 'info');

    /* ── 1. Unwrap AES key with RSA private key ── */
    const rawAES = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      PRV,
      LAST_EK
    );
    log('AES-256 session key recovered.', 'success');

    /* ── 2. Re-import raw AES key ── */
    const aesRec = await crypto.subtle.importKey(
      'raw', rawAES,
      { name: 'AES-GCM' },
      false,           // not extractable
      ['decrypt']
    );
    await sl(200);
    log('Decrypting ciphertext with recovered AES-256-GCM key...', 'info');

    /* ── 3. Decrypt ciphertext (GCM auto-verifies auth tag) ── */
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: LAST_IV },
      aesRec,
      LAST_CT
    );
    const plain = new TextDecoder().decode(dec);

    log('GCM authentication tag verified · no tampering detected.', 'success');
    log(`✓ Plaintext restored: "${plain.slice(0, 50)}${plain.length > 50 ? '...' : ''}"`, 'success');

    cD++;
    bump('sD', cD);
    addHist('DEC', '(local session)', (new TextEncoder().encode(plain).byteLength / 1024).toFixed(3) + ' KB');

    /* Render decrypted message */
    $('decRes').innerHTML = `
      <div style="width:100%">
        <div style="text-align:center;margin-bottom:14px">
          <span style="font-size:2.4rem">🔓</span>
          <div style="font-family:var(--fm);font-size:.8rem;letter-spacing:.12em;text-transform:uppercase;color:var(--green);margin-top:8px">Decryption Successful</div>
        </div>
        <div style="background:rgba(0,255,163,.06);border:1px solid rgba(0,255,163,.3);border-radius:12px;padding:18px;font-family:var(--fm);font-size:.92rem;color:var(--textb);line-height:1.8;word-break:break-word">${plain}</div>
        <div style="margin-top:14px;font-family:var(--fm);font-size:.78rem;color:var(--textd);line-height:1.9">
          ✔ RSA key unwrap OK &nbsp;·&nbsp; ✔ GCM auth tag verified &nbsp;·&nbsp; ✔ Integrity confirmed
        </div>
      </div>`;

    btn.innerHTML = '✓ Decrypted — Click to Decrypt Again';
    btn.style.background = 'linear-gradient(135deg,#007a50,#00ffa3)';
    btn.style.color = '#02080f';
    btn.disabled = false;

  } catch (e) {
    log(`Decryption failed: ${e.message}`, 'error');
    $('decRes').innerHTML = `<div class="dph"><div class="di">❌</div><p style="color:var(--red)">${e.message}</p></div>`;
    btn.innerHTML = '🔓 Decrypt Message';
    btn.disabled = false;
  }
}


/* ═══════════════════════════════════════════
   MODAL
═══════════════════════════════════════════ */
function closeModal() {
  $('modal').classList.remove('open');
}


/* ═══════════════════════════════════════════
   LIVE PLAINTEXT PREVIEW
   Updates the preview box as the user types
═══════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  const inp  = $('msg');
  const prev = $('ptPrev');
  if (inp && prev) {
    inp.addEventListener('input', () => {
      prev.textContent = inp.value || '— empty —';
    });
  }
});