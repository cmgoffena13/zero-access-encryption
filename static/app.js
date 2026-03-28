import { createSaltedVerificationKey, SrpUser } from "./srp-client.js";

const $ = (id) => document.getElementById(id);

function bytesToBase64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function log(msg, err = false) {
  const el = $("log");
  const line = document.createElement("div");
  line.className = err ? "err" : "";
  line.textContent = msg;
  el.prepend(line);
}

async function deriveVaultKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(plaintext, password, salt) {
  const key = await deriveVaultKey(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  const u8 = new Uint8Array(ct);
  const out = new Uint8Array(1 + iv.length + u8.length);
  out[0] = 1;
  out.set(iv, 1);
  out.set(u8, 1 + iv.length);
  return out;
}

async function decryptVault(blob, password, salt) {
  if (blob[0] !== 1) throw new Error("Unknown vault format");
  const iv = blob.subarray(1, 13);
  const ct = blob.subarray(13);
  const key = await deriveVaultKey(password, salt);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt);
}

function session() {
  const raw = sessionStorage.getItem("zae");
  return raw ? JSON.parse(raw) : {};
}

function saveSession(data) {
  const cur = session();
  const next = { ...cur };
  for (const [k, v] of Object.entries(data)) {
    if (v !== undefined) next[k] = v;
  }
  sessionStorage.setItem("zae", JSON.stringify(next));
}

/** Vault uses the same password as SRP; allow login field when vault field is empty. */
function vaultPassword() {
  const v = $("vaultPass").value;
  if (v) return v;
  return $("loginPass").value || $("regPass").value;
}

$("btnRegister").addEventListener("click", async () => {
  const username = $("regUser").value.trim();
  const password = $("regPass").value;
  if (!username || !password) {
    log("Username and password required.", true);
    return;
  }
  try {
    const { salt, verifier } = await createSaltedVerificationKey(username, password);
    const res = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        salt: bytesToBase64(salt),
        verifier: bytesToBase64(verifier),
      }),
    });
    if (!res.ok) {
      log(`Register failed: ${res.status} ${await res.text()}`, true);
      return;
    }
    const { user_id } = await res.json();
    saveSession({
      user_id,
      username,
      salt_b64: bytesToBase64(salt),
    });
    $("vaultPass").value = password;
    log(`Registered. user_id=${user_id} (salt stored locally for vault crypto).`);
  } catch (e) {
    log(String(e), true);
  }
});

$("btnLogin").addEventListener("click", async () => {
  const username = $("loginUser").value.trim();
  const password = $("loginPass").value;
  if (!username || !password) {
    log("Username and password required.", true);
    return;
  }
  try {
    const usr = await SrpUser.create(username, password);
    const { A } = usr.startAuthentication();
    const ch = await fetch("/srp/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        A: bytesToBase64(A),
      }),
    });
    if (!ch.ok) {
      log(`Challenge failed: ${ch.status} ${await ch.text()}`, true);
      return;
    }
    const { s: sb64, B: bb64 } = await ch.json();
    const M = await usr.processChallenge(base64ToBytes(sb64), base64ToBytes(bb64));
    if (!M) {
      log("SRP process_challenge failed (safety check).", true);
      return;
    }
    const vf = await fetch("/srp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        M: bytesToBase64(M),
      }),
    });
    if (!vf.ok) {
      log(`Verify failed: ${vf.status} ${await vf.text()}`, true);
      return;
    }
    const body = await vf.json();
    const { HAMK, user_id, salt: saltB64 } = body;
    if (user_id == null || !saltB64 || HAMK == null) {
      log(
        `SRP verify response missing fields (reload app / rebuild API?). ${JSON.stringify(body)}`,
        true
      );
      return;
    }
    saveSession({
      user_id,
      username,
      salt_b64: saltB64,
    });
    $("vaultPass").value = password;
    log(
      `SRP OK. Session saved for vault (user_id=${user_id}). HAMK: ${String(HAMK).slice(0, 16)}…`
    );
  } catch (e) {
    log(String(e), true);
  }
});

$("btnUpload").addEventListener("click", async () => {
  const s = session();
  const user_id = s.user_id;
  const salt = s.salt_b64 ? base64ToBytes(s.salt_b64) : null;
  const password = vaultPassword();
  const note = $("vaultNote").value;
  if (user_id == null || !salt) {
    log("Register or complete SRP login first (session needs user id + salt).", true);
    return;
  }
  if (!password) {
    log("Enter vault password (same as your account password), or use login/register password fields.", true);
    return;
  }
  try {
    const blob = await encryptVault(note, password, salt);
    const res = await fetch("/data/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_id,
        blob: bytesToBase64(blob),
      }),
    });
    if (!res.ok) {
      log(`Upload failed: ${res.status} ${await res.text()}`, true);
      return;
    }
    log("Uploaded ciphertext (server cannot decrypt).");
  } catch (e) {
    log(String(e), true);
  }
});

$("btnDownload").addEventListener("click", async () => {
  const s = session();
  const user_id = s.user_id;
  const salt = s.salt_b64 ? base64ToBytes(s.salt_b64) : null;
  const password = vaultPassword();
  if (user_id == null || !salt) {
    log("Register or complete SRP login first (session needs user id + salt).", true);
    return;
  }
  if (!password) {
    log("Enter vault password or use login/register password field.", true);
    return;
  }
  try {
    const res = await fetch(`/data/${user_id}`);
    if (!res.ok) {
      log(`Download failed: ${res.status}`, true);
      return;
    }
    const { blob: b64 } = await res.json();
    const plain = await decryptVault(base64ToBytes(b64), password, salt);
    $("vaultOut").textContent = plain;
    log("Decrypted in browser only.");
  } catch (e) {
    log(String(e), true);
  }
});
