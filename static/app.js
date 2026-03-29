import { createSaltedVerificationKey, SrpUser } from "./srp-client.js";

function byId(id) {
  return document.getElementById(id);
}

function bytesToBase64(bytes) {
  let string = "";
  for (let i = 0; i < bytes.length; i++) {
    string += String.fromCharCode(bytes[i]);
  }
  return btoa(string);
}

function base64ToBytes(base64String) {
  const binaryString = atob(base64String);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function log(message, isError = false) {
  const logElement = byId("log");
  const line = document.createElement("div");
  line.className = isError ? "err" : "";
  line.textContent = message;
  logElement.prepend(line);
}

function showMessageDialog(title, body, { isError = false } = {}) {
  const dialog = byId("message-dialog");
  byId("message-dialog-title").textContent = title;
  byId("message-dialog-body").textContent = body;
  dialog.classList.toggle("message-dialog--error", isError);
  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  }
}

byId("message-dialog-close").addEventListener("click", () => {
  byId("message-dialog").close();
});

async function deriveDataKey(password, salt) {
  const textEncoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
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

async function encryptData(plaintext, password, salt) {
  const key = await deriveDataKey(password, salt);
  const initializationVector = crypto.getRandomValues(new Uint8Array(12));
  const textEncoder = new TextEncoder();
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: initializationVector },
    key,
    textEncoder.encode(plaintext)
  );
  const ciphertextBytes = new Uint8Array(ciphertextBuffer);
  const encryptedBlob = new Uint8Array(
    1 + initializationVector.length + ciphertextBytes.length
  );
  encryptedBlob[0] = 1;
  encryptedBlob.set(initializationVector, 1);
  encryptedBlob.set(ciphertextBytes, 1 + initializationVector.length);
  return encryptedBlob;
}

async function decryptData(encryptedBlob, password, salt) {
  if (encryptedBlob[0] !== 1) {
    throw new Error("Unknown encrypted blob format");
  }
  const initializationVector = encryptedBlob.subarray(1, 13);
  const ciphertext = encryptedBlob.subarray(13);
  const key = await deriveDataKey(password, salt);
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: initializationVector },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decryptedBuffer);
}

function readSession() {
  const raw = sessionStorage.getItem("zae");
  return raw ? JSON.parse(raw) : {};
}

function saveSession(partial) {
  const current = readSession();
  const updated = { ...current };
  for (const [key, value] of Object.entries(partial)) {
    if (value !== undefined) updated[key] = value;
  }
  sessionStorage.setItem("zae", JSON.stringify(updated));
}

function encryptionPassword() {
  return (
    byId("login-password")?.value || byId("register-password")?.value || ""
  );
}

byId("register-submit").addEventListener("click", async () => {
  const username = byId("register-username").value.trim();
  const password = byId("register-password").value;
  if (!username || !password) {
    const message = "Enter both username and password.";
    log(message, true);
    showMessageDialog("Register", message, { isError: true });
    return;
  }
  try {
    const { salt, verifier } = await createSaltedVerificationKey(
      username,
      password
    );
    const response = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        salt: bytesToBase64(salt),
        verifier: bytesToBase64(verifier),
      }),
    });
    if (!response.ok) {
      const detail = await response.text();
      const message = `Could not register (${response.status}). ${detail}`;
      log(message, true);
      showMessageDialog("Registration failed", message, { isError: true });
      return;
    }
    const { user_id, access_token } = await response.json();
    saveSession({
      user_id,
      username,
      salt_b64: bytesToBase64(salt),
      access_token,
    });
    const successMessage =
      `You are registered. User id: ${user_id}.\nSalt is stored in this tab for client-side encryption.`;
    log(`Registered. (salt stored locally for client-side encryption).`);
    showMessageDialog("Registered", successMessage);
  } catch (error) {
    const message = String(error);
    log(message, true);
    showMessageDialog("Registration failed", message, { isError: true });
  }
});

byId("login-submit").addEventListener("click", async () => {
  const username = byId("login-username").value.trim();
  const password = byId("login-password").value;
  if (!username || !password) {
    const message = "Enter both username and password.";
    log(message, true);
    showMessageDialog("Login", message, { isError: true });
    return;
  }
  try {
    const srpUser = await SrpUser.create(username, password);
    const { A } = srpUser.startAuthentication();
    const challengeResponse = await fetch("/srp/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        A: bytesToBase64(A),
      }),
    });
    if (!challengeResponse.ok) {
      const detail = await challengeResponse.text();
      const message = `Challenge step failed (${challengeResponse.status}). ${detail}`;
      log(message, true);
      showMessageDialog("Login failed", message, { isError: true });
      return;
    }
    const {
      s: saltBase64,
      B: serverEphemeralBase64,
      session_id: sessionId,
    } = await challengeResponse.json();
    const clientProof = await srpUser.processChallenge(
      base64ToBytes(saltBase64),
      base64ToBytes(serverEphemeralBase64)
    );
    if (!clientProof) {
      const message = "SRP client proof could not be computed (safety check).";
      log(message, true);
      showMessageDialog("Login failed", message, { isError: true });
      return;
    }
    const verifyResponse = await fetch("/srp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        username,
        M: bytesToBase64(clientProof),
      }),
    });
    if (!verifyResponse.ok) {
      const detail = await verifyResponse.text();
      const message = `Verify step failed (${verifyResponse.status}). ${detail}`;
      log(message, true);
      showMessageDialog("Login failed", message, { isError: true });
      return;
    }
    const verifyBody = await verifyResponse.json();
    const {
      HAMK,
      user_id,
      salt: saltFromServer,
      access_token: accessToken,
    } = verifyBody;
    if (
      user_id == null ||
      !saltFromServer ||
      HAMK == null ||
      accessToken == null
    ) {
      const message = `Unexpected response from server: ${JSON.stringify(verifyBody)}`;
      log(message, true);
      showMessageDialog("Login failed", message, { isError: true });
      return;
    }
    const saltB64 =
      typeof saltFromServer === "string"
        ? saltFromServer
        : bytesToBase64(saltFromServer);
    saveSession({
      user_id,
      username,
      salt_b64: saltB64,
      access_token: accessToken,
    });
    log(
      `SRP OK. Session saved (user_id=${user_id}). HAMK: ${String(HAMK).slice(0, 16)}…`
    );
    const successMessage = `You are logged in.\nUser id: ${user_id}. Session data saved in this tab for encrypting data.`;
    showMessageDialog("Logged in", successMessage);
  } catch (error) {
    const message = String(error);
    log(message, true);
    showMessageDialog("Login failed", message, { isError: true });
  }
});

byId("upload-submit").addEventListener("click", async () => {
  const sessionData = readSession();
  const userId = sessionData.user_id;
  const salt = sessionData.salt_b64
    ? base64ToBytes(sessionData.salt_b64)
    : null;
  const password = encryptionPassword();
  const plaintext = byId("data-input").value;
  if (userId == null || !salt) {
    log("Register or complete SRP login first (session needs user id + salt).", true);
    return;
  }
  if (!sessionData.access_token) {
    log("No access token — register or log in again.", true);
    return;
  }
  if (!password) {
    log(
      "Enter your password in Register or SRP login (used to encrypt this data).",
      true
    );
    return;
  }
  try {
    const encryptedBlob = await encryptData(plaintext, password, salt);
    const uploadResponse = await fetch("/data/upload", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${sessionData.access_token}`,
      },
      body: JSON.stringify({
        blob: bytesToBase64(encryptedBlob),
      }),
    });
    if (!uploadResponse.ok) {
      log(
        `Upload failed: ${uploadResponse.status} ${await uploadResponse.text()}`,
        true
      );
      return;
    }
    log("Uploaded ciphertext (server cannot decrypt).");
  } catch (error) {
    log(String(error), true);
  }
});

byId("download-submit").addEventListener("click", async () => {
  const sessionData = readSession();
  const userId = sessionData.user_id;
  const salt = sessionData.salt_b64
    ? base64ToBytes(sessionData.salt_b64)
    : null;
  const password = encryptionPassword();
  if (userId == null || !salt) {
    log("Register or complete SRP login first (session needs user id + salt).", true);
    return;
  }
  if (!sessionData.access_token) {
    log("No access token — register or log in again.", true);
    return;
  }
  if (!password) {
    log(
      "Enter your password in Register or SRP login (used to decrypt this data).",
      true
    );
    return;
  }
  try {
    const downloadResponse = await fetch(`/data/${userId}`, {
      headers: {
        Authorization: `Bearer ${sessionData.access_token}`,
      },
    });
    if (!downloadResponse.ok) {
      log(`Download failed: ${downloadResponse.status}`, true);
      return;
    }
    const { blob: blobBase64 } = await downloadResponse.json();
    const decryptedText = await decryptData(
      base64ToBytes(blobBase64),
      password,
      salt
    );
    byId("data-output").textContent = decryptedText;
    log("Decrypted in browser only.");
  } catch (error) {
    log(String(error), true);
  }
});
