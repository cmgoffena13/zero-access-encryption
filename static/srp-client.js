/**
 * SRP-6a client matching Python package `srp` (SHA1, NG_2048) — see srp._pysrp.
 */
const NG2048_N_HEX =
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4" +
  "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60" +
  "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF" +
  "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907" +
  "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861" +
  "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB" +
  "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

export const NG2048_N = BigInt(`0x${NG2048_N_HEX}`);
const G = 2n;

function concatUint8Arrays(parts) {
  const len = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function longToBytes(n) {
  if (typeof n === "number") n = BigInt(n);
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

export function bytesToLong(u8) {
  let n = 0n;
  for (const b of u8) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

async function sha1Raw(data) {
  const buf =
    data.buffer instanceof ArrayBuffer
      ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
      : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-1", buf));
}

/** Python `H`: SHA1 of concatenated parts (ints → minimal long_to_bytes). */
async function HConcat(parts) {
  const chunks = [];
  for (const s of parts) {
    if (s === null || s === undefined) continue;
    const data = typeof s === "bigint" ? longToBytes(s) : s;
    chunks.push(data);
  }
  return sha1Raw(concatUint8Arrays(chunks));
}

async function HNxorg(N, g) {
  const binN = longToBytes(N);
  const binG = longToBytes(g);
  const padding = 0;
  const hN = await sha1Raw(binN);
  const padG = new Uint8Array(padding + binG.length);
  padG.set(binG, padding);
  const hg = await sha1Raw(padG);
  const out = new Uint8Array(hN.length);
  for (let i = 0; i < hN.length; i++) {
    out[i] = hN[i] ^ hg[i];
  }
  return out;
}

async function calculateM(N, g, I, sBytes, A, B, K) {
  const enc = new TextEncoder();
  const Ibytes = typeof I === "string" ? enc.encode(I) : I;
  const hnx = await HNxorg(N, g);
  const hI = await sha1Raw(Ibytes);
  const parts = [
    hnx,
    hI,
    sBytes instanceof Uint8Array ? sBytes : longToBytes(sBytes),
    longToBytes(A),
    longToBytes(B),
    K,
  ];
  return sha1Raw(concatUint8Arrays(parts));
}

async function calculateHAMK(A, M, K) {
  return HConcat([longToBytes(A), M, K]);
}

function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  let b = base;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function getRandomBytes(n) {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
}

function getRandom(nbytes) {
  return bytesToLong(getRandomBytes(nbytes));
}

function getRandomOfLength(nbytes) {
  let n = getRandom(nbytes);
  const offset = BigInt(nbytes * 8 - 1);
  n |= 1n << offset;
  return n;
}

async function genX(salt, username, password) {
  const enc = new TextEncoder();
  const inner = enc.encode(`${username}:${password}`);
  const innerHash = await sha1Raw(inner);
  const xBytes = await HConcat([salt, innerHash]);
  return bytesToLong(xBytes);
}

async function computeK(N, g) {
  return bytesToLong(await HConcat([N, g]));
}

/** Registration: same as `srp.create_salted_verification_key` defaults. */
export async function createSaltedVerificationKey(username, password) {
  const N = NG2048_N;
  const salt = getRandomBytes(4);
  const x = await genX(salt, username, password);
  const v = modPow(G, x, N);
  return { salt, verifier: longToBytes(v) };
}

export class SrpUser {
  /**
   * @param {{ I: string, p: string, N: bigint, g: bigint, k: bigint, a: bigint, A: bigint }} state
   */
  constructor(state) {
    Object.assign(this, state);
    this.M = null;
    this.K = null;
    this.H_AMK = null;
  }

  static async create(username, password) {
    const N = NG2048_N;
    const g = G;
    const k = await computeK(N, g);
    const a = getRandomOfLength(256);
    const A = modPow(g, a, N);
    return new SrpUser({ I: username, p: password, N, g, k, a, A });
  }

  /** @returns {{ I: string, A: Uint8Array }} */
  startAuthentication() {
    return { I: this.I, A: longToBytes(this.A) };
  }

  /** @returns {Promise<Uint8Array | null>} M (client proof) */
  async processChallenge(bytes_s, bytes_B) {
    const B = bytesToLong(bytes_B);
    const { N, g, k } = this;
    if (B % N === 0n) return null;

    const u = bytesToLong(await HConcat([this.A, B]));
    if (u === 0n) return null;

    const x = await genX(bytes_s, this.I, this.p);
    const v = modPow(g, x, N);
    let base = (B - k * v) % N;
    if (base < 0n) base += N;
    const exp = this.a + u * x;
    const S = modPow(base, exp, N);
    const K = await sha1Raw(longToBytes(S));
    const M = await calculateM(N, g, this.I, bytes_s, this.A, B, K);
    this.M = M;
    this.K = K;
    this.H_AMK = await calculateHAMK(this.A, M, K);
    return M;
  }
}
