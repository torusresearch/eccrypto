import { concatBytes } from "@noble/curves/abstract/utils";
import { secp256k1 } from "@noble/curves/secp256k1";
// eslint-disable-next-line @typescript-eslint/no-explicit-any, n/no-unsupported-features/node-builtins
const browserCrypto = globalThis.crypto || (globalThis as any).msCrypto || {};
// eslint-disable-next-line @typescript-eslint/no-explicit-any, n/no-unsupported-features/node-builtins
const subtle = (browserCrypto.subtle || (browserCrypto as any).webkitSubtle) as SubtleCrypto;

const EC_GROUP_ORDER = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

export interface Ecies {
  iv: Uint8Array;
  ephemPublicKey: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
}

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}
export function uint8ArrayToBigInt(arr: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < arr.length; i++) {
    result = (result << 8n) | BigInt(arr[i]);
  }
  return result;
}

function isValidPrivateKey(privateKey: Uint8Array): boolean {
  const privateKeyBigInt = uint8ArrayToBigInt(privateKey);
  return (
    privateKeyBigInt > 0n &&
    // > 0
    privateKeyBigInt < EC_GROUP_ORDER
  ); // < G
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1: Uint8Array, b2: Uint8Array): boolean {
  if (b1.length !== b2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i]; // jshint ignore:line
  }

  return res === 0;
}

/* This must check if we're in the browser or
not, since the functions are different and does
not convert using browserify */
function randomBytes(size: number): Uint8Array {
  if (typeof browserCrypto.getRandomValues === "undefined") {
    return browserCrypto.randomBytes(size);
  }
  const arr = new Uint8Array(size);
  browserCrypto.getRandomValues(arr);
  return arr;
}

async function sha512(msg: Uint8Array): Promise<Uint8Array> {
  if (!browserCrypto.createHash) {
    const hash = await subtle.digest("SHA-512", msg);
    const result = new Uint8Array(hash);
    return result;
  }
  const hash = browserCrypto.createHash("sha512");
  const result = hash.update(msg).digest();
  return new Uint8Array(result);
}

type AesFunctionType = (iv: Uint8Array, key: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;

function getAes(op: "encrypt" | "decrypt"): AesFunctionType {
  return async function (iv: Uint8Array, key: Uint8Array, data: Uint8Array) {
    if (subtle && subtle[op] && subtle.importKey) {
      const importAlgorithm = {
        name: "AES-CBC",
      };
      const cryptoKey = await subtle.importKey("raw", key, importAlgorithm, false, [op]);
      const encAlgorithm = {
        name: "AES-CBC",
        iv,
      };
      // encrypt and decrypt ops are not implemented in react-native-quick-crypto yet.
      const result = await subtle[op](encAlgorithm, cryptoKey, data);
      return new Uint8Array(result);
    } else if (op === "encrypt" && browserCrypto.createCipheriv) {
      // This is available if crypto is polyfilled in react native environment
      const cipher = browserCrypto.createCipheriv("aes-256-cbc", key, iv);
      const firstChunk = cipher.update(data);
      const secondChunk = cipher.final();

      return concatBytes(firstChunk, secondChunk);
    } else if (op === "decrypt" && browserCrypto.createDecipheriv) {
      const decipher = browserCrypto.createDecipheriv("aes-256-cbc", key, iv);
      const firstChunk = decipher.update(data);
      const secondChunk = decipher.final();
      return concatBytes(firstChunk, secondChunk);
    }
    throw new Error(`Unsupported operation: ${op}`);
  };
}
const aesCbcEncrypt = getAes("encrypt");
const aesCbcDecrypt = getAes("decrypt");

async function hmacSha256Sign(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  if (!browserCrypto.createHmac) {
    const importAlgorithm = {
      name: "HMAC",
      hash: {
        name: "SHA-256",
      },
    };
    const cryptoKey = await subtle.importKey("raw", new Uint8Array(key), importAlgorithm, false, ["sign", "verify"]);
    const sig = await subtle.sign("HMAC", cryptoKey, msg);
    const result = new Uint8Array(sig);
    return result;
  }
  const hmac = browserCrypto.createHmac("sha256", key);
  hmac.update(msg);
  const result = hmac.digest();
  return result;
}
async function hmacSha256Verify(key: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const expectedSig = await hmacSha256Sign(key, msg);
  return equalConstTime(expectedSig, sig);
}

/**
 * Generate a new valid private key. Will use the window.crypto or window.msCrypto as source
 * depending on your browser.
 */
export const generatePrivate = function (): Uint8Array {
  let privateKey = randomBytes(32);
  while (!isValidPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
};

export const getPublic = function (privateKey: Uint8Array): Uint8Array {
  // This function has sync API so we throw an error immediately.
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  // XXX(Kagami): `elliptic.utils.encode` returns array for every
  // encoding except `hex`.
  return secp256k1.getPublicKey(privateKey, false);
};

/**
 * Get compressed version of public key.
 */
export const getPublicCompressed = function (privateKey: Uint8Array): Uint8Array {
  // jshint ignore:line
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  // See https://github.com/wanderer/secp256k1-node/issues/46
  const compressed = true;
  return secp256k1.getPublicKey(privateKey, compressed);
};

// NOTE(Kagami): We don't use promise shim in Browser implementation
// because it's supported natively in new browsers (see
// <http://caniuse.com/#feat=promises>) and we can use only new browsers
// because of the WebCryptoAPI (see
// <http://caniuse.com/#feat=cryptography>).
export const sign = async function (privateKey: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  return secp256k1.sign(msg, privateKey).toDERRawBytes();
};

export const verify = async function (publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<null> {
  assert(publicKey.length === 65 || publicKey.length === 33, "Bad public key");
  if (publicKey.length === 65) {
    assert(publicKey[0] === 4, "Bad public key");
  }
  if (publicKey.length === 33) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, "Bad public key");
  }
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  if (secp256k1.verify(sig, msg, publicKey)) return null;
  throw new Error("Bad signature");
};

export const derive = async function (privateKeyA: Uint8Array, publicKeyB: Uint8Array): Promise<Uint8Array> {
  // assert(Buffer.isBuffer(privateKeyA), "Bad private key");
  // assert(Buffer.isBuffer(publicKeyB), "Bad public key");
  assert(privateKeyA.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKeyA), "Bad private key");
  assert(publicKeyB.length === 65 || publicKeyB.length === 33, "Bad public key");
  if (publicKeyB.length === 65) {
    assert(publicKeyB[0] === 4, "Bad public key");
  }
  if (publicKeyB.length === 33) {
    assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
  }

  // unpad to match previous implementation
  // elliptic return BN and we return Buffer(BN.toArray())
  // match by unpadding
  const sharedSecret = secp256k1.getSharedSecret(privateKeyA, publicKeyB);
  const Px = sharedSecret.subarray(sharedSecret.length - 32);

  let i = 0;
  while (i < Px.length && Px[i] === 0) {
    i++;
  }

  return Px.subarray(i);
};

export const deriveUnpadded = derive;

export const derivePadded = async function (privateKeyA: Uint8Array, publicKeyB: Uint8Array): Promise<Uint8Array> {
  // assert(Buffer.isBuffer(privateKeyA), "Bad private key");
  // assert(Buffer.isBuffer(publicKeyB), "Bad public key");
  assert(privateKeyA.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKeyA), "Bad private key");
  assert(publicKeyB.length === 65 || publicKeyB.length === 33, "Bad public key");
  if (publicKeyB.length === 65) {
    assert(publicKeyB[0] === 4, "Bad public key");
  }
  if (publicKeyB.length === 33) {
    assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
  }
  const Px = secp256k1.getSharedSecret(privateKeyA, publicKeyB);
  return Px.subarray(Px.length - 32);
};

export const encrypt = async function (
  publicKeyTo: Uint8Array,
  msg: Uint8Array,
  opts?: { iv?: Uint8Array; ephemPrivateKey?: Uint8Array }
): Promise<Ecies> {
  opts = opts || {};

  let ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  // There is a very unlikely possibility that it is not a valid key
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  }
  const ephemPublicKey = getPublic(ephemPrivateKey);
  const Px = await deriveUnpadded(ephemPrivateKey, publicKeyTo);
  const hash = await sha512(Px);
  const iv = opts.iv || randomBytes(16);
  const encryptionKey = hash.slice(0, 32);
  const macKey = hash.slice(32);
  const data = await aesCbcEncrypt(iv, encryptionKey, msg);
  const ciphertext = data;
  const dataToMac = concatBytes(iv, ephemPublicKey, ciphertext);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return {
    iv,
    ephemPublicKey,
    ciphertext,
    mac,
  };
};

export const decrypt = async function (privateKey: Uint8Array, opts: Ecies, _padding?: boolean): Promise<Uint8Array> {
  const padding = _padding ?? false;
  const deriveLocal = padding ? derivePadded : deriveUnpadded;
  const Px = await deriveLocal(privateKey, opts.ephemPublicKey);
  const hash = await sha512(Px);
  const encryptionKey = hash.slice(0, 32);
  const macKey = hash.slice(32);
  const dataToMac = concatBytes(opts.iv, opts.ephemPublicKey, opts.ciphertext);
  const macGood = await hmacSha256Verify(macKey, dataToMac, opts.mac);
  if (!macGood && padding === false) {
    return decrypt(privateKey, opts, true);
  } else if (!macGood && padding === true) {
    throw new Error("bad MAC after trying padded");
  }
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return new Uint8Array(msg);
};
