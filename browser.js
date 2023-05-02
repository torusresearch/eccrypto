"use strict";

const EC = require("elliptic").ec;
const ec = new EC("secp256k1");
const browserCrypto = global.crypto || global.msCrypto || {};
const subtle = browserCrypto.subtle || browserCrypto.webkitSubtle;
const nodeCrypto = require("crypto");
const EC_GROUP_ORDER = Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex");
const ZERO32 = Buffer.alloc(32, 0);
function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}
function isScalar(x) {
  return Buffer.isBuffer(x) && x.length === 32;
}
function isValidPrivateKey(privateKey) {
  if (!isScalar(privateKey)) {
    return false;
  }
  return (
    privateKey.compare(ZERO32) > 0 &&
    // > 0
    privateKey.compare(EC_GROUP_ORDER) < 0
  ); // < G
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
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
function randomBytes(size) {
  const arr = new Uint8Array(size);
  if (typeof browserCrypto.getRandomValues === "undefined") {
    return Buffer.from(nodeCrypto.randomBytes(size));
  } else {
    browserCrypto.getRandomValues(arr);
  }
  return Buffer.from(arr);
}

async function sha512(msg) {
  if (subtle) {
    const hash = await subtle.digest("SHA-512", msg);
    const result = new Uint8Array(hash);
    return result;
  }
  const hash = nodeCrypto.createHash("sha512");
  const result = hash.update(msg).digest();
  return new Uint8Array(result);
}

function getAes(op) {
  return async function (iv, key, data) {
    if (subtle) {
      const importAlgorithm = {
        name: "AES-CBC",
      };
      const cryptoKey = await subtle.importKey("raw", key, importAlgorithm, false, [op]);
      const encAlgorithm = {
        name: "AES-CBC",
        iv: iv,
      };
      const result = await subtle[op](encAlgorithm, cryptoKey, data);
      return Buffer.from(new Uint8Array(result));
    } else if (op === "encrypt") {
      const cipher = nodeCrypto.createCipheriv("aes-256-cbc", key, iv);
      let firstChunk = cipher.update(data);
      let secondChunk = cipher.final();
      return Buffer.concat([firstChunk, secondChunk]);
    } else if (op === "decrypt") {
      const decipher = nodeCrypto.createDecipheriv("aes-256-cbc", key, iv);
      let firstChunk = decipher.update(data);
      let secondChunk = decipher.final();
      return Buffer.concat([firstChunk, secondChunk]);
    }
  };
}
const aesCbcEncrypt = getAes("encrypt");
const aesCbcDecrypt = getAes("decrypt");

async function hmacSha256Sign(key, msg) {
  if (subtle) {
    const importAlgorithm = {
      name: "HMAC",
      hash: {
        name: "SHA-256",
      },
    };
    const cryptoKey = await subtle.importKey("raw", new Uint8Array(key), importAlgorithm, false, ["sign", "verify"]);
    const sig = await subtle.sign("HMAC", cryptoKey, msg);
    const result = Buffer.from(new Uint8Array(sig));
    return result;
  }
  const hmac = nodeCrypto.createHmac("sha256", Buffer.from(key));
  hmac.update(msg);
  const result = hmac.digest();
  return result;
}
async function hmacSha256Verify(key, msg, sig) {
  const expectedSig = await hmacSha256Sign(key, msg);
  return equalConstTime(expectedSig, sig);
}

/**
 * Generate a new valid private key. Will use the window.crypto or window.msCrypto as source
 * depending on your browser.
 * @return {Buffer} A 32-byte private key.
 * @function
 */
exports.generatePrivate = function () {
  let privateKey = randomBytes(32);
  while (!isValidPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
};

const getPublic = (exports.getPublic = function (privateKey) {
  // This function has sync API so we throw an error immediately.
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  // XXX(Kagami): `elliptic.utils.encode` returns array for every
  // encoding except `hex`.
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic("arr"));
});

/**
 * Get compressed version of public key.
 */
exports.getPublicCompressed = function (privateKey) {
  // jshint ignore:line
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  // See https://github.com/wanderer/secp256k1-node/issues/46
  let compressed = true;
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, "arr"));
};

// NOTE(Kagami): We don't use promise shim in Browser implementation
// because it's supported natively in new browsers (see
// <http://caniuse.com/#feat=promises>) and we can use only new browsers
// because of the WebCryptoAPI (see
// <http://caniuse.com/#feat=cryptography>).
exports.sign = async function (privateKey, msg) {
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  return Buffer.from(
    ec
      .sign(msg, privateKey, {
        canonical: true,
      })
      .toDER()
  );
};
exports.verify = async function (publicKey, msg, sig) {
  assert(publicKey.length === 65 || publicKey.length === 33, "Bad public key");
  if (publicKey.length === 65) {
    assert(publicKey[0] === 4, "Bad public key");
  }
  if (publicKey.length === 33) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, "Bad public key");
  }
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  if (ec.verify(msg, sig, publicKey)) {
    return null;
  } else {
    throw new Error("Bad signature");
  }
};

const deriveUnpadded = (exports.derive = async function (privateKeyA, publicKeyB) {
  assert(Buffer.isBuffer(privateKeyA), "Bad private key");
  assert(Buffer.isBuffer(publicKeyB), "Bad public key");
  assert(privateKeyA.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKeyA), "Bad private key");
  assert(publicKeyB.length === 65 || publicKeyB.length === 33, "Bad public key");
  if (publicKeyB.length === 65) {
    assert(publicKeyB[0] === 4, "Bad public key");
  }
  if (publicKeyB.length === 33) {
    assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
  }
  const keyA = ec.keyFromPrivate(privateKeyA);
  const keyB = ec.keyFromPublic(publicKeyB);
  const Px = keyA.derive(keyB.getPublic()); // BN instance
  return Buffer.from(Px.toArray());
});

const derivePadded = (exports.derivePadded = async function (privateKeyA, publicKeyB) {
  assert(Buffer.isBuffer(privateKeyA), "Bad private key");
  assert(Buffer.isBuffer(publicKeyB), "Bad public key");
  assert(privateKeyA.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKeyA), "Bad private key");
  assert(publicKeyB.length === 65 || publicKeyB.length === 33, "Bad public key");
  if (publicKeyB.length === 65) {
    assert(publicKeyB[0] === 4, "Bad public key");
  }
  if (publicKeyB.length === 33) {
    assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
  }
  const keyA = ec.keyFromPrivate(privateKeyA);
  const keyB = ec.keyFromPublic(publicKeyB);
  const Px = keyA.derive(keyB.getPublic()); // BN instance
  return Buffer.from(Px.toString(16, 64), "hex");
});

exports.encrypt = async function (publicKeyTo, msg, opts) {
  opts = opts || {};
  // Tmp variables to save context from flat promises;
  let iv, ephemPublicKey, ciphertext, macKey;

  let ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  // There is a very unlikely possibility that it is not a valid key
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  }
  ephemPublicKey = getPublic(ephemPrivateKey);
  const Px = await deriveUnpadded(ephemPrivateKey, publicKeyTo);
  const hash = await sha512(Px);
  iv = opts.iv || randomBytes(16);
  const encryptionKey = hash.slice(0, 32);
  macKey = hash.slice(32);
  const data = await aesCbcEncrypt(iv, encryptionKey, msg);
  ciphertext = data;
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return {
    iv: iv,
    ephemPublicKey: ephemPublicKey,
    ciphertext: ciphertext,
    mac: mac,
  };
};

const decrypt = async function (privateKey, opts) {
  let padding = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;
  // Tmp variable to save context from flat promises;
  let encryptionKey;
  const derive = padding ? derivePadded : deriveUnpadded;
  const Px = await derive(privateKey, opts.ephemPublicKey);
  const hash = await sha512(Px);
  encryptionKey = hash.slice(0, 32);
  const macKey = hash.slice(32);
  const dataToMac = Buffer.concat([opts.iv, opts.ephemPublicKey, opts.ciphertext]);
  const macGood = await hmacSha256Verify(macKey, dataToMac, opts.mac);
  if (!macGood && padding === false) {
    return decrypt(privateKey, opts, true);
  } else if (!macGood && padding === true) {
    throw new Error("bad MAC after trying padded");
  }
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return Buffer.from(new Uint8Array(msg));
};

exports.decrypt = decrypt;
