import { cbc } from "@noble/ciphers/aes";
import { hmac } from "@noble/hashes/hmac";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { getPublicKey, getSharedSecret, utils } from "@noble/secp256k1";

import { Ecies } from ".";

export interface NobleEcies {
  iv: Uint8Array;
  ephemPublicKey: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
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

export const NobleEciesToEcies = (nobleEcies: NobleEcies): Ecies => {
  return {
    iv: Buffer.from(nobleEcies.iv),
    ciphertext: Buffer.from(nobleEcies.ciphertext),
    mac: Buffer.from(nobleEcies.mac),
    ephemPublicKey: Buffer.from(nobleEcies.ephemPublicKey),
  };
};

export const EciesToNobleEcies = (ecies: Ecies): NobleEcies => {
  return {
    iv: new Uint8Array(ecies.iv),
    ephemPublicKey: new Uint8Array(ecies.ephemPublicKey),
    ciphertext: new Uint8Array(ecies.ciphertext),
    mac: new Uint8Array(ecies.mac),
  };
};

export const hmacSha256Sign = (key: Uint8Array, msg: Uint8Array) => {
  const mac = hmac(sha256, key, msg);
  return mac;
};

export function hmacSha256Verify(key: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const expectedSig = hmacSha256Sign(key, msg);
  return equalConstTime(expectedSig, sig);
}

export const nobleEncrypt = async function (
  publicKeyTo: Uint8Array,
  msg: Uint8Array,
  opts?: { iv?: Uint8Array; ephemPrivateKey?: Uint8Array }
): Promise<NobleEcies> {
  const ephemPrivateKey = opts?.ephemPrivateKey || utils.randomPrivateKey();
  const ephemPublicKey = getPublicKey(ephemPrivateKey, false);

  const sharedSecret = getSharedSecret(ephemPrivateKey, publicKeyTo);

  // need to remove first byte
  const sharedSecretSliced = sharedSecret.slice(1);

  const hash = sha512(sharedSecretSliced);
  const key = hash.slice(0, 32);
  const macKey = hash.slice(32);

  const iv = opts?.iv || utils.randomPrivateKey().slice(0, 16);
  const cipher = cbc(key, iv);

  const cipherText = cipher.encrypt(msg);

  const dataToMac = new Uint8Array(iv.length + ephemPublicKey.length + cipherText.length);
  dataToMac.set(iv, 0);
  dataToMac.set(ephemPublicKey, iv.length);
  dataToMac.set(cipherText, iv.length + ephemPublicKey.length);
  const mac = hmacSha256Sign(Buffer.from(macKey), dataToMac);

  return {
    iv,
    ephemPublicKey,
    ciphertext: cipherText,
    mac,
  };
};

export const nobleDecrypt = async function (privateKey: Uint8Array, opts: NobleEcies, padding?: boolean): Promise<Uint8Array> {
  const { iv, ephemPublicKey, ciphertext, mac } = opts;
  const sharedSecret = getSharedSecret(privateKey, ephemPublicKey);
  // need to remove first byte
  const sharedSecretSliced = sharedSecret.slice(1);

  const hash = sha512(sharedSecretSliced);
  const key = hash.slice(0, 32);
  const macKey = hash.slice(32);

  const dataToMac = new Uint8Array(iv.length + ephemPublicKey.length + ciphertext.length);
  dataToMac.set(iv, 0);
  dataToMac.set(ephemPublicKey, iv.length);
  dataToMac.set(ciphertext, iv.length + ephemPublicKey.length);
  const macGood = hmacSha256Verify(macKey, dataToMac, mac);

  if (!macGood && !padding) {
    return nobleDecrypt(privateKey, opts, true);
  } else if (!macGood && padding === true) {
    throw new Error("bad MAC after trying padded");
  }

  const cipher = cbc(key, iv);
  const decrypted = cipher.decrypt(ciphertext);

  return decrypted;
};

export const encrypt = async function (
  publicKeyTo: Buffer,
  msg: Buffer,
  opts?: { iv?: Buffer; ephemPrivateKey?: Buffer; padding?: boolean }
): Promise<Ecies> {
  if (opts?.padding !== undefined) throw new Error("padding opts is not supported");
  const nobleEcies = await nobleEncrypt(publicKeyTo, msg, opts);
  return NobleEciesToEcies(nobleEcies);
};

export const decrypt = async function (privateKey: Buffer, opts: Ecies, padding?: boolean): Promise<Buffer> {
  const nobleEcies = EciesToNobleEcies(opts);
  const decrypted = await nobleDecrypt(privateKey, nobleEcies, padding);
  return Buffer.from(decrypted);
};
