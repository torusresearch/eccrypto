/* eslint-disable import/no-extraneous-dependencies */

/* eslint-disable mocha/max-top-level-suites */
import bufferEqual from "buffer-equal";
import { createHash } from "crypto";
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";

const msg = createHash("sha256").update("test").digest();
const otherMsg = createHash("sha256").update("test2").digest();
const shortMsg = createHash("sha1").update("test").digest();

const privateKey = Buffer.alloc(32);
privateKey.fill(1);
const publicKey = eccrypto.getPublic(privateKey);
const publicKeyCompressed = eccrypto.getPublicCompressed(privateKey);

const privateKeyA = Buffer.alloc(32);
privateKeyA.fill(2);
const publicKeyA = eccrypto.getPublic(privateKeyA);
const publicKeyACompressed = eccrypto.getPublicCompressed(privateKeyA);

const privateKeyB = Buffer.alloc(32);
privateKeyB.fill(3);
const publicKeyB = eccrypto.getPublic(privateKeyB);
const publicKeyBCompressed = eccrypto.getPublicCompressed(privateKeyB);

describe("Key conversion", () => {
  it("should allow to convert private key to public", () => {
    expect(Buffer.isBuffer(publicKey)).toBe(true);
    expect(publicKey.toString("hex")).toBe(
      "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1"
    );
  });

  it("should allow to convert private key to compressed public", () => {
    expect(Buffer.isBuffer(publicKeyCompressed)).toBe(true);
    expect(publicKeyCompressed.toString("hex")).toBe("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
  });

  it("should throw on invalid private key", () => {
    expect(() => eccrypto.getPublic(Buffer.from("00", "hex"))).toThrow("Bad private key");
    expect(() => eccrypto.getPublic(Buffer.from("test"))).toThrow("Bad private key");
  });
});

describe("ECDSA", () => {
  it("should allow to sign and verify message", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).toBe(true);
    expect(sig.toString("hex")).toBe(
      "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
    );
    await expect(eccrypto.verify(publicKey, msg, sig)).resolves.toBeNull();
  });

  it("should allow to sign and verify message using a compressed public key", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).toBe(true);
    expect(sig.toString("hex")).toBe(
      "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
    );
    await expect(eccrypto.verify(publicKeyCompressed, msg, sig)).resolves.toBeNull();
  });

  it("shouldn't verify incorrect signature", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).toBe(true);
    await expect(eccrypto.verify(publicKey, otherMsg, sig)).rejects.toThrow("Bad signature");
  });

  it("should reject promise on invalid key when signing", async () => {
    const k4 = Buffer.from("test");
    const k192 = Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hex");
    const k384 = Buffer.from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "hex");

    await expect(eccrypto.sign(k4, msg)).rejects.toThrow("Bad private key");
    await expect(eccrypto.sign(k192, msg)).rejects.toThrow("Bad private key");
    await expect(eccrypto.sign(k384, msg)).rejects.toThrow("Bad private key");
  });

  it("should reject promise on invalid key when verifying", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).toBe(true);
    await expect(eccrypto.verify(Buffer.from("test"), msg, sig)).rejects.toThrow("Bad public key");
    const badKey = Buffer.alloc(65);
    publicKey.copy(badKey);
    badKey[0] ^= 1;
    await expect(eccrypto.verify(badKey, msg, sig)).rejects.toThrow("Bad public key");
  });

  it("should reject promise on invalid sig when verifying", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).toBe(true);
    sig[0] ^= 1;
    await expect(eccrypto.verify(publicKey, msg, sig)).rejects.toThrow("Signature without r or s");
  });

  it("should allow to sign and verify messages less than 32 bytes", async () => {
    const sig = await eccrypto.sign(privateKey, shortMsg);
    expect(Buffer.isBuffer(sig)).toBe(true);
    expect(sig.toString("hex")).toBe(
      "304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa"
    );
    await expect(eccrypto.verify(publicKey, shortMsg, sig)).resolves.toBeNull();
  });

  it("shouldn't sign and verify messages longer than 32 bytes", async () => {
    const longMsg = Buffer.alloc(40);
    const someSig = Buffer.from(
      "304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa",
      "hex"
    );
    await expect(eccrypto.sign(privateKey, longMsg)).rejects.toThrow("Message is too long");
    await expect(eccrypto.verify(privateKey, longMsg, someSig)).rejects.toThrow("Bad public key");
  });

  it("shouldn't sign and verify empty messages", async () => {
    const emptyMsg = Buffer.alloc(0);
    const someSig = Buffer.from(
      "304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa",
      "hex"
    );
    await expect(eccrypto.sign(privateKey, emptyMsg)).rejects.toThrow("Message should not be empty");
    await expect(eccrypto.verify(publicKey, emptyMsg, someSig)).rejects.toThrow("Message should not be empty");
  });
});

describe("ECDH", () => {
  it("should derive shared secret from privkey A and pubkey B", async () => {
    const Px = await eccrypto.derive(privateKeyA, publicKeyB);
    expect(Buffer.isBuffer(Px)).toBe(true);
    expect(Px.length).toBe(32);
    expect(Px.toString("hex")).toBe("aca78f27d5f23b2e7254a0bb8df128e7c0f922d47ccac72814501e07b7291886");
    const Px2 = await eccrypto.derive(privateKeyB, publicKeyA);
    expect(Buffer.isBuffer(Px2)).toBe(true);
    expect(Px2.length).toBe(32);
    expect(bufferEqual(Px, Px2)).toBe(true);
  });

  it("should derive shared secret from  privkey A and compressed pubkey B", async () => {
    const Px = await eccrypto.derive(privateKeyA, publicKeyBCompressed);
    expect(Buffer.isBuffer(Px)).toBe(true);
    expect(Px.length).toBe(32);
    expect(Px.toString("hex")).toBe("aca78f27d5f23b2e7254a0bb8df128e7c0f922d47ccac72814501e07b7291886");
    const Px2 = await eccrypto.derive(privateKeyB, publicKeyA);
    expect(Buffer.isBuffer(Px2)).toBe(true);
    expect(Px2.length).toBe(32);
    expect(bufferEqual(Px, Px2)).toBe(true);
  });

  it("should reject promise on bad keys", async () => {
    await expect(eccrypto.derive(Buffer.from("test"), publicKeyB)).rejects.toThrow();
    await expect(eccrypto.derive(publicKeyB, publicKeyB)).rejects.toThrow();
    await expect(eccrypto.derive(privateKeyA, privateKeyA)).rejects.toThrow();
    await expect(eccrypto.derive(privateKeyB, Buffer.from("test"))).rejects.toThrow();
  });

  it("should reject promise on bad arguments", async () => {
    await expect(eccrypto.derive({}, {})).rejects.toThrow();
  });
});

describe("ECIES", () => {
  let ephemPublicKey: Buffer, encOpts: any, decOpts: any, iv: Buffer, ciphertext: Buffer, mac: Buffer;

  beforeEach(() => {
    const ephemPrivateKey = Buffer.alloc(32);
    ephemPrivateKey.fill(4);
    ephemPublicKey = eccrypto.getPublic(ephemPrivateKey);
    iv = Buffer.alloc(16);
    iv.fill(5);
    ciphertext = Buffer.from("bbf3f0e7486b552b0e2ba9c4ca8c4579", "hex");
    mac = Buffer.from("dbb14a9b53dbd6b763dba24dc99520f570cdf8095a8571db4bf501b535fda1ed", "hex");
    encOpts = { ephemPrivateKey, iv };
    decOpts = { iv, ephemPublicKey, ciphertext, mac };
  });

  it("should encrypt", async () => {
    const enc = await eccrypto.encrypt(publicKeyB, Buffer.from("test"), encOpts);
    expect(bufferEqual(enc.iv, iv)).toBe(true);
    expect(bufferEqual(enc.ephemPublicKey, ephemPublicKey)).toBe(true);
    expect(bufferEqual(enc.ciphertext, ciphertext)).toBe(true);
    expect(bufferEqual(enc.mac, mac)).toBe(true);
  });

  it("should decrypt", async () => {
    const message = await eccrypto.decrypt(privateKeyB, decOpts);
    expect(message.toString()).toBe("test");
  });

  it("should encrypt and decrypt", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("to a"), encOpts);
    const message = await eccrypto.decrypt(privateKeyA, enc);
    expect(message.toString()).toBe("to a");
  });

  it("should encrypt and decrypt with message size > 15", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("message size that is greater than 15 for sure =)"), encOpts);
    const message = await eccrypto.decrypt(privateKeyA, enc);
    expect(message.toString()).toBe("message size that is greater than 15 for sure =)");
  });

  it("should encrypt with compressed public key", async () => {
    const enc = await eccrypto.encrypt(publicKeyBCompressed, Buffer.from("test"), encOpts);
    expect(bufferEqual(enc.iv, iv)).toBe(true);
    expect(bufferEqual(enc.ephemPublicKey, ephemPublicKey)).toBe(true);
    expect(bufferEqual(enc.ciphertext, ciphertext)).toBe(true);
    expect(bufferEqual(enc.mac, mac)).toBe(true);
  });

  it("should encrypt and decrypt with compressed public key", async () => {
    const enc = await eccrypto.encrypt(publicKeyACompressed, Buffer.from("to a"), encOpts);
    const message = await eccrypto.decrypt(privateKeyA, enc);
    expect(message.toString()).toBe("to a");
  });

  it("should encrypt and decrypt with generated private and public key", async () => {
    const privKey = eccrypto.generatePrivate();
    const pubKey = eccrypto.getPublic(privKey);
    const enc = await eccrypto.encrypt(pubKey, Buffer.from("generated private key"), encOpts);
    const message = await eccrypto.decrypt(privKey, enc);
    expect(message.toString()).toBe("generated private key");
  });

  it("should reject promise on bad private key when decrypting", async () => {
    await expect(eccrypto.encrypt(publicKeyA, Buffer.from("test"), encOpts)).resolves.toBeDefined();
  });

  it("should reject promise on bad IV when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"), encOpts);
    enc.iv[0] ^= 1;
    await expect(eccrypto.decrypt(privateKeyA, enc)).rejects.toThrow();
  });

  it("should reject promise on bad R when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"), encOpts);
    enc.ephemPublicKey[0] ^= 1;
    await expect(eccrypto.decrypt(privateKeyA, enc)).rejects.toThrow();
  });

  it("should reject promise on bad ciphertext when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"), encOpts);
    enc.ciphertext[0] ^= 1;
    await expect(eccrypto.decrypt(privateKeyA, enc)).rejects.toThrow();
  });

  it("should reject promise on bad MAC when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"), encOpts);
    const origMac = enc.mac;
    enc.mac = mac.slice(1);
    await expect(eccrypto.decrypt(privateKeyA, enc)).rejects.toThrow();
    enc.mac = origMac;
    enc.mac[10] ^= 1;
    await expect(eccrypto.decrypt(privateKeyA, enc)).rejects.toThrow();
  });

  it("should successfully decrypt if bad MAC is caused by inconsistent padding in derive", async () => {
    const encryption = {
      ciphertext: Buffer.from("e614aff7db97b01d4b0d5cfb1387b4763cb369f74d743bed95020330d57e3ae91a574bd7ae89da0885eb5f6e332a296f", "hex"),
      ephemPublicKey: Buffer.from(
        "04fb0a7c19defeaeeb34defbc47be3c9a4c1de500895c1e1e8ce6d0991595217f8e76c4594968e8c77d83c26f4f1ee496c40c7ac48816a4ee2edf38c550d8916a0",
        "hex"
      ),
      iv: Buffer.from("456f0c039cb2224849082c3d0feebec1", "hex"),
      mac: Buffer.from("df7352dcdf2ee10c939276791515340479b526920a155b8ac932a5a26ea4c924", "hex"),
    };

    const decryptionKey = Buffer.from("78bb3f8efcd59ebc8c4f0dee865ba10e375869921c62caa5b3b46699504bb280", "hex");

    const message = await eccrypto.decrypt(decryptionKey, encryption);
    expect(message.toString()).not.toBeNull();
  });

  it("should throw an error when decryption fails due to bad MAC", async () => {
    const testPrivateKey = Buffer.from("1111111111111111111111111111111111111111111111111111111111111111", "hex");
    const testPublicKey = eccrypto.getPublic(testPrivateKey);

    const testMessage = Buffer.from("Hello, world!");
    const encrypted = await eccrypto.encrypt(testPublicKey, testMessage);

    // Tamper with the MAC to make it invalid
    encrypted.mac = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex");

    try {
      await eccrypto.decrypt(testPrivateKey, encrypted);
      // throw new Error("Decryption should have failed");
    } catch (error) {
      if (error instanceof Error) {
        expect(error.message).toBe("bad MAC after trying padded");
      } else {
        throw error;
      }
    }
  });
});
