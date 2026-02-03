/* eslint-disable import/no-extraneous-dependencies */
import { concatBytes, equalBytes, hexToBytes } from "@noble/curves/utils.js";
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";

const bytesToUtf8 = (bytes: Uint8Array): string => {
  return new TextDecoder().decode(bytes);
};

describe("Functions: encrypt & decrypt", () => {
  let ephemPublicKey: Uint8Array;
  let encOpts: { ephemPrivateKey: Uint8Array; iv: Uint8Array };
  let decOpts: eccrypto.Ecies;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  let mac: Uint8Array;
  let privateKey: Uint8Array;
  let publicKey: Uint8Array;
  let publicKeyCompressed: Uint8Array;

  beforeEach(() => {
    const ephemPrivateKey = new Uint8Array(32).fill(4);
    ephemPublicKey = eccrypto.getPublic(ephemPrivateKey);
    iv = new Uint8Array(16).fill(5);
    ciphertext = hexToBytes("bbf3f0e7486b552b0e2ba9c4ca8c4579");
    mac = hexToBytes("dbb14a9b53dbd6b763dba24dc99520f570cdf8095a8571db4bf501b535fda1ed");
    encOpts = { ephemPrivateKey, iv };
    decOpts = { iv, ephemPublicKey, ciphertext, mac };
    privateKey = new Uint8Array(32).fill(3);
    publicKey = eccrypto.getPublic(privateKey);
    publicKeyCompressed = eccrypto.getPublicCompressed(privateKey);
  });

  describe("encrypt", () => {
    it("should encrypt message with encOpts undefined", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"));
      expect(enc.iv).toBeDefined();
      expect(enc.ephemPublicKey).toBeDefined();
      expect(enc.ciphertext).toBeDefined();
      expect(enc.mac).toBeDefined();
    });

    it("should encrypt message when let encOpts empty", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), {});
      expect(enc.iv).toBeDefined();
      expect(enc.ephemPublicKey).toBeDefined();
      expect(enc.ciphertext).toBeDefined();
      expect(enc.mac).toBeDefined();
    });

    it("should encrypt message when provided encryption options", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), encOpts);
      expect(equalBytes(enc.iv, iv)).toBe(true);
      expect(equalBytes(enc.ephemPublicKey, ephemPublicKey)).toBe(true);
      expect(equalBytes(enc.ciphertext, ciphertext)).toBe(true);
      expect(equalBytes(enc.mac, mac)).toBe(true);
    });

    it("should encrypt with padding", async () => {
      const encOptsLocal = { ...encOpts };
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), encOptsLocal);
      expect(equalBytes(enc.iv, iv)).toBe(true);
      expect(equalBytes(enc.ephemPublicKey, ephemPublicKey)).toBe(true);
      expect(equalBytes(enc.ciphertext, ciphertext)).toBe(true);
      expect(equalBytes(enc.mac, mac)).toBe(true);
    });

    it("should encrypt with compressed public key", async () => {
      const enc = await eccrypto.encrypt(publicKeyCompressed, new TextEncoder().encode("test"), encOpts);
      expect(equalBytes(enc.iv, iv)).toBe(true);
      expect(equalBytes(enc.ephemPublicKey, ephemPublicKey)).toBe(true);
      expect(equalBytes(enc.ciphertext, ciphertext)).toBe(true);
      expect(equalBytes(enc.mac, mac)).toBe(true);
    });

    it("should throw 'Bad public key' on bad publicKey when encrypting", async () => {
      const badPublicKey = new Uint8Array(32).fill(4);
      await expect(eccrypto.encrypt(badPublicKey, new TextEncoder().encode("test"), encOpts)).rejects.toThrow("Bad public key");
    });
  });

  describe("decrypt", () => {
    it("should decrypt", async () => {
      const dec = await eccrypto.decrypt(privateKey, decOpts);
      expect(bytesToUtf8(dec)).toBe("test");
    });

    it("should throw 'bad MAC after trying padded' on bad privateKey when decrypting", async () => {
      const badPrivateKey = concatBytes(new Uint8Array([1]), privateKey.subarray(1));
      await expect(eccrypto.decrypt(badPrivateKey, decOpts)).rejects.toThrow("bad MAC after trying padded");
    });

    it("should reject promise on bad IV when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), encOpts);
      enc.iv[0] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should reject promise on bad R when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), encOpts);
      enc.ephemPublicKey[0] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should reject promise on bad ciphertext when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), encOpts);
      enc.ciphertext[0] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should reject promise on bad MAC when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("test"), encOpts);
      const origMac = enc.mac;
      enc.mac = mac.slice(1);
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
      enc.mac = origMac;
      enc.mac[10] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should successfully decrypt if bad MAC is caused by inconsistent padding in derive", async () => {
      const encryption = {
        ciphertext: hexToBytes("e614aff7db97b01d4b0d5cfb1387b4763cb369f74d743bed95020330d57e3ae91a574bd7ae89da0885eb5f6e332a296f"),
        ephemPublicKey: hexToBytes(
          "04fb0a7c19defeaeeb34defbc47be3c9a4c1de500895c1e1e8ce6d0991595217f8e76c4594968e8c77d83c26f4f1ee496c40c7ac48816a4ee2edf38c550d8916a0"
        ),
        iv: hexToBytes("456f0c039cb2224849082c3d0feebec1"),
        mac: hexToBytes("df7352dcdf2ee10c939276791515340479b526920a155b8ac932a5a26ea4c924"),
      };

      const decryptionKey = hexToBytes("78bb3f8efcd59ebc8c4f0dee865ba10e375869921c62caa5b3b46699504bb280");

      const message = await eccrypto.decrypt(decryptionKey, encryption);
      expect(bytesToUtf8(message)).not.toBeNull();
    });

    it("should throw an error when decryption fails due to bad MAC", async () => {
      const testPrivateKey = hexToBytes("1111111111111111111111111111111111111111111111111111111111111111");
      const testPublicKey = eccrypto.getPublic(testPrivateKey);

      const testMessage = new TextEncoder().encode("Hello, world!");
      const encrypted = await eccrypto.encrypt(testPublicKey, testMessage);

      // Tamper with the MAC to make it invalid
      encrypted.mac = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");

      await expect(eccrypto.decrypt(testPrivateKey, encrypted)).rejects.toThrow("bad MAC after trying padded");
    });
  });

  describe("ECIES:encrypt -> decrypt", () => {
    it("should encrypt and decrypt", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("to a"), encOpts);
      const dec = await eccrypto.decrypt(privateKey, enc);
      expect(bytesToUtf8(dec)).toBe("to a");
    });

    it("should encrypt and decrypt with message size > 15", async () => {
      const enc = await eccrypto.encrypt(publicKey, new TextEncoder().encode("message size that is greater than 15 for sure =)"), encOpts);
      const message = await eccrypto.decrypt(privateKey, enc);
      expect(bytesToUtf8(message)).toBe("message size that is greater than 15 for sure =)");
    });

    it("should encrypt and decrypt with compressed public key", async () => {
      const enc = await eccrypto.encrypt(publicKeyCompressed, new TextEncoder().encode("to a"), encOpts);
      const message = await eccrypto.decrypt(privateKey, enc);
      expect(bytesToUtf8(message)).toBe("to a");
    });

    it("should encrypt and decrypt with generated private and public key", async () => {
      const privKey = eccrypto.generatePrivate();
      const pubKey = eccrypto.getPublic(privKey);
      const enc = await eccrypto.encrypt(pubKey, new TextEncoder().encode("generated private key"), encOpts);
      const message = await eccrypto.decrypt(privKey, enc);
      expect(bytesToUtf8(message)).toBe("generated private key");
    });
  });
});
