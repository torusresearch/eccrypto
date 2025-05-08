/* eslint-disable import/no-extraneous-dependencies */
import { bytesToUtf8 } from "@noble/ciphers/utils";
import { sha512 as nobleSha512 } from "@noble/hashes/sha2";
import { getPublicKey, getSharedSecret } from "@noble/secp256k1";
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";
import { nobleDecrypt, NobleEciesToEcies, nobleEncrypt } from "../src/nobleEncryption";

describe("Functions: encrypt & decrypt", () => {
  let ephemPublicKey: Buffer;
  let encOpts: any;
  let decOpts: any;
  let iv: Buffer;
  let ciphertext: Buffer;
  let mac: Buffer;
  let privateKey: Buffer;
  let publicKey: Buffer;
  let publicKeyCompressed: Buffer;

  let ephemPrivateKey: Buffer;
  beforeEach(() => {
    ephemPrivateKey = Buffer.alloc(32).fill(4);
    ephemPublicKey = eccrypto.getPublic(ephemPrivateKey);
    iv = Buffer.alloc(16).fill(5);
    ciphertext = Buffer.from("bbf3f0e7486b552b0e2ba9c4ca8c4579", "hex");
    mac = Buffer.from("dbb14a9b53dbd6b763dba24dc99520f570cdf8095a8571db4bf501b535fda1ed", "hex");
    encOpts = { ephemPrivateKey, iv };
    decOpts = { iv, ephemPublicKey, ciphertext, mac };
    privateKey = Buffer.alloc(32).fill(3);
    publicKey = eccrypto.getPublic(privateKey);
    publicKeyCompressed = eccrypto.getPublicCompressed(privateKey);
  });

  describe("encrypt", () => {
    it("should encrypt message with encOpts undefined", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"));
      expect(enc.iv).toBeDefined();
      expect(enc.ephemPublicKey).toBeDefined();
      expect(enc.ciphertext).toBeDefined();
      expect(enc.mac).toBeDefined();
    });

    it("should encrypt message when let encOpts empty", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), {});
      expect(enc.iv).toBeDefined();
      expect(enc.ephemPublicKey).toBeDefined();
      expect(enc.ciphertext).toBeDefined();
      expect(enc.mac).toBeDefined();
    });

    it("should encrypt message when provided encryption options", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), encOpts);
      expect(Buffer.compare(enc.iv, iv)).toBe(0);
      expect(Buffer.compare(enc.ephemPublicKey, ephemPublicKey)).toBe(0);
      expect(Buffer.compare(enc.ciphertext, ciphertext)).toBe(0);
      expect(Buffer.compare(enc.mac, mac)).toBe(0);
    });

    it("should encrypt with padding", async () => {
      const encOptsLocal = { ...encOpts, padding: true };
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), encOptsLocal);
      expect(Buffer.compare(enc.iv, iv)).toBe(0);
      expect(Buffer.compare(enc.ephemPublicKey, ephemPublicKey)).toBe(0);
      expect(Buffer.compare(enc.ciphertext, ciphertext)).toBe(0);
      expect(Buffer.compare(enc.mac, mac)).toBe(0);
    });

    it("should encrypt with compressed public key", async () => {
      const enc = await eccrypto.encrypt(publicKeyCompressed, Buffer.from("test"), encOpts);
      expect(Buffer.compare(enc.iv, iv)).toBe(0);
      expect(Buffer.compare(enc.ephemPublicKey, ephemPublicKey)).toBe(0);
      expect(Buffer.compare(enc.ciphertext, ciphertext)).toBe(0);
      expect(Buffer.compare(enc.mac, mac)).toBe(0);
    });

    it("should throw 'Bad public key' on bad publicKey when encrypting", async () => {
      const badPublicKey = Buffer.alloc(32).fill(4);
      await expect(eccrypto.encrypt(badPublicKey, Buffer.from("test"), encOpts)).rejects.toThrow("Bad public key");
    });
  });

  describe("decrypt", () => {
    it("should decrypt", async () => {
      const dec = await eccrypto.decrypt(privateKey, decOpts);
      expect(dec.toString()).toBe("test");
    });

    it("should throw 'bad MAC after trying padded' on bad privateKey when decrypting", async () => {
      const badPrivateKey = Buffer.from([1, ...privateKey.subarray(1)]);
      await expect(eccrypto.decrypt(badPrivateKey, decOpts)).rejects.toThrow("bad MAC after trying padded");
    });

    it("should reject promise on bad IV when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), encOpts);
      enc.iv[0] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should reject promise on bad R when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), encOpts);
      enc.ephemPublicKey[0] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should reject promise on bad ciphertext when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), encOpts);
      enc.ciphertext[0] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
    });

    it("should reject promise on bad MAC when decrypting", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("test"), encOpts);
      const origMac = enc.mac;
      enc.mac = mac.slice(1);
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
      enc.mac = origMac;
      enc.mac[10] ^= 1;
      await expect(eccrypto.decrypt(privateKey, enc)).rejects.toThrow();
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

  describe("ECIES:encrypt -> decrypt", () => {
    it("should encrypt and decrypt", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("to a"), encOpts);
      const dec = await eccrypto.decrypt(privateKey, enc);
      expect(dec.toString()).toBe("to a");
    });

    it("should encrypt and decrypt with message size > 15", async () => {
      const enc = await eccrypto.encrypt(publicKey, Buffer.from("message size that is greater than 15 for sure =)"), encOpts);
      const message = await eccrypto.decrypt(privateKey, enc);
      expect(message.toString()).toBe("message size that is greater than 15 for sure =)");
    });

    it("should encrypt and decrypt with compressed public key", async () => {
      const enc = await eccrypto.encrypt(publicKeyCompressed, Buffer.from("to a"), encOpts);
      const message = await eccrypto.decrypt(privateKey, enc);
      expect(message.toString()).toBe("to a");
    });

    it("should encrypt and decrypt with generated private and public key", async () => {
      const privKey = eccrypto.generatePrivate();
      const pubKey = eccrypto.getPublic(privKey);
      const enc = await eccrypto.encrypt(pubKey, Buffer.from("generated private key"), encOpts);
      const message = await eccrypto.decrypt(privKey, enc);
      expect(message.toString()).toBe("generated private key");
    });
  });

  describe("ECIES:encrypt -> decrypt withnoble/ciphers", () => {
    it("should encrypt and decrypt", async () => {
      const message = "random message which is very very long and should be encrypted";
      const nobleEcies = await nobleEncrypt(getPublicKey(privateKey), Buffer.from(message), {
        iv: iv,
        ephemPrivateKey: ephemPrivateKey,
      });

      const convertedEcies = NobleEciesToEcies(nobleEcies);

      const encrypted = await eccrypto.encrypt(publicKey, Buffer.from(message), {
        iv: iv,
        ephemPrivateKey: ephemPrivateKey,
      });

      expect(convertedEcies).toEqual(encrypted);

      const decrypted = await nobleDecrypt(privateKey, nobleEcies);
      expect(bytesToUtf8(decrypted)).toBe(message);

      const decrypted1 = await eccrypto.decrypt(privateKey, convertedEcies);
      expect(bytesToUtf8(decrypted1)).toBe(message);
    });
  });
});
