/* eslint-disable import/no-extraneous-dependencies */
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";
// msgString is the sha256 hash of "test"
const msgString = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const msg = Buffer.from(msgString, "hex");

describe("Functions: sign & verify", () => {
  let privKey: Buffer;
  let pubKey: Buffer;
  let comPubkey: Buffer;
  let sig: Buffer;

  beforeEach(async () => {
    privKey = eccrypto.generatePrivate();
    pubKey = eccrypto.getPublic(privKey);
    comPubkey = eccrypto.getPublicCompressed(privKey);
    sig = await eccrypto.sign(privKey, msg);
  });

  describe("sign", () => {
    it("should throw 'Bad private key' if the private key is not 32 bytes", async () => {
      await expect(eccrypto.sign(Buffer.alloc(31), msg)).rejects.toThrow("Bad private key");
      await expect(eccrypto.sign(Buffer.alloc(33), msg)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Bad private key' if the private key is not valid", async () => {
      await expect(eccrypto.sign(Buffer.alloc(32), msg)).rejects.toThrow("Bad private key");
      await expect(eccrypto.sign(Buffer.from("00", "hex"), msg)).rejects.toThrow("Bad private key");
      await expect(eccrypto.sign(Buffer.from("test"), msg)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Message should not be empty' if the message is empty", async () => {
      await expect(eccrypto.sign(privKey, Buffer.alloc(0))).rejects.toThrow("Message should not be empty");
    });

    it("should throw 'Message is too long' if the message is longer than 32 bytes", async () => {
      await expect(eccrypto.sign(privKey, Buffer.alloc(33))).rejects.toThrow("Message is too long");
    });

    it("should throw 'Bad private key' for invalid private key k4, k192, k384", async () => {
      const k4 = Buffer.from("test");
      const k192 = Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hex");
      const k384 = Buffer.from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "hex");

      await expect(eccrypto.sign(k4, msg)).rejects.toThrow("Bad private key");
      await expect(eccrypto.sign(k192, msg)).rejects.toThrow("Bad private key");
      await expect(eccrypto.sign(k384, msg)).rejects.toThrow("Bad private key");
    });

    it("should return a buffer", async () => {
      expect(Buffer.isBuffer(sig)).toBe(true);
    });

    it("should return correct signature then verify it with the public key", async () => {
      await expect(eccrypto.verify(pubKey, msg, sig)).resolves.toBeNull();
    });
  });

  describe("verify", () => {
    it("should throw 'Bad public key' if public key length is not 65 or 33", async () => {
      await expect(eccrypto.verify(Buffer.alloc(64), msg, sig)).rejects.toThrow("Bad public key");
      await expect(eccrypto.verify(Buffer.alloc(66), msg, sig)).rejects.toThrow("Bad public key");
      await expect(eccrypto.verify(Buffer.alloc(32), msg, sig)).rejects.toThrow("Bad public key");
      await expect(eccrypto.verify(Buffer.alloc(34), msg, sig)).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is not compressed and first byte is not 4", async () => {
      await expect(eccrypto.verify(Buffer.from([2, ...pubKey.subarray(1)]), msg, sig)).rejects.toThrow("Bad public key");
      await expect(eccrypto.verify(Buffer.from([3, ...pubKey.subarray(1)]), msg, sig)).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is compressed and first byte is not 2 or 3", async () => {
      await expect(eccrypto.verify(Buffer.from([5, ...comPubkey.subarray(1)]), msg, sig)).rejects.toThrow("Bad public key");
      await expect(eccrypto.verify(Buffer.from([4, ...comPubkey.subarray(1)]), msg, sig)).rejects.toThrow("Bad public key");
    });

    it("should throw 'Message should not be empty' if the message is empty", async () => {
      await expect(eccrypto.verify(pubKey, Buffer.alloc(0), sig)).rejects.toThrow("Message should not be empty");
    });

    it("should throw 'Message is too long' if the message is longer than 32 bytes", async () => {
      await expect(eccrypto.verify(pubKey, Buffer.alloc(33), sig)).rejects.toThrow("Message is too long");
    });

    it("should throw 'Bad signature' if the signature is incorrect", async () => {
      const anotherMsg = Buffer.from("Another message", "utf-8");
      const anotherSig = await eccrypto.sign(privKey, anotherMsg);
      await expect(eccrypto.verify(pubKey, msg, anotherSig)).rejects.toThrow("Bad signature");
      await expect(eccrypto.verify(comPubkey, msg, anotherSig)).rejects.toThrow("Bad signature");
    });

    it("should return null if the signature is valid", async () => {
      await expect(eccrypto.verify(pubKey, msg, sig)).resolves.toBeNull();
      await expect(eccrypto.verify(comPubkey, msg, sig)).resolves.toBeNull();
    });
  });

  describe("ECDSA", () => {
    let ecdsaPrivateKey: Buffer;
    let ecdsaPublicKey: Buffer;
    let ecdsaCompressedPublicKey: Buffer;
    let ecdsaSignature: Buffer;

    beforeEach(async () => {
      ecdsaPrivateKey = Buffer.alloc(32).fill(1);
      ecdsaPublicKey = eccrypto.getPublic(ecdsaPrivateKey);
      ecdsaCompressedPublicKey = eccrypto.getPublicCompressed(ecdsaPrivateKey);
      ecdsaSignature = await eccrypto.sign(ecdsaPrivateKey, msg);
    });

    it("should allow to sign and verify message", async () => {
      expect(Buffer.isBuffer(ecdsaSignature)).toBe(true);
      expect(ecdsaSignature.toString("hex")).toBe(
        "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
      );
      await expect(eccrypto.verify(ecdsaPublicKey, msg, ecdsaSignature)).resolves.toBeNull();
    });

    it("should allow to sign and verify message using a compressed public key", async () => {
      expect(Buffer.isBuffer(ecdsaSignature)).toBe(true);
      expect(ecdsaSignature.toString("hex")).toBe(
        "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
      );
      await expect(eccrypto.verify(ecdsaCompressedPublicKey, msg, ecdsaSignature)).resolves.toBeNull();
    });
  });
});
