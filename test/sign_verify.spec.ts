/* eslint-disable import/no-extraneous-dependencies */
import { bytesToHex, concatBytes, hexToBytes } from "@noble/curves/utils.js";
import { beforeEach, describe, expect, it } from "vitest";

import * as ec from "../src/index";
// msgString is the sha256 hash of "test"
const msgString = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const msg = hexToBytes(msgString);

describe("Functions: sign & verify", () => {
  let privKey: Uint8Array;
  let pubKey: Uint8Array;
  let comPubkey: Uint8Array;
  let sig: Uint8Array;

  beforeEach(async () => {
    privKey = ec.generatePrivate();
    pubKey = ec.getPublic(privKey);
    comPubkey = ec.getPublicCompressed(privKey);
    sig = await ec.sign(privKey, msg);
  });

  describe("sign", () => {
    it("should throw 'Bad private key' if the private key is not 32 bytes", async () => {
      await expect(ec.sign(new Uint8Array(31), msg)).rejects.toThrow("Bad private key");
      await expect(ec.sign(new Uint8Array(33), msg)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Bad private key' if the private key is not valid", async () => {
      await expect(ec.sign(new Uint8Array(32), msg)).rejects.toThrow("Bad private key");
      await expect(ec.sign(hexToBytes("00"), msg)).rejects.toThrow("Bad private key");
      await expect(ec.sign(new TextEncoder().encode("test"), msg)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Message should not be empty' if the message is empty", async () => {
      await expect(ec.sign(privKey, new Uint8Array(0))).rejects.toThrow("Message should not be empty");
    });

    it("should throw 'Message is too long' if the message is longer than 32 bytes", async () => {
      await expect(ec.sign(privKey, new Uint8Array(33))).rejects.toThrow("Message is too long");
    });

    it("should throw 'Bad private key' for invalid private key k4, k192, k384", async () => {
      const k4 = new TextEncoder().encode("test");
      const k192 = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      const k384 = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

      await expect(ec.sign(k4, msg)).rejects.toThrow("Bad private key");
      await expect(ec.sign(k192, msg)).rejects.toThrow("Bad private key");
      await expect(ec.sign(k384, msg)).rejects.toThrow("Bad private key");
    });

    it("should return a Uint8Array", async () => {
      expect(sig instanceof Uint8Array).toBe(true);
    });

    it("should return correct signature then verify it with the public key", async () => {
      await expect(ec.verify(pubKey, msg, sig)).resolves.toBeNull();
    });
  });

  describe("verify", () => {
    it("should throw 'Bad public key' if public key length is not 65 or 33", async () => {
      await expect(ec.verify(new Uint8Array(64), msg, sig)).rejects.toThrow("Bad public key");
      await expect(ec.verify(new Uint8Array(66), msg, sig)).rejects.toThrow("Bad public key");
      await expect(ec.verify(new Uint8Array(32), msg, sig)).rejects.toThrow("Bad public key");
      await expect(ec.verify(new Uint8Array(34), msg, sig)).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is not compressed and first byte is not 4", async () => {
      await expect(ec.verify(concatBytes(new Uint8Array([2]), pubKey.subarray(1)), msg, sig)).rejects.toThrow("Bad public key");
      await expect(ec.verify(concatBytes(new Uint8Array([3]), pubKey.subarray(1)), msg, sig)).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is compressed and first byte is not 2 or 3", async () => {
      await expect(ec.verify(concatBytes(new Uint8Array([5]), comPubkey.subarray(1)), msg, sig)).rejects.toThrow("Bad public key");
      await expect(ec.verify(concatBytes(new Uint8Array([4]), comPubkey.subarray(1)), msg, sig)).rejects.toThrow("Bad public key");
    });

    it("should throw 'Message should not be empty' if the message is empty", async () => {
      await expect(ec.verify(pubKey, new Uint8Array(0), sig)).rejects.toThrow("Message should not be empty");
    });

    it("should throw 'Message is too long' if the message is longer than 32 bytes", async () => {
      await expect(ec.verify(pubKey, new Uint8Array(33), sig)).rejects.toThrow("Message is too long");
    });

    it("should throw 'Bad signature' if the signature is incorrect", async () => {
      const anotherMsg = new TextEncoder().encode("Another message");
      const anotherSig = await ec.sign(privKey, anotherMsg);
      await expect(ec.verify(pubKey, msg, anotherSig)).rejects.toThrow("Bad signature");
      await expect(ec.verify(comPubkey, msg, anotherSig)).rejects.toThrow("Bad signature");
    });

    it("should return null if the signature is valid", async () => {
      await expect(ec.verify(pubKey, msg, sig)).resolves.toBeNull();
      await expect(ec.verify(comPubkey, msg, sig)).resolves.toBeNull();
    });
  });

  describe("ECDSA", () => {
    let ecdsaPrivateKey: Uint8Array;
    let ecdsaPublicKey: Uint8Array;
    let ecdsaCompressedPublicKey: Uint8Array;
    let ecdsaSignature: Uint8Array;

    beforeEach(async () => {
      ecdsaPrivateKey = new Uint8Array(32).fill(1);
      ecdsaPublicKey = ec.getPublic(ecdsaPrivateKey);
      ecdsaCompressedPublicKey = ec.getPublicCompressed(ecdsaPrivateKey);
      ecdsaSignature = await ec.sign(ecdsaPrivateKey, msg);
    });

    it("should allow to sign and verify message", async () => {
      expect(ecdsaSignature instanceof Uint8Array).toBe(true);
      expect(bytesToHex(ecdsaSignature)).toBe(
        "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
      );
      await expect(ec.verify(ecdsaPublicKey, msg, ecdsaSignature)).resolves.toBeNull();
    });

    it("should allow to sign and verify message using a compressed public key", async () => {
      expect(ecdsaSignature instanceof Uint8Array).toBe(true);
      expect(bytesToHex(ecdsaSignature)).toBe(
        "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
      );
      await expect(ec.verify(ecdsaCompressedPublicKey, msg, ecdsaSignature)).resolves.toBeNull();
    });
  });
});
