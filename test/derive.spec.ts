/* eslint-disable import/no-extraneous-dependencies */
import bufferEqual from "buffer-equal";
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";

describe("Functions: derive & derivePadded", () => {
  let privateKeyA: Buffer;
  let publicKeyA: Buffer;
  let compressedPublicKeyA: Buffer;
  let privateKeyB: Buffer;
  let publicKeyB: Buffer;
  let compressedPublicKeyB: Buffer;

  beforeEach(() => {
    privateKeyA = eccrypto.generatePrivate();
    publicKeyA = eccrypto.getPublic(privateKeyA);
    compressedPublicKeyA = eccrypto.getPublicCompressed(privateKeyA);
    privateKeyB = eccrypto.generatePrivate();
    publicKeyB = eccrypto.getPublic(privateKeyB);
    compressedPublicKeyB = eccrypto.getPublicCompressed(privateKeyB);
  });

  describe("derive", () => {
    it("should throw 'Bad private key' if private key is not a 32-byte buffer", async () => {
      // @ts-expect-error private key is not a buffer
      await expect(eccrypto.derive("Not buffer", publicKeyB)).rejects.toThrow("Bad private key");
      await expect(eccrypto.derive(Buffer.alloc(0), publicKeyB)).rejects.toThrow("Bad private key");
      await expect(eccrypto.derive(Buffer.alloc(33), publicKeyB)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Bad public key' if public key is not a 65-byte or 33-byte buffer", async () => {
      // @ts-expect-error public key is not a buffer
      await expect(eccrypto.derive(privateKeyA, "Not buffer")).rejects.toThrow("Bad public key");
      await expect(eccrypto.derive(privateKeyA, Buffer.alloc(0))).rejects.toThrow("Bad public key");
      await expect(eccrypto.derive(privateKeyA, Buffer.alloc(32))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is not compressed and first byte is not 4", async () => {
      await expect(eccrypto.derive(privateKeyA, Buffer.concat([Buffer.from([1]), publicKeyB]))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is compressed and first byte is not 2 or 3", async () => {
      await expect(eccrypto.derive(privateKeyA, Buffer.concat([Buffer.from([2]), compressedPublicKeyB]))).rejects.toThrow("Bad public key");
      await expect(eccrypto.derive(privateKeyA, Buffer.concat([Buffer.from([3]), compressedPublicKeyB]))).rejects.toThrow("Bad public key");
    });

    it("should return a 32-byte buffer", async () => {
      const derived = await eccrypto.derive(privateKeyA, publicKeyB);
      expect(derived.length).toBe(32);
    });
  });

  describe("derivePadded", () => {
    it("should throw 'Bad private key' if private key is not a 32-byte buffer", async () => {
      // @ts-expect-error private key is not a buffer
      await expect(eccrypto.derivePadded("Not buffer", publicKeyB)).rejects.toThrow("Bad private key");
      await expect(eccrypto.derivePadded(Buffer.alloc(0), publicKeyB)).rejects.toThrow("Bad private key");
      await expect(eccrypto.derivePadded(Buffer.alloc(33), publicKeyB)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Bad public key' if public key is not a 65-byte or 33-byte buffer", async () => {
      // @ts-expect-error public key is not a buffer
      await expect(eccrypto.derivePadded(privateKeyA, "Not buffer")).rejects.toThrow("Bad public key");
      await expect(eccrypto.derivePadded(privateKeyA, Buffer.alloc(0))).rejects.toThrow("Bad public key");
      await expect(eccrypto.derivePadded(privateKeyA, Buffer.alloc(32))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is not compressed and first byte is not 4", async () => {
      await expect(eccrypto.derivePadded(privateKeyA, Buffer.concat([Buffer.from([1]), publicKeyB]))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is compressed and first byte is not 2 or 3", async () => {
      await expect(eccrypto.derivePadded(privateKeyA, Buffer.concat([Buffer.from([2]), compressedPublicKeyB]))).rejects.toThrow("Bad public key");
      await expect(eccrypto.derivePadded(privateKeyA, Buffer.concat([Buffer.from([3]), compressedPublicKeyB]))).rejects.toThrow("Bad public key");
    });

    it("should return a 64-byte buffer", async () => {
      const derived = await eccrypto.derivePadded(privateKeyA, publicKeyB);
      expect(derived.length).toBe(32);
    });
  });

  describe("ECDH", () => {
    let deriveAB: Buffer;
    let deriveABUseCompressed: Buffer;
    let deriveBA: Buffer;
    let deriveBAUseCompressed: Buffer;
    let derivePaddedAB: Buffer;
    let derivePaddedBA: Buffer;

    beforeEach(async () => {
      deriveAB = await eccrypto.derive(privateKeyA, publicKeyB);
      deriveABUseCompressed = await eccrypto.derive(privateKeyA, compressedPublicKeyB);
      deriveBA = await eccrypto.derive(privateKeyB, publicKeyA);
      deriveBAUseCompressed = await eccrypto.derive(privateKeyB, compressedPublicKeyA);
      derivePaddedAB = await eccrypto.derivePadded(privateKeyA, publicKeyB);
      derivePaddedBA = await eccrypto.derivePadded(privateKeyB, publicKeyA);
    });

    it("should be equal: derive(privateKeyA, publicKeyB) == derive(privateKeyB, publicKeyA)", async () => {
      expect(bufferEqual(deriveBA, deriveAB)).toBe(true);
    });

    it("should be equal: derive(privateKeyA, publicKeyB) == derivePadded(privateKeyA, publicKeyB)", async () => {
      expect(bufferEqual(deriveAB, derivePaddedAB)).toBe(true);
    });

    it("should be equal: derivePadded(privateKeyA, publicKeyB) == derivePadded(privateKeyB, publicKeyA)", async () => {
      expect(bufferEqual(derivePaddedBA, derivePaddedAB)).toBe(true);
    });

    it("should be equal: derive(privateKeyA, compressedPublicKeyB) == derive(privateKeyB, compressedPublicKeyA)", async () => {
      expect(bufferEqual(deriveABUseCompressed, deriveBAUseCompressed)).toBe(true);
    });

    it("should be equal: derive(privateKeyA, compressedPublicKeyB) == derivePadded(privateKeyA, compressedPublicKeyB)", async () => {
      expect(bufferEqual(deriveABUseCompressed, derivePaddedAB)).toBe(true);
    });
  });
});
