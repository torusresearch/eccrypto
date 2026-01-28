/* eslint-disable import/no-extraneous-dependencies */
import { concatBytes, equalBytes } from "@noble/curves/abstract/utils";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import * as ec from "../src/index";

describe("Functions: derive & derivePadded", () => {
  let privateKeyA: Uint8Array;
  let publicKeyA: Uint8Array;
  let compressedPublicKeyA: Uint8Array;
  let privateKeyB: Uint8Array;
  let publicKeyB: Uint8Array;
  let compressedPublicKeyB: Uint8Array;

  beforeEach(() => {
    privateKeyA = ec.generatePrivate();
    publicKeyA = ec.getPublic(privateKeyA);
    compressedPublicKeyA = ec.getPublicCompressed(privateKeyA);
    privateKeyB = ec.generatePrivate();
    publicKeyB = ec.getPublic(privateKeyB);
    compressedPublicKeyB = ec.getPublicCompressed(privateKeyB);
  });

  describe("derive", () => {
    it("should throw 'Bad private key' if private key is not a 32-byte Uint8Array", async () => {
      // @ts-expect-error private key is not a Uint8Array
      await expect(ec.derive("Not buffer", publicKeyB)).rejects.toThrow("Bad private key");
      await expect(ec.derive(new Uint8Array(0), publicKeyB)).rejects.toThrow("Bad private key");
      await expect(ec.derive(new Uint8Array(33), publicKeyB)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Bad public key' if public key is not a 65-byte or 33-byte Uint8Array", async () => {
      // @ts-expect-error public key is not a Uint8Array
      await expect(ec.derive(privateKeyA, "Not buffer")).rejects.toThrow("Bad public key");
      await expect(ec.derive(privateKeyA, new Uint8Array(0))).rejects.toThrow("Bad public key");
      await expect(ec.derive(privateKeyA, new Uint8Array(32))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is not compressed and first byte is not 4", async () => {
      await expect(ec.derive(privateKeyA, concatBytes(new Uint8Array([1]), publicKeyB))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is compressed and first byte is not 2 or 3", async () => {
      await expect(ec.derive(privateKeyA, concatBytes(new Uint8Array([2]), compressedPublicKeyB))).rejects.toThrow("Bad public key");
      await expect(ec.derive(privateKeyA, concatBytes(new Uint8Array([3]), compressedPublicKeyB))).rejects.toThrow("Bad public key");
    });

    it("should return a 32-byte Uint8Array", async () => {
      const derived = await ec.derive(privateKeyA, publicKeyB);
      expect(derived.length).toBe(32);
    });
  });

  describe("derivePadded", () => {
    it("should throw 'Bad private key' if private key is not a 32-byte Uint8Array", async () => {
      // @ts-expect-error private key is not a Uint8Array
      await expect(ec.derivePadded("Not buffer", publicKeyB)).rejects.toThrow("Bad private key");
      await expect(ec.derivePadded(new Uint8Array(0), publicKeyB)).rejects.toThrow("Bad private key");
      await expect(ec.derivePadded(new Uint8Array(33), publicKeyB)).rejects.toThrow("Bad private key");
    });

    it("should throw 'Bad public key' if public key is not a 65-byte or 33-byte Uint8Array", async () => {
      // @ts-expect-error public key is not a Uint8Array
      await expect(ec.derivePadded(privateKeyA, "Not buffer")).rejects.toThrow("Bad public key");
      await expect(ec.derivePadded(privateKeyA, new Uint8Array(0))).rejects.toThrow("Bad public key");
      await expect(ec.derivePadded(privateKeyA, new Uint8Array(32))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is not compressed and first byte is not 4", async () => {
      await expect(ec.derivePadded(privateKeyA, concatBytes(new Uint8Array([1]), publicKeyB))).rejects.toThrow("Bad public key");
    });

    it("should throw 'Bad public key' if public key is compressed and first byte is not 2 or 3", async () => {
      await expect(ec.derivePadded(privateKeyA, concatBytes(new Uint8Array([2]), compressedPublicKeyB))).rejects.toThrow("Bad public key");
      await expect(ec.derivePadded(privateKeyA, concatBytes(new Uint8Array([3]), compressedPublicKeyB))).rejects.toThrow("Bad public key");
    });

    it("should return a 32-byte Uint8Array", async () => {
      const derived = await ec.derivePadded(privateKeyA, publicKeyB);
      expect(derived.length).toBe(32);
    });
  });

  describe("ECDH", () => {
    let deriveAB: Uint8Array;
    let deriveABUseCompressed: Uint8Array;
    let deriveBA: Uint8Array;
    let deriveBAUseCompressed: Uint8Array;
    let derivePaddedAB: Uint8Array;
    let derivePaddedBA: Uint8Array;

    beforeAll(async () => {
      deriveAB = await ec.derive(privateKeyA, publicKeyB);
      deriveABUseCompressed = await ec.derive(privateKeyA, compressedPublicKeyB);
      deriveBA = await ec.derive(privateKeyB, publicKeyA);
      deriveBAUseCompressed = await ec.derive(privateKeyB, compressedPublicKeyA);
      derivePaddedAB = await ec.derivePadded(privateKeyA, publicKeyB);
      derivePaddedBA = await ec.derivePadded(privateKeyB, publicKeyA);
    });

    it("should be equal: derive(privateKeyA, publicKeyB) == derive(privateKeyB, publicKeyA)", async () => {
      expect(equalBytes(deriveBA, deriveAB)).toBe(true);
    });

    it("should be equal: derive(privateKeyA, publicKeyB) == derivePadded(privateKeyA, publicKeyB)", async () => {
      expect(equalBytes(deriveAB, derivePaddedAB)).toBe(true);
    });

    it("should be equal: derivePadded(privateKeyA, publicKeyB) == derivePadded(privateKeyB, publicKeyA)", async () => {
      expect(equalBytes(derivePaddedBA, derivePaddedAB)).toBe(true);
    });

    it("should be equal: derive(privateKeyA, compressedPublicKeyB) == derive(privateKeyB, compressedPublicKeyA)", async () => {
      expect(equalBytes(deriveABUseCompressed, deriveBAUseCompressed)).toBe(true);
    });

    it("should be equal: derive(privateKeyA, compressedPublicKeyB) == derivePadded(privateKeyA, compressedPublicKeyB)", async () => {
      expect(equalBytes(deriveABUseCompressed, derivePaddedAB)).toBe(true);
    });
  });
});
