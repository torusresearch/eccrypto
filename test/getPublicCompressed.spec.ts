/* eslint-disable import/no-extraneous-dependencies */
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { beforeEach, describe, expect, it } from "vitest";

import * as ec from "../src/index";

describe("Functions: getPublicCompressed", () => {
  let privKey: Uint8Array;
  let compressedPubKey: Uint8Array;

  beforeEach(() => {
    privKey = ec.generatePrivate();
    compressedPubKey = ec.getPublicCompressed(privKey);
  });

  it("should throw 'Bad private key' if the private key is not 32 bytes", () => {
    expect(() => ec.getPublicCompressed(new Uint8Array(31))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is empty", () => {
    expect(() => ec.getPublicCompressed(new Uint8Array(0))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is not valid", () => {
    expect(() => ec.getPublicCompressed(new Uint8Array(32))).toThrow("Bad private key");
    expect(() => ec.getPublicCompressed(hexToBytes("00"))).toThrow("Bad private key");
    expect(() => ec.getPublicCompressed(new TextEncoder().encode("test"))).toThrow("Bad private key");
  });

  it("should return a 33-byte Uint8Array", () => {
    expect(compressedPubKey.length).toBe(33);
  });

  it("should return corresponding compressed public key", () => {
    const compressedPubKey2 = ec.getPublicCompressed(privKey);
    expect(compressedPubKey).toEqual(compressedPubKey2);
  });

  it("should return different compressed public keys for different private keys", () => {
    const privKey2 = ec.generatePrivate();
    const compressedPubKey2 = ec.getPublicCompressed(privKey2);
    expect(compressedPubKey).not.toEqual(compressedPubKey2);
  });

  it("should return correct compressed public key for predefined private key", () => {
    const givenPrivKey = new Uint8Array(32).fill(1);
    const returnedCompressedPubKey = ec.getPublicCompressed(givenPrivKey);
    expect(bytesToHex(returnedCompressedPubKey)).toBe("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
  });
});
