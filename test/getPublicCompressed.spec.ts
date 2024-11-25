/* eslint-disable import/no-extraneous-dependencies */
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";

describe("Functions: getPublicCompressed", () => {
  let privKey: Buffer, compressedPubKey: Buffer;

  beforeEach(() => {
    privKey = eccrypto.generatePrivate();
    compressedPubKey = eccrypto.getPublicCompressed(privKey);
  });

  it("should throw 'Bad private key' if the private key is not 32 bytes", () => {
    expect(() => eccrypto.getPublicCompressed(Buffer.alloc(31))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is empty", () => {
    expect(() => eccrypto.getPublicCompressed(Buffer.alloc(0))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is not valid", () => {
    expect(() => eccrypto.getPublicCompressed(Buffer.alloc(32))).toThrow("Bad private key");
    expect(() => eccrypto.getPublicCompressed(Buffer.from("00", "hex"))).toThrow("Bad private key");
    expect(() => eccrypto.getPublicCompressed(Buffer.from("test"))).toThrow("Bad private key");
  });

  it("should return a 33-byte buffer", () => {
    expect(compressedPubKey.length).toBe(33);
  });

  it("should return corresponding compressed public key", () => {
    const compressedPubKey2 = eccrypto.getPublicCompressed(privKey);
    expect(compressedPubKey).toEqual(compressedPubKey2);
  });

  it("should return different compressed public keys for different private keys", () => {
    const privKey2 = eccrypto.generatePrivate();
    const compressedPubKey2 = eccrypto.getPublicCompressed(privKey2);
    expect(compressedPubKey).not.toEqual(compressedPubKey2);
  });

  it("should return correct compressed public key for predefined private key", () => {
    const givenPrivKey = Buffer.alloc(32).fill(1);
    const returnedCompressedPubKey = eccrypto.getPublicCompressed(givenPrivKey);
    expect(returnedCompressedPubKey.toString("hex")).toBe("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
  });
});
