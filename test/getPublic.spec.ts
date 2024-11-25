/* eslint-disable import/no-extraneous-dependencies */
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";

describe("Functions: getPublic", () => {
  let privKey: Buffer, pubKey: Buffer;

  beforeEach(() => {
    privKey = eccrypto.generatePrivate();
    pubKey = eccrypto.getPublic(privKey);
  });

  it("should throw 'Bad private key' if the private key is not 32 bytes", () => {
    expect(() => eccrypto.getPublic(Buffer.alloc(31))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is empty", () => {
    expect(() => eccrypto.getPublic(Buffer.alloc(0))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is not valid", () => {
    // @ts-expect-error private key is not a buffer
    expect(() => eccrypto.getPublic("01234567890123456789012345678912")).toThrow("Bad private key");
    expect(() => eccrypto.getPublic(Buffer.alloc(32))).toThrow("Bad private key");
    expect(() => eccrypto.getPublic(Buffer.from("00", "hex"))).toThrow("Bad private key");
    expect(() => eccrypto.getPublic(Buffer.from("test"))).toThrow("Bad private key");
  });

  it("should return a 65-byte buffer", () => {
    expect(pubKey.length).toBe(65);
  });

  it("should return corresponding public key", () => {
    const pubKey2 = eccrypto.getPublic(privKey);
    expect(pubKey).toEqual(pubKey2);
  });

  it("should return different public keys for different private keys", () => {
    const privKey2 = eccrypto.generatePrivate();
    const pubKey2 = eccrypto.getPublic(privKey2);
    expect(pubKey).not.toEqual(pubKey2);
  });

  it("should return correct public key for predefined private key", () => {
    const givenPrivKey = Buffer.alloc(32).fill(1);
    const returnedPubKey = eccrypto.getPublic(givenPrivKey);
    expect(returnedPubKey.toString("hex")).toBe(
      "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1"
    );
  });
});
