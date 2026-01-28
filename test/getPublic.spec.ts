/* eslint-disable import/no-extraneous-dependencies */
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { beforeEach, describe, expect, it } from "vitest";

import * as ec from "../src/index";

describe("Functions: getPublic", () => {
  let privKey: Uint8Array;
  let pubKey: Uint8Array;

  beforeEach(() => {
    privKey = ec.generatePrivate();
    pubKey = ec.getPublic(privKey);
  });

  it("should throw 'Bad private key' if the private key is not 32 bytes", () => {
    expect(() => ec.getPublic(new Uint8Array(31))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is empty", () => {
    expect(() => ec.getPublic(new Uint8Array(0))).toThrow("Bad private key");
  });

  it("should throw 'Bad private key' if private key is not valid", () => {
    // @ts-expect-error private key is not a Uint8Array
    expect(() => ec.getPublic("01234567890123456789012345678912")).toThrow();
    expect(() => ec.getPublic(new Uint8Array(32))).toThrow("Bad private key");
    expect(() => ec.getPublic(hexToBytes("00"))).toThrow("Bad private key");
    expect(() => ec.getPublic(new TextEncoder().encode("test"))).toThrow("Bad private key");
  });

  it("should return a 65-byte Uint8Array", () => {
    expect(pubKey.length).toBe(65);
  });

  it("should return corresponding public key", () => {
    const pubKey2 = ec.getPublic(privKey);
    expect(pubKey).toEqual(pubKey2);
  });

  it("should return different public keys for different private keys", () => {
    const privKey2 = ec.generatePrivate();
    const pubKey2 = ec.getPublic(privKey2);
    expect(pubKey).not.toEqual(pubKey2);
  });

  it("should return correct public key for predefined private key", () => {
    const givenPrivKey = new Uint8Array(32).fill(1);
    const returnedPubKey = ec.getPublic(givenPrivKey);
    expect(bytesToHex(returnedPubKey)).toBe(
      "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1"
    );
  });
});
