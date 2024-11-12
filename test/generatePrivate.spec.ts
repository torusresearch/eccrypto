/* eslint-disable import/no-extraneous-dependencies */
import { beforeEach, describe, expect, it } from "vitest";

import * as eccrypto from "../src/index";

describe("Functions: generatePrivate", () => {
  let privKey: Buffer;

  beforeEach(() => {
    privKey = eccrypto.generatePrivate();
  });

  it("should return a buffer", () => {
    expect(Buffer.isBuffer(privKey)).toBe(true);
  });

  it("should return a 32-byte buffer", () => {
    expect(privKey.length).toBe(32);
  });

  it("should return a unique private key", () => {
    const privKey2 = eccrypto.generatePrivate();
    expect(privKey).not.toEqual(privKey2);
  });
});
