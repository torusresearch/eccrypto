/* eslint-disable import/no-extraneous-dependencies */
import { beforeEach, describe, expect, it } from "vitest";

import * as ec from "../src/index";

describe("Functions: generatePrivate", () => {
  let privKey: Uint8Array;

  beforeEach(() => {
    privKey = ec.generatePrivate();
  });

  it("should return a Uint8Array", () => {
    expect(privKey instanceof Uint8Array).toBe(true);
  });

  it("should return a 32-byte Uint8Array", () => {
    expect(privKey.length).toBe(32);
  });

  it("should return a unique private key", () => {
    const privKey2 = ec.generatePrivate();
    expect(privKey).not.toEqual(privKey2);
  });
});
