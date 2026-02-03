/**
 * Backward Compatibility Tests
 *
 * These tests ensure that the new @noble/curves implementation produces
 * the same results as the old elliptic-based implementation.
 *
 * Uses the old @toruslabs/eccrypto@5.0.4 (aliased as "eccrypto-old")
 * which was the last version using the elliptic library.
 */
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";

import * as eccryptoOld from "eccrypto-old";
import * as eccryptoNew from "../src/index";

function toUint8Array(buf: Buffer | Uint8Array): Uint8Array {
  if (buf instanceof Uint8Array && !(buf instanceof Buffer)) {
    return buf;
  }
  return new Uint8Array(buf);
}

describe("Backward Compatibility: derive functions", () => {
  const testVectors = [
    {
      name: "Standard key pair",
      privateKeyA: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      publicKeyB:
        "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9",
    },
    {
      name: "Another standard pair",
      privateKeyA: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
      publicKeyB:
        "04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
    },
    {
      name: "Key pair 3",
      privateKeyA: "0000000000000000000000000000000000000000000000000000000000000001",
      publicKeyB:
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    },
  ];

  describe("derive (unpadded)", () => {
    testVectors.forEach((vector) => {
      it(`should match old eccrypto output: ${vector.name}`, async () => {
        const privateKeyA = hexToBytes(vector.privateKeyA);
        const publicKeyB = hexToBytes(vector.publicKeyB);
        const oldResult = await eccryptoOld.derive(Buffer.from(privateKeyA), Buffer.from(publicKeyB));
        const newResult = await eccryptoNew.derive(privateKeyA, publicKeyB);

        expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
      });
    });

    it("should match old library with compressed public key", async () => {
      const privateKeyA = hexToBytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
      // Compressed version of the public key
      const publicKeyBCompressed = hexToBytes("02b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f");

      const oldResult = await eccryptoOld.derive(Buffer.from(privateKeyA), Buffer.from(publicKeyBCompressed));
      const newResult = await eccryptoNew.derive(privateKeyA, publicKeyBCompressed);

      expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
    });
  });

  describe("derivePadded", () => {
    testVectors.forEach((vector) => {
      it(`should match old eccrypto output: ${vector.name}`, async () => {
        const privateKeyA = hexToBytes(vector.privateKeyA);
        const publicKeyB = hexToBytes(vector.publicKeyB);

        const oldResult = await eccryptoOld.derivePadded(Buffer.from(privateKeyA), Buffer.from(publicKeyB));
        const newResult = await eccryptoNew.derivePadded(privateKeyA, publicKeyB);

        expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
        // derivePadded should always return 32 bytes
        expect(newResult.length).toBe(32);
        expect(oldResult.length).toBe(32);
      });
    });

    it("should match old library with compressed public key", async () => {
      const privateKeyA = hexToBytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
      const publicKeyBCompressed = hexToBytes("02b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f");

      const oldResult = await eccryptoOld.derivePadded(Buffer.from(privateKeyA), Buffer.from(publicKeyBCompressed));
      const newResult = await eccryptoNew.derivePadded(privateKeyA, publicKeyBCompressed);

      expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
    });
  });

  describe("Random key pairs - dynamic comparison", () => {
    it("should match old library for randomly generated keys (derive)", async () => {
      for (let i = 0; i < 10; i++) {
        const privateKeyA = eccryptoNew.generatePrivate();
        const privateKeyB = eccryptoNew.generatePrivate();
        const publicKeyB = eccryptoNew.getPublic(privateKeyB);

        const oldResult = await eccryptoOld.derive(Buffer.from(privateKeyA), Buffer.from(publicKeyB));
        const newResult = await eccryptoNew.derive(privateKeyA, publicKeyB);

        expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
      }
    });

    it("should match old library for randomly generated keys (derivePadded)", async () => {
      for (let i = 0; i < 10; i++) {
        const privateKeyA = eccryptoNew.generatePrivate();
        const privateKeyB = eccryptoNew.generatePrivate();
        const publicKeyB = eccryptoNew.getPublic(privateKeyB);

        const oldResult = await eccryptoOld.derivePadded(Buffer.from(privateKeyA), Buffer.from(publicKeyB));
        const newResult = await eccryptoNew.derivePadded(privateKeyA, publicKeyB);

        expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
      }
    });

    it("should match old library with compressed public keys", async () => {
      for (let i = 0; i < 10; i++) {
        const privateKeyA = eccryptoNew.generatePrivate();
        const privateKeyB = eccryptoNew.generatePrivate();
        const publicKeyBCompressed = eccryptoNew.getPublicCompressed(privateKeyB);

        const oldResult = await eccryptoOld.derive(Buffer.from(privateKeyA), Buffer.from(publicKeyBCompressed));
        const newResult = await eccryptoNew.derive(privateKeyA, publicKeyBCompressed);

        expect(bytesToHex(newResult)).toBe(bytesToHex(toUint8Array(oldResult)));
      }
    });
  });

  describe("ECDH symmetry with old library", () => {
    it("derive(A, pubB) == derive(B, pubA) - both old and new", async () => {
      const privateKeyA = eccryptoNew.generatePrivate();
      const publicKeyA = eccryptoNew.getPublic(privateKeyA);
      const privateKeyB = eccryptoNew.generatePrivate();
      const publicKeyB = eccryptoNew.getPublic(privateKeyB);

      // Old library
      const oldAB = await eccryptoOld.derive(Buffer.from(privateKeyA), Buffer.from(publicKeyB));
      const oldBA = await eccryptoOld.derive(Buffer.from(privateKeyB), Buffer.from(publicKeyA));

      // New library
      const newAB = await eccryptoNew.derive(privateKeyA, publicKeyB);
      const newBA = await eccryptoNew.derive(privateKeyB, publicKeyA);

      // ECDH symmetry
      expect(bytesToHex(toUint8Array(oldAB))).toBe(bytesToHex(toUint8Array(oldBA)));
      expect(bytesToHex(newAB)).toBe(bytesToHex(newBA));

      // Old == New
      expect(bytesToHex(newAB)).toBe(bytesToHex(toUint8Array(oldAB)));
    });
  });
});

describe("Backward Compatibility: sign/verify", () => {
  it("should produce DER-encoded signatures compatible with old library verification", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const msg = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    const signature = await eccryptoNew.sign(privateKey, msg);

    // Verify signature format is DER
    expect(signature[0]).toBe(0x30); // SEQUENCE tag

    // Old library should verify new library's signature
    await expect(eccryptoOld.verify(Buffer.from(publicKey), Buffer.from(msg), Buffer.from(signature))).resolves.toBeNull();
  });

  it("old library signature should be verifiable by new library", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const msg = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    // Sign with old library
    const oldSignature = await eccryptoOld.sign(Buffer.from(privateKey), Buffer.from(msg));

    // Verify with new library
    await expect(eccryptoNew.verify(publicKey, msg, toUint8Array(oldSignature))).resolves.toBeNull();
  });

  it("new library signature should be verifiable by old library", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const msg = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    // Sign with new library
    const newSignature = await eccryptoNew.sign(privateKey, msg);

    // Verify with old library
    await expect(eccryptoOld.verify(Buffer.from(publicKey), Buffer.from(msg), Buffer.from(newSignature))).resolves.toBeNull();
  });
});

describe("Backward Compatibility: getPublic/getPublicCompressed", () => {
  const testKeys = [
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    "0000000000000000000000000000000000000000000000000000000000000001",
  ];

  testKeys.forEach((privateKeyHex) => {
    it(`should match old library getPublic: ${privateKeyHex.slice(0, 16)}...`, () => {
      const privateKey = hexToBytes(privateKeyHex);

      const oldPublic = eccryptoOld.getPublic(Buffer.from(privateKey));
      const newPublic = eccryptoNew.getPublic(privateKey);

      expect(bytesToHex(newPublic)).toBe(bytesToHex(toUint8Array(oldPublic)));
    });

    it(`should match old library getPublicCompressed: ${privateKeyHex.slice(0, 16)}...`, () => {
      const privateKey = hexToBytes(privateKeyHex);

      const oldPublicCompressed = eccryptoOld.getPublicCompressed(Buffer.from(privateKey));
      const newPublicCompressed = eccryptoNew.getPublicCompressed(privateKey);

      expect(bytesToHex(newPublicCompressed)).toBe(bytesToHex(toUint8Array(oldPublicCompressed)));
    });
  });

  it("should match old library for randomly generated keys", () => {
    for (let i = 0; i < 10; i++) {
      const privateKey = eccryptoNew.generatePrivate();

      const oldPublic = eccryptoOld.getPublic(Buffer.from(privateKey));
      const newPublic = eccryptoNew.getPublic(privateKey);

      const oldCompressed = eccryptoOld.getPublicCompressed(Buffer.from(privateKey));
      const newCompressed = eccryptoNew.getPublicCompressed(privateKey);

      expect(bytesToHex(newPublic)).toBe(bytesToHex(toUint8Array(oldPublic)));
      expect(bytesToHex(newCompressed)).toBe(bytesToHex(toUint8Array(oldCompressed)));
    }
  });
});

describe("Backward Compatibility: encrypt/decrypt", () => {
  it("should decrypt message encrypted by old library", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const msg = new TextEncoder().encode("Hello, World!");

    // Encrypt with old library
    const encrypted = await eccryptoOld.encrypt(Buffer.from(publicKey), Buffer.from(msg));

    // Decrypt with new library
    const decrypted = await eccryptoNew.decrypt(privateKey, {
      iv: toUint8Array(encrypted.iv),
      ephemPublicKey: toUint8Array(encrypted.ephemPublicKey),
      ciphertext: toUint8Array(encrypted.ciphertext),
      mac: toUint8Array(encrypted.mac),
    });

    expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!");
  });

  it("should allow old library to decrypt message encrypted by new library", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const msg = new TextEncoder().encode("Hello, World!");

    // Encrypt with new library
    const encrypted = await eccryptoNew.encrypt(publicKey, msg);

    // Decrypt with old library
    const decrypted = await eccryptoOld.decrypt(Buffer.from(privateKey), {
      iv: Buffer.from(encrypted.iv),
      ephemPublicKey: Buffer.from(encrypted.ephemPublicKey),
      ciphertext: Buffer.from(encrypted.ciphertext),
      mac: Buffer.from(encrypted.mac),
    });

    expect(new TextDecoder().decode(toUint8Array(decrypted))).toBe("Hello, World!");
  });

  it("should handle encryption with specific options", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const ephemPrivateKey = eccryptoNew.generatePrivate();
    const iv = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const msg = new TextEncoder().encode("Test message with specific options");

    // Encrypt with new library using specific options
    const encryptedNew = await eccryptoNew.encrypt(publicKey, msg, { iv, ephemPrivateKey });

    // Encrypt with old library using same options
    const encryptedOld = await eccryptoOld.encrypt(Buffer.from(publicKey), Buffer.from(msg), {
      iv: Buffer.from(iv),
      ephemPrivateKey: Buffer.from(ephemPrivateKey),
    });

    // Both should produce the same ciphertext
    expect(bytesToHex(encryptedNew.ciphertext)).toBe(bytesToHex(toUint8Array(encryptedOld.ciphertext)));
    expect(bytesToHex(encryptedNew.mac)).toBe(bytesToHex(toUint8Array(encryptedOld.mac)));
    expect(bytesToHex(encryptedNew.ephemPublicKey)).toBe(bytesToHex(toUint8Array(encryptedOld.ephemPublicKey)));
  });

  it("should decrypt message encrypted by old library with padding=true", async () => {
    const privateKey = eccryptoNew.generatePrivate();
    const publicKey = eccryptoNew.getPublic(privateKey);
    const msg = new TextEncoder().encode("Hello with padding!");

    // Encrypt with old library using padding=true
    const encrypted = await eccryptoOld.encrypt(Buffer.from(publicKey), Buffer.from(msg), {
      padding: true,
    });

    // Decrypt with new library - should handle padded encryption
    const decrypted = await eccryptoNew.decrypt(privateKey, {
      iv: toUint8Array(encrypted.iv),
      ephemPublicKey: toUint8Array(encrypted.ephemPublicKey),
      ciphertext: toUint8Array(encrypted.ciphertext),
      mac: toUint8Array(encrypted.mac),
    });

    expect(new TextDecoder().decode(decrypted)).toBe("Hello with padding!");
  });
});
