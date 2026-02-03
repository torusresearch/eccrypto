# eccrypto

![Build Status](https://github.com/torusresearch/eccrypto/actions/workflows/master.yml/badge.svg)

[![npm downloads](https://img.shields.io/npm/dm/@toruslabs/eccrypto.svg?style=flat-square)](https://www.npmjs.com/package/@toruslabs/eccrypto)

[![NPM](https://nodei.co/npm/@toruslabs/eccrypto.png)](https://www.npmjs.com/package/@toruslabs/eccrypto)

JavaScript Elliptic curve cryptography library for both browserify and node.

## Motivation

- ECDSA (sign/verify)
- ECDH (key agreement)
- ECIES (encrypt/decrypt)
- secp256k1 curve support
- Compressed and uncompressed public key support
- Works in both Node.js and browsers
- Uses `Uint8Array` for all binary data

## Implementation details

This library uses [`@noble/curves`](https://github.com/paulmillr/noble-curves) for elliptic curve operations, which provides:

- Use Node.js crypto module/library bindings where possible
- Use WebCryptoAPI where possible
- Promise-driven API
- Only secp256k1 curve, only SHA-512 (KDF), HMAC-SHA-256 (HMAC) and AES-256-CBC for ECIES
- Compressed key support

### Native crypto API limitations

#### crypto

```bash
npm install @toruslabs/eccrypto
```

#### WebCryptoAPI

ECDSA and ECDH are supported in Chrome [only on Windows](https://sites.google.com/a/chromium.org/dev/blink/webcrypto#TOC-Supported-algorithms-as-of-Chrome-41-) (see also [bug 338883](https://code.google.com/p/chromium/issues/detail?id=338883)), aren't supported by Firefox (fixed only in 36.0+, see [bug 1034854](https://bugzilla.mozilla.org/show_bug.cgi?id=1034854); see also [feature matrix](https://docs.google.com/spreadsheet/ccc?key=0AiAcidBZRLxndE9LWEs2R1oxZ0xidUVoU3FQbFFobkE#gid=1)) and ECIES is not defined at all in WebCryptoAPI draft. Also WebCryptoAPI [currently defines](http://www.w3.org/TR/WebCryptoAPI/#EcKeyGenParams-dictionary) only curves recommended by NIST meaning that secp256k1 (K-256) curve is not supported (see also: [[1]](http://lists.w3.org/Archives/Public/public-webcrypto-comments/2013Dec/0001.html), [[2]](https://bugzilla.mozilla.org/show_bug.cgi?id=1051509)).

```ts
import * as eccrypto from "@toruslabs/eccrypto";

// Generate a new random 32-byte private key
const privateKey = eccrypto.generatePrivate();

// Get the corresponding public key (65 bytes uncompressed)
const publicKey = eccrypto.getPublic(privateKey);

// Or get compressed public key (33 bytes)
const compressedPublicKey = eccrypto.getPublicCompressed(privateKey);

// Message must be 32 bytes or less (typically a hash)
const msgHash = new Uint8Array(32); // Your message hash here

// Sign the message
const signature = await eccrypto.sign(privateKey, msgHash);
console.log("Signature (DER format):", signature);

// Verify the signature
try {
  await eccrypto.verify(publicKey, msgHash, signature);
  console.log("Signature is valid");
} catch (e) {
  console.log("Signature is invalid");
}
```

### ECDH (Key Agreement)

```ts
import * as eccrypto from "@toruslabs/eccrypto";

const privateKeyA = eccrypto.generatePrivate();
const publicKeyA = eccrypto.getPublic(privateKeyA);

const privateKeyB = eccrypto.generatePrivate();
const publicKeyB = eccrypto.getPublic(privateKeyB);

// Both parties derive the same shared secret
const sharedSecretA = await eccrypto.derive(privateKeyA, publicKeyB);
const sharedSecretB = await eccrypto.derive(privateKeyB, publicKeyA);

// sharedSecretA and sharedSecretB are equal
console.log("Shared secrets match:", sharedSecretA.toString() === sharedSecretB.toString());
```

### ECIES (Encrypt/Decrypt)

```ts
import * as eccrypto from "@toruslabs/eccrypto";

const privateKeyA = eccrypto.generatePrivate();
const publicKeyA = eccrypto.getPublic(privateKeyA);

const privateKeyB = eccrypto.generatePrivate();
const publicKeyB = eccrypto.getPublic(privateKeyB);

// Encrypt a message for B
const message = new TextEncoder().encode("Hello, World!");
const encrypted = await eccrypto.encrypt(publicKeyB, message);

// B decrypts the message
const decrypted = await eccrypto.decrypt(privateKeyB, encrypted);
console.log("Decrypted:", new TextDecoder().decode(decrypted));
```

## API

### `generatePrivate(): Uint8Array`

Generate a new random 32-byte private key.

### `getPublic(privateKey: Uint8Array): Uint8Array`

Get the 65-byte uncompressed public key from a private key.

### `getPublicCompressed(privateKey: Uint8Array): Uint8Array`

Get the 33-byte compressed public key from a private key.

### `sign(privateKey: Uint8Array, msg: Uint8Array): Promise<Uint8Array>`

Sign a message (max 32 bytes) with a private key. Returns DER-encoded signature.

### `verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<null>`

Verify a signature. Throws an error if the signature is invalid.

### `derive(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>`

Derive a shared secret using ECDH.

### `encrypt(publicKey: Uint8Array, msg: Uint8Array, opts?): Promise<Ecies>`

Encrypt a message using ECIES. Returns an object with `iv`, `ephemPublicKey`, `ciphertext`, and `mac`.

### `decrypt(privateKey: Uint8Array, opts: Ecies): Promise<Uint8Array>`

Decrypt an ECIES encrypted message.

## License

eccrypto - JavaScript Elliptic curve cryptography library

Written in 2014-2015 by Kagami Hiiragi <kagami@genshiken.org>

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
