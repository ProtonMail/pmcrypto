# pmcrypto

## v7
Changed:

* `init` no longer accepts a `openpgp` instance: the OpenPGP.js lightweight build for browsers is always used.
* In `encryptMessage`:
  - input message: `options.data` has been replaced by `options.textData/binaryData`, and `options.message` has been removed
  - `options.data` used to have trailing spaces automatically stripped. Now pass `options.stripTrailingSpaces = true` for the same behaviour
  - `options.returnSessionKey` has been removed, now separately generate a session key using e.g. `generateSessionKey` and pass it via `options.sessionKey`.
  - `options.publicKeys` has been renamed to `options.encryptionKeys`, `options.privateKeys` to `options.signingKeys`.
  - `options.armor` has been replaced by `options.format` taking `'armored'|'binary'|'object'`, where `armor: false` corresponds to `format: 'object'` (but it is recommended to use 'binary' or 'armored' instead).
  - output message: `result.message` is always returned for encrypted data (`result.data` has been removed)
* In `decryptMessage`:
  - `options.privateKeys` has been renamed to `options.decryptionKeys`, `options.publicKeys` to `options.verificationKeys`.
  - `errors` has been renamed to `verificationErrors`
  - if the message is signed, and `verificationKeys` are given but none corresponds to the original signing key, a verification error is returned (previously, this didn't return any errors).
* In `signMessage`:
  - input message: `options.data` has been replaced by `options.textData/binaryData`, and `options.message` has been removed
  - `options.data` used to automatically create a cleartext message. For the same behaviour, if `detached = true`, now pass `textData` with `stripTrailingSpaces`. The equivalent for `detached = false` (namely CleartextMessage signing) is not implemented (unused).
  - `options.privateKeys` has been renamed to `options.signingKeys`.
  - `options.armor` has been replaced by `options.format` taking `'armored'|'binary'|'object'`, where `armor: false` corresponds to `format: 'object'` (but it is recommended to use 'binary' or 'armored' instead).

* In `verifyMessage`:
  - `options.publicKeys` has been renamed to `options.verificationKeys`.
  - pass `options.stripTrailingSpaces: true` if the message could contain trailing whitespaces on any line and it was signed by passing `options.data` in previous versions.
  - as in `decryptMessage`, if `verificationKeys` are given but none matches the original, a verification error is returned (previously, this didn't return any errors).
* `generateSessionKey` now takes recipient public keys in input and generates a session key compatible with their key preferences. The former function, which generates a key for a given symmetric algo was renamed `generateSessionKeyForAlgorithm`.

Replaced:
* `getMessage`, `getSignature`, `getCleartextMessage`, `getKey(s)`: use the corresponding `read*` functions instead, which take named inputs to preserve type info (e.g. `readMessage({ armoredMessage })`)
* `decryptPrivateKey`, `encryptPrivateKey`: these performed both parsing/serialization and decryption/encryption. Now, separately parse a binary/armored key using `readPrivateKey` and then pass the result to `decryptKey` or `encryptKey`. These function still do not modify the original `privateKey` instance.

Added
* `readPrivateKey(s)`: similar to `readKey(s)` but expect and return a `PrivateKey` instance
* `generateSessionKeyForAlgorithm`: same as `generateSessionKey` for v6

Removed:
* `createMessage`, `createCleartextMessage`: serialized data is now taken as input directly by `sign/verify/encryptMessage` as `options.text/binaryData`
* `decryptMIMEMessage` (unused)
* `keyCheck` and `keyInfo` (unused)
* snake_case aliases for base64 utils (e.g. `encode_base64`)
* `createWorker` : OpenPGP.js no longer includes a worker. For performance reasons, apps are encouraged to create their own workers.

## Usage
pmcrypto must be initialized using the `init` function, to apply changes to the underlying OpenPGP.js configuration.

```js
import { init } from 'pmcrypto';

init();
```

### Examples
<details>
<summary><b>Encrypt/sign and decrypt/verify string or binary data using keys</b></summary>

#### Encrypt/sign and decrypt/verify string or binary data using keys

To parse and decrypt the keys
```js
const recipientPublicKey = await readKey({ armoredKey: '...' }); // or `binaryKey`
const senderPrivateKey = await decryptKey({
  privateKey: await readPrivateKey({ armoredKey: '...' }),
  passphrase: 'personal key passphrase'
});
```
To encrypt and sign:
```js
const { 
  message: armoredMessage,
  encryptedSignature: armoredEncryptedSignature
} = await encryptMessage({
  textData: 'text data to encrypt', // or `binaryData` for Uint8Arrays
  encryptionKeys: recipientPublicKey, // and/or `passwords`
  signingKeys: senderPrivateKey,
  detached: true,
  format: 'armored' // or 'binary' to output a binary message and signature
});

// share `armoredMessage`
```
To decrypt and verify (non-streamed input):
```js
// load the required keys
const senderPublicKey = await readKey(...);
const recipientPrivateKey = await decryptKey(...);

const { data: decryptedData, verified } = await decryptMessage({
  message: await readMessage({ armoredMessage }), // or `binaryMessage`
  encryptedSignature: await readMessage({ armoredMessage: armoredEncryptedSignature })
  decryptionKeys: recipientPrivateKey // and/or 'passwords'
  verificationKeys: senderPublicKey
});
```

**For streamed inputs:**
to encrypt (and/or sign), pass the stream to `textData` or `binaryData` based on the streamed data type. Similarly, to decrypt and verify, the input options are the same as the non-streaming case. However, if `armoredMessage` (or `binaryMessage`) is a stream, the decryption result needs to be handled differently:
```js
// explicitly loading stream polyfills for legacy browsers is required since v7.2.2
if (!globalThis.TransformStream) {
  await import('web-streams-polyfill/es6');
}

const { data: dataStream, verified: verifiedPromise } = await decryptMessage({
  message: await readMessage({ armoredMessage: streamedArmoredMessage }),
  ... // other options
});

// you need to read `dataStream` before resolving `verifiedPromise`, even if you do not need the decrypted data
const decryptedData = await readToEnd(dataStream);
const verificationStatus = await verified;
```
</details>

<details>
<summary><b>Encrypt/decrypt using the session key</b></summary>

#### Encrypt/decrypt using the session key directly
In v6, `encryptMessage` would return the generated session key if `options.returnSessionKey: true` was given. This option is no longer supported. Instead:
```js
// First generate the session key
const sessionKey = await generateSessionKey({ recipientKeys: recipientPublicKey });

// Then encrypt the data with it
const { message: armoredMessage } = await encryptMessage({
  textData: 'text data to encrypt', // or `binaryData` for Uint8Arrays
  sessionKey,
  encryptionKeys: recipientPublicKey, // and/or `passwords`, used to encrypt the session key
  signingKeys: senderPrivateKey,
});
```

To decrypt, you can again provide the session key directly:
```js

// Then encrypt the data with it
const { data } = await decryptMessage({
  message: await readMessage({ armoredMessage }),
  sessionKeys: sessionKey,
  verificationKeys: senderPublicKey,
});
```
You can also encrypt the session key on its own:
```js
const armoredEncryptedSessionKey = await encryptSessionKey({
  sessionKey,
  encryptionKeys, // and/or passwords
  format: 'armored'
});

// And decrypt it with:
const sessionKey = await decryptSessionKey({
  message: await readMessage({ armoredMessage: armoredEncryptedSessionKey }),
  decryptionsKeys // and/or passwords
});

```
</details>

## Testing
Headless Chrome (or Chromium), Firefox and Webkit are used for the tests.
To install any missing browsers automatically, you can run `npx playwright install --with-deps <chromium|firefox|webkit>`. Alternatively, you can install them manually as you normally would on your platform.
If you'd like to test on a subset of browsers, use e.g. `npm test -- --browsers ChromeHeadless,FirefoxHeadless`.


