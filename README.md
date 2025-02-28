# pmcrypto

pmcrypto v8 introduces support for [RFC9580](https://datatracker.ietf.org/doc/rfc9580/) (via [OpenPGP.js v6](https://github.com/openpgpjs/openpgpjs/releases/tag/v6.0.0)), which standardizes new OpenPGP packets and algorithms, such as v6 keys and AEAD encryption for keys and messages. The [OpenPGP PQC RFC draft](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) also builds on top of RFC9580.

The new entities are not supported across Proton clients yet, and most of the library changes compared to v7 are internal, and are about ensuring we don't unexpectedly produce (or accept, e.g. for key imports), artifacts that will break some of our existing clients.

API changes:

- `checkKeyCompatibility`:
  - reject v5 keys (breaking change: these were supported by pmcrypto v7, as they were introduced in draft RFC4880bis, but we are dropping support as they haven't been standardized)
  - add `v6KeysAllowed` argument (defaulting to false) to accept v6 keys


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
To install any missing browsers automatically, you can run `npx playwright install --with-deps <chromium|firefox|webkit|firefox-beta>`. Alternatively, you can install them manually as you normally would on your platform.

The available test commands are:

- `npm run test`: all browsers are tested in headless mode.
- `npm run test:ci`: similar to `test`, but beta browser versions are used if the vendor provides them; also, Webkit is skipped if not installed.
- `npm run test:debug`: opens up a browser instance in your default browser to allow debugging the tests live

