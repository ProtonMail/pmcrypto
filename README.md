[![CircleCI](https://circleci.com/gh/ProtonMail/pmcrypto.svg?style=svg)](https://circleci.com/gh/ProtonMail/pmcrypto)


# pmcrypto

# v7 (WIP)
Changed:

* In `encryptMessage`, `options.data` used to have trailing spaces automatically stripped. Now pass `options.stripTrailingSpaces = true` for the same behaviour
* In `signMessage`, `options.data` used to automatically create a cleartext message. For the same behaviour, if `detached = true`, now pass `textData` with `stripTrailingSpaces`, otherwise pass `cleartextMessageData` (TBD: never used in app -- not implemented for now).

# V6
Added:

* SHA512 hash, exposed as `SHA512`
* MD5 hash, exposed as `unsafeMD5`
* `arrayToHexString`
* `createCleartextMessage`

Changed:

* `getCleartextMessage` now reads an armored message instead of creating one. To create one the `createCleartextMessage` should be used. This is to have consistency with the `getMessage`, `createMessage`, `getSignature` etc functions.

Removed:

* `getHashedPassword` not used.

# V5
openpgp is installed by this library as a dependency. 

However it must be passed to `pmcrypto` because the client needs to choose which bundle of openpgpjs to use.

Now, pmcrypto must to be initialized with openpgp using the init function.

```
import { init } from 'pmcrypto';

init();
```

# Testing
Headless Chrome is used for the tests.
With Chrome installed, running `npm test` should work out of the box.
To use a different Chromium-based browser, set the environment variable `CHROME_BIN` to point to the corresponding executable.


