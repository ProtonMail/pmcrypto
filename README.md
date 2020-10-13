[![CircleCI](https://circleci.com/gh/ProtonMail/pmcrypto.svg?style=svg)](https://circleci.com/gh/ProtonMail/pmcrypto)


# pmcrypto

# V7
Removed:

* MD5 hash for security concerns

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

init(require('openpgp'));
```



