[![CircleCI](https://circleci.com/gh/ProtonMail/pmcrypto.svg?style=svg)](https://circleci.com/gh/ProtonMail/pmcrypto)


# pmcrypto

# Changelog:

## V6

Now includes SRP and hash password functionality

## V5
openpgp is installed by this library as a dependency. 

However it must be passed to `pmcrypto` because the client needs to choose which bundle of openpgpjs to use.

Now, once openpgp is loaded, pmcrypto must to be initialized with openpgp using the init function.

```
import { init } from 'pmcrypto';

init(require('openpgp'));
```



