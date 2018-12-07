[![CircleCI](https://circleci.com/gh/ProtonMail/pmcrypto.svg?style=svg)](https://circleci.com/gh/ProtonMail/pmcrypto)


# pmcrypto

# V4
openpgp is no longer installed by this library because the client needs to choose which bundle of openpgpjs to use.

Now, pmcrypto must to be initialized with openpgp, btoa and atob using the init function.

```
import { init } from 'pmcrypto';

init({
    openpgp: require('openpgp'),
    atob: require('atob'),
    btoa: require('btoa'),
});
```



