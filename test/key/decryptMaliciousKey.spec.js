import test from 'ava';
import '../helper';

import { decryptPrivateKey } from '../../lib';

const testPrivateKeyMalicious = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.7.0
Comment: https://openpgpjs.org

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
0NubenKyljKtyHyoU+S+TqUyx7gf5A==
=Lj9k
-----END PGP PRIVATE KEY BLOCK-----
`;

const testPrivateKeyAllDummy = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.7.2
Comment: https://openpgpjs.org

xTsEXh3pJhYJKwYBBAHaRw8BAQdAvUsUrJxExPjhTNDZ3LVLdCgiwuNnNx1J
9cPKKfdrS/f+CWUAR05VAc0hRGFuaWVsIDxkLmh1aWdlbnNAcHJvdG9ubWFp
bC5jb20+wngEEBYKACAFAl4d6SYGCwkHCAMCBBUICgIEFgIBAAIZAQIbAwIe
AQAKCRA942LN2odXWtNCAP40zqtj/LiPyTNf5mVJmd4Ky/M0YW9a+B/OLcMN
q/vwKgEA/A5IlthmEZKaulAHlcy1NrviMR3vHo8ha8E2uxL1GwTHQAReHekm
EgorBgEEAZdVAQUBAQdAYK8adOSzCojxTXcjtjtiPWPWsfhip7PHWqxjm5Lj
83oDAQgH/gllAEdOVQHCYQQYFggACQUCXh3pJgIbDAAKCRA942LN2odXWmWW
AP9P98q90Qny33gXCdpOGs/vCP/aqnygBxOrJ00cm3oF1QD+Llgp9SuhB4YM
BVwyGMu4Utoe7o2jTBfQiSuisOU5rQk=
=tZEz
-----END PGP PRIVATE KEY BLOCK-----`;

test('it fails to decrypt a key with mismatching private and public key parameters', async (t) => {
    const decryptedPrivateKey = decryptPrivateKey(testPrivateKeyMalicious, 'userpass');
    const error = await t.throwsAsync(decryptedPrivateKey);
    t.regex(error.message, /Key is invalid/);
});

test('it fails to decrypt a key with all GNU-dummy key packets', async (t) => {
    const decryptedPrivateKey = decryptPrivateKey(testPrivateKeyAllDummy, 'any password');
    const error = await t.throwsAsync(decryptedPrivateKey);
    t.regex(error.message, /Cannot validate an all-gnu-dummy key/);
});
