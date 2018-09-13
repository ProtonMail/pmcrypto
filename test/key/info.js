const pmcrypto = require('../..');
const assert = require('assert');

suite('pmcrypto', () => {
    const publickey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EW5kE2gEEAN3QcfWzMQCniICMlLJg3LgHtobUyQbv+PO1wPbBTdTo5XddwMVO
ef2QN+MNy4UXmRtjUoaWEvHzYQ1a8t10fUI0IyIjc2LhQDm2Wye6xXLrTxV0rWyp
HjC5027fQjaNiyuBUCU9cG78mwZVFTw0lboWryHjqZuBoF2mPHopTaaxABEBAAG0
JWV4cGlyYXRpb24gdGVzdCA8ZXhwaXJhdGlvbkB0ZXN0LmNvbT6IzgQTAQgAOBYh
BPjBOFw5rULVXFVgVMkCMBoLuY3LBQJbmQTaAhsDBQsJCAcCBhUKCQgLAgQWAgMB
Ah4BAheAAAoJEMkCMBoLuY3LwCQD/jCUZkJj8dTNmcn/3lGceL7IxGrh7oFEks9s
bwWsMhi5i6KUxCoYnmm9kp/E1mLDE9JufXzJB+bvaCyCRPjS1hksoCTdcIVOuggc
mtO5I+0ArW32mFHgLK1Dz6JrV8T4jiVkwpuD6YcTlL3O4ebGdCRyK4ICvHmSbRT5
DX9A4XbpuI0EW5kE2gEEAJmcO5EPemO/04X1XFwktOhSFUg7iwGHjNmqv15PhloP
NtjraL0K7rzYrC/cvaOBHQg8Va2MB11HkxUx50C1kBQf8K3BEhcFQwLpDjyocniu
gFqUigNlQLP+xFkaYZfhxajPGzhUe+ja6GjcthYYV0F1QtooaQEy0C0cs7e5Cfot
ABEBAAGIvAQYAQgAJgIbDBYhBPjBOFw5rULVXFVgVMkCMBoLuY3LBQJbmQhHBQkA
AVTtAAoJEMkCMBoLuY3LWr8EANCDuRF0i9SSEo+eDeqsMGPcy56J1rJz6YBrr+sE
hjz72pMy/LgTEucsc2Ag4SBO2ULxDj8A1o8M0wovqol57UgzkyzjqmsndyHgGP5+
Zbrv9MFSY3S4PFCdvQRF4svp/nZ7TFmeX2BLYZH2KIE7m4wKIWsDy30mm33A+VbI
EE1DuI0EW5kIbgEEAM38fxqrvdThdAwH9lSVR6Tb7JE4ASFY0j2EpDft1byBOiDm
sSkdZfaMal4ItHbbqsNeKxDW6DFda0VS5zeamPl2/GD8X/lzyBYrV6iqqRKu4zql
q3JSWRjkhcuJy48IwUQ0OR8cUrqK174cWylXY5mvjqJqxeI+dVxnvLC0lEdtABEB
AAGIvAQYAQgAJhYhBPjBOFw5rULVXFVgVMkCMBoLuY3LBQJbmQhuAhsMBQkJZgGA
AAoJEMkCMBoLuY3L6p8D/jwJkrNLrsBCDEv+7uIQWaXu9dn5sUY1hR2V8eIQo7yp
r7Wg1nvgd7aRzevVrtpn/fowNXaB6pfX1bUl4sRbGAKnF1avn4tPBAAZ5eh67bhO
JLdxTBJgqQoLePyHnb4LEPZItOUOMiHRBLUV8PSj/dxLEmYlmbPFOTnE62izRX4Q
=dM0r
-----END PGP PUBLIC KEY BLOCK-----`;

    test('expiration test', async () => {
        const { expires } = await pmcrypto.keyInfo(publickey);
        assert.ok(expires.getTime() === new Date('2023-09-11T12:37:02.000Z').getTime());
    });
});
