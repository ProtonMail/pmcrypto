import test from 'ava';
import '../helper';
import * as pmcrypto from '../../lib/pmcrypto';
import { openpgp } from '../../lib/openpgp';

test.serial('sha256 fingerprints - v4 key', async (t) => {
    openpgp.config.v5_keys = !openpgp.config.v5_keys;
    const { publicKeyArmored } = await pmcrypto.generateKey({ userIds: [{}], passphrase: 'test' });
    const { fingerprints, sha256Fingerprints } = await pmcrypto.keyInfo(publicKeyArmored);
    t.is(sha256Fingerprints.length, fingerprints.length);
    sha256Fingerprints.forEach((sha256Fingerprint, i) => {
        t.not(sha256Fingerprint, fingerprints[i]);
    });
    openpgp.config.v5_keys = !openpgp.config.v5_keys;
});

test('sha256 fingerprints - v5 key', async (t) => {
    const { publicKeyArmored } = await pmcrypto.generateKey({ userIds: [{}], passphrase: 'test' });
    const { fingerprints, sha256Fingerprints } = await pmcrypto.keyInfo(publicKeyArmored);
    t.is(sha256Fingerprints.length, fingerprints.length);
    sha256Fingerprints.forEach((sha256Fingerprint, i) => {
        t.is(sha256Fingerprint, fingerprints[i]);
    });
});

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

test('expiration test', async (t) => {
    const { expires, dateError } = await pmcrypto.keyInfo(publickey);
    t.is(expires.getTime(), new Date('2023-09-11T12:37:02.000Z').getTime());
    t.is(dateError, null);
});

const creationkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v3.0.5
Comment: https://openpgpjs.org

xsBNBFgsrPkBCAC4NTH8ew1ASUtqVRA3j+aolI5lMAmAER18fBIfwjd/IbtC
XzYbi/+arYyIMzUXU3OZUTwifxV3PBu1FCq1ZxVvZyH2ZoliP5fwx39bv3sI
Oo1ijtxUKgVXmu+o4N5y3dhAjO9UYFza5Wq8TjmNdPhHp/PEd1+qMK8W3cxm
8Ly7du9zv3nQ1B5M5/uGoo4FyQxKdh4wX6lJnAjYI0g/kfj/zfzaPyjiRurB
wuXrRYVcliUQy3OP/fera5VJOhGzb6/Kycth0dgBsMPsn8gx8VOHPiHDcXlv
vwp6drbCXujReU+hZgPda/eqhafjQDbCAfs5ZJD/B4/6SF8IMQ+Z9gjVABEB
AAHNNSJzaGFudGFyYW1AcHJvdG9ubWFpbC5jb20iIDxzaGFudGFyYW1AcHJv
dG9ubWFpbC5jb20+wsB1BBABCAApBQJcaFwkBgsJBwgDAgkQbolVqMpNxdsE
FQgKAgMWAgECGQECGwMCHgEAACzfB/9t+McxCVvVqUQblF1phnV8mKC9uPcU
5yPEu07lRoJw3D3qusK25iDVwLGNS3Mx2G2ugHx6I/ik60LPDrOXgH44k90b
LnyUIUGUFX61Rzn/Un637dw1o2+kOfQzN4SYce/rwPvF1efAnZiwSoVhy+Ks
oV0MHA8QeP4woMhL6y014tJDrqHGXIk6KTMLp+CR/5gBlHaVihVIZsTgLj01
y2J6NykjPVPy5CGFju457jaWcsxpaO308fQGUB5hhelJvKzUt9zpDL0Dyr2O
sFVnKhDts5EoVE13Yp4BrZslvXR7PZqoaMNOXr8uSIWt6khe06aPH8cSBtCu
MtsgAlmN08vxzsBNBFgsrPkBCADxmOuZvx1fMLxYr/08a/b3dZfncP1fA1PH
66mkUo9kE5Zr5UOqqbbFaCQbuc54nE4pvAJgR6EaynrnzjfbX75/v0ElEhZq
cAWEXgM+A+WwPD3KTpAcMDXd42lPkq1lHH7ExN4UsYfrqSF7T7GVMZpo30wC
IOYBBbYAZUCiDmSjeLTE1iLx14G6GMxniL+3TvUWUSF5waabouzV6vYlBlok
lby0vw7gyvexkPOQgG/u4lmsvNYRGl3UcVbecu2yS94RhBm/TG5kA+eaa8mc
jBZsMZ2GcfDfMZZLrP/5KwjLJ9OTrV9yDM0D6F6sAVlBF4l0MyOXl8ov/Qc/
bsdDA+J9ABEBAAHCwF8EGAEIABMFAlxoXCoJEG6JVajKTcXbAhsMAADltAf/
TbsN49vres/68RKkg3C4wihCTzSujrFYOxeKJOZALynTvMTwpjKmYik7zaJT
+25WxK0P3IknYKpsUFlDtIBluvdz4McZLEH0ymNwsi3hsnEG3l2W18JdKdzl
RLfkk/sT5Ay2LtjvPUmynkGvI3LFRkkqiA4buDiFOV/pqdV6RGIXEOcyMyPJ
hufD30wViByeDdxpJsFOlVnw7D02WDNUHomhN2m8ogLJyFbfrG8/c54VmX6O
J5Tj5Die5J5mSWCHbi9O0TBBgCysDxAr7blqK2xBO85q+Kp0809lPiS97iDq
uokpJQHZjIvfQ5/9tx1946Tvo0RX0A26JfOO+J68XA==
=MPBF
-----END PGP PUBLIC KEY BLOCK-----`;

test('creation test', async (t) => {
    const { dateError } = await pmcrypto.keyInfo(
        creationkey,
        undefined,
        undefined,
        new Date('2019-01-01T00:00:00.000Z')
    );
    t.is(dateError, 'The self certifications are created with illegal times');
});

test('invalid key', async (t) => {
    const { validationError } = await pmcrypto.keyInfo(publickey);
    t.is(validationError, 'Key is less than 2048 bits');
});

test('valid key', async (t) => {
    const { validationError } = await pmcrypto.keyInfo(creationkey);
    t.is(validationError, null);
});

test('newly generated RSA key', async (t) => {
    const { publicKeyArmored } = await pmcrypto.generateKey({ userIds: [{}], passphrase: 'test' });
    const { validationError } = await pmcrypto.keyInfo(publicKeyArmored);
    t.is(validationError, null);
});

test('newly generated ECC key', async (t) => {
    const { publicKeyArmored } = await pmcrypto.generateKey({ userIds: [{}], passphrase: 'test', curve: 'curve25519' });
    const { validationError } = await pmcrypto.keyInfo(publicKeyArmored);
    t.is(validationError, null);
});

test('newly generated ECC key: invalid curve', async (t) => {
    const { publicKeyArmored } = await pmcrypto.generateKey({ userIds: [{}], passphrase: 'test', curve: 'secp256k1' });
    const { validationError } = await pmcrypto.keyInfo(publicKeyArmored);
    t.is(validationError, 'Key must use Curve25519, P-256, P-384 or P-521');
});
