import { expect } from 'chai';
import { checkKeyStrength, checkKeyCompatibility, readKey } from '../../lib';

export const curve25519KeyV6 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----`;

export const curve25519LegacyKeyV4 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYRaiLRYJKwYBBAHaRw8BAQdAMrsrfniSJuxOLn+Q3VKP0WWqgizG4VOF
6t0HZYx8mSnNEHRlc3QgPHRlc3RAYS5pdD7CjAQQFgoAHQUCYRaiLQQLCQcI
AxUICgQWAAIBAhkBAhsDAh4BACEJEKaNwv/NOLSZFiEEnJT1OMsrVBCZa+wE
po3C/804tJnYOAD/YR2og60sJ2VVhPwYRL258dYIHnJXI2dDXB+m76GK9x4A
/imlPnTOgIJAV1xOqkvO96QcbawjKgvH829zxN9DZEgMzjgEYRaiLRIKKwYB
BAGXVQEFAQEHQN5UswYds0RWr4I7xNKNK+fOn+o9pYkkYzJwCbqxCsBwAwEI
B8J4BBgWCAAJBQJhFqItAhsMACEJEKaNwv/NOLSZFiEEnJT1OMsrVBCZa+wE
po3C/804tJkeKgEA0ruKx9rcMTi4LxfYgijjPrI+GgrfegfREt/YN2KQ75gA
/Rs9S+8arbQVoniq7izz3uisWxfjMup+IVEC5uqMld8L
=8+ep
-----END PGP PUBLIC KEY BLOCK-----`;

export const eddsaLegacyElGamalSubkeyV4 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYRU8lhYJKwYBBAHaRw8BAQdAixQ3oWfWg0zF8Dr8iCSKI7d87uR0D8KT
jaXmeP/BFLMAAQC6l0agypEfDhEsPXnooVeQ9RdbuQJt79G0X0fEMJUaHA6L
zQDCjAQQFgoAHQUCYRU+mQQLCQcIAxUICgQWAAIBAhkBAhsDAh4BACEJECU3
cYVou5siFiEEX78JM3S2Y1dhmm1KJTdxhWi7myIj8gEA08yfQM4huuE0HyzB
gfVrSx/tZ7YNIuS8NusuI2C67PAA/2VDK/asD/++J6jeTLf4TojOBgKSNaF2
3OVX3XdjESQNx8F9BGEVFHAQCAChUnflGlhxwxxppDZCIG5RKmvya6PPPjeS
/hhIHhYrvRkPio8bOolG72GW+jwTpkttqhX7hQeYSAuFVLWbvZT6nxxrUDCk
v7eN3pq4YIaIF5UxHucoiE65LNBaa9rtqQdcrn/dT/SCS0YNfIIVqWUeHM1w
sY06CwqQvRfBVbn5GkJqA+RhMF3Pavlb7vz99vDGaQXBqQlIRYWI3pWL2Abs
nG35qzF6mA/gLuEazmdOmdn0RvUUxYUA4pkxVYaFvU+tQfMUFc0KvJgKLU1N
ePtTeT9XxBgxLRAbi0v8ex1R08hFkvc5o7mFrAjiJ5iq7GUib0xSmEl9sa8b
NQ2osvurAAMFB/42M4lEdyeGt+GC7NMI3k6E1s6piyvDFEX0BbWJihYuOmoU
bHIS86NiRXoUUp9fyE4Qj7JLvtBUWxfRw4UsWSX02NZVT9GjpBGBjwpr/kB0
Gev/+mUshgYQjmycxVwsK42P15wNaP09JBf60ONcMswNq4UIhBs936yxwdJ4
EAKesY58vx7Pr+1BClS5338LzoSF8tVsAIdRyN9uC1DM+8IN2o4a/DrYD9Tu
AVCHekvLzt2fX1oAV6HM2S9uaSfXyAkYqTa0EAPHzKthgiFa4IVyCqU9qNXH
LJx6tdMkCFlIrl8R+HiA49AHx5x/n1FCOJ+POIlwfwJGgYrkLqI4F4V3AAFU
CIWprTH3YxjBAAxfs4gj4oVmBwWBC5PfdQpO4a2Rp5eexmDGpyU4T8qesBRb
wngEGBYIAAkFAmEVPpkCGwwAIQkQJTdxhWi7myIWIQRfvwkzdLZjV2GabUol
N3GFaLubIojzAPwNPJX9AwYnd8vuvq4s+JCyG+Gs5a8MeUtAQyMTszhHDwD+
LAhjJS/ggyNCU/A+d6Eu9gacwFDD3j0IQLNe012Z2wU=
=qRad
-----END PGP PRIVATE KEY BLOCK-----`;

export const rsa512BitsKeyV4 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xk0EYRam4gECALVRNFX0hcAEE2+FfdzawLPZJwyk2Lt4Rw/iWk+lBmbWuifM
b7vbYKV2gGBnyEIoo1P6eN6aN7sRFtYYL0uVWB0AEQEAAc0QdGVzdCA8dGVz
dEBhLml0PsKKBBABCAAdBQJhFqbiBAsJBwgDFQgKBBYAAgECGQECGwMCHgEA
IQkQNE7iDhRqacUWIQSvhgc8XQvlU4EgETE0TuIOFGppxa/XAf43Z7Y4marq
wN7RGSinKMFLerNInhaJsyFmHEuNPk3Z1k32EL3007lYemvg5U96KdBn7cos
qOz1E5L+vNW3qcSpzk0EYRam4gECALLIfkJOcpHUYazmmD4e4SuyfDvHxaA5
D1GnOsavGycj5AlYnhGu6mwFFQvhjgNSFIT/l6KZjVxRVci++eH4pXEAEQEA
AcJ2BBgBCAAJBQJhFqbiAhsMACEJEDRO4g4UamnFFiEEr4YHPF0L5VOBIBEx
NE7iDhRqacULrAH6AmBrodF/hjHBy9Ag+m21Q4WcIsRMse4T0arCZgrjmwwZ
m53MXUW1fnpBPuv9RWJDN+tLhm5FPJktpuElr6hcBg==
=J9mf
-----END PGP PUBLIC KEY BLOCK-----`;

describe('key checks', () => {
    it('checkKeyStrength - it warns on insecure primary key (RSA 512 bits)', async () => {
        const key = await readKey({ armoredKey: rsa512BitsKeyV4 });
        expect(
            () => checkKeyStrength(key)
        ).to.throw(/Keys shorter than 2047 bits are considered unsafe/);
    });

    it('checkKeyStrength - it warns on insecure subkey (ElGamal)', async () => {
        const key = await readKey({ armoredKey: eddsaLegacyElGamalSubkeyV4 });
        expect(
            () => checkKeyStrength(key)
        ).to.throw(/elgamal keys are considered unsafe/);
    });

    it('checkKeyStrength - it does not warn on secure key (curve25519Legacy)', async () => {
        const v4Key = await readKey({ armoredKey: curve25519LegacyKeyV4 });
        expect(
            () => checkKeyStrength(v4Key)
        ).to.not.throw();

        const v6Key = await readKey({ armoredKey: curve25519KeyV6 });
        expect(
            () => checkKeyStrength(v6Key)
        ).to.not.throw();
    });

    it('checkKeyCompatibility - it rejects a v4 key using the new EdDSA format', async () => {
        const key = await readKey({ armoredKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----

xiYEZIbSkxsHknQrXGfb+kM2iOsOvin8yE05ff5hF8KE6k+saspAZc0VdXNl
ciA8dXNlckB0ZXN0LnRlc3Q+wocEExsIAD0FAmSG0pMJkEHsytogdrSJFiEE
amc2vcEGXMMaYxmDQezK2iB2tIkCGwMCHgECGQECCwcCFQgCFgADJwcCAABT
nme46ymbAs0X7tX3xWu+9O+LLdM0aAUyV6FwUNWcy47IfmTunwdqHZ2CbUGL
Lb+OR/9yci1aIHDJxXmJh3kj9wDOJgRkhtKTGX6Xe04jkL+7ikivpOB0/ZSq
+fnZr2+76Mf/InbOrpxJwnQEGBsIACoFAmSG0pMJkEHsytogdrSJFiEEamc2
vcEGXMMaYxmDQezK2iB2tIkCGwwAAMJizYj3AFqQi70eHGzhHcmr0XwnsAfL
Gw0vQaiZn6HGITQw5nBGvXQPF9VpFpsXV9x/08dIdfZLAQVdQowgeBsxCw==
=JIkN
-----END PGP PUBLIC KEY BLOCK-----` });
        expect(
            () => checkKeyCompatibility(key)
        ).to.throw(/key algorithm ed25519 is currently not supported/);
    });

    it('checkKeyCompatibility - it rejects a v5 key', async () => {
        const key = await readKey({
            armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xYwFZC7tvxYAAAAtCSsGAQQB2kcPAQEHQP/d1oBAqCKZYxb6k8foyX2Aa/VK
dHFymZPGvHRk1ncs/R0JAQMIrDnS3Bany9EAF6dwQSfPSdObc4ROYIMAnwAA
ADKV1OhGzwANnapimvODI6fK5F7/V0GxETY9WmnipnBzr4Fe9GZw4QD4Q4hd
IJMawjUBrs0MdjVAYWVhZC50ZXN0wpIFEBYKAEQFgmQu7b8ECwkHCAMVCAoE
FgACAQIZAQKbAwIeByKhBQ/Y89PNwfdXUdI/td5Q9rNrYP9mb7Dg6k/3nxTg
ugQ5AyIBAgAAf0kBAJv0OQvd4u8R0f3HAsmQeqMnwNA4or75BOn/ieApNZUt
AP9kQVmYEk4+MV57Us15l2kQEslLDr3qiH5+VCICdEprB8eRBWQu7b8SAAAA
MgorBgEEAZdVAQUBAQdA4IgEkfze3eNKRz6DgzGSJxw/CV/5Rp5u4Imn47h7
pyADAQgH/R0JAQMIwayD3R4E0ugAyszSmOIpaLJ40YGBp5uU7wAAADKmSv4W
tio7GfZCVl8eJ7xX3J1b0iMvEm876tUeHANQlYYCWz+2ahmPVe79zzZA9OhN
FcJ6BRgWCAAsBYJkLu2/ApsMIqEFD9jz083B91dR0j+13lD2s2tg/2ZvsODq
T/efFOC6BDkAAHcjAPwIPNHnR9bKmkVop6cE05dCIpZ/W8zXDGnjKYrrC4Hb
4gEAmISD1GRkNOmCV8aHwN5svO6HuwXR4cR3o3l7HlYeag8=
=wpkQ
-----END PGP PRIVATE KEY BLOCK-----`
        });
        expect(
            () => checkKeyCompatibility(key)
        ).to.throw(/Version 5 keys are currently not supported/);
    });

    it('checkKeyCompatibility - it rejects a v6 key unless explicitly allowed', async () => {
        const key = await readKey({ armoredKey: curve25519KeyV6 });
        expect(
            () => checkKeyCompatibility(key)
        ).to.throw(/Version 6 keys are currently not supported/);
        expect(
            () => checkKeyCompatibility(key, true)
        ).to.not.throw();
    });

    it('checkKeyCompatibility - it does not reject a v4 key using the eddsa legacy format', async () => {
        const key = await readKey({ armoredKey: curve25519LegacyKeyV4 });
        expect(
            () => checkKeyCompatibility(key)
        ).to.not.throw();
    });
});
