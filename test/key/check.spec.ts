import test from 'ava';
import '../helper';
import { checkKeyStrength } from '../../lib';
import { readKey } from 'openpgp';

const ecc25519Key = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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

const eddsaElGamalSubkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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

const rsa512BitsKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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

test('it warns on insecure primary key (RSA 512 bits)', async (t) => {
    const key = await readKey({ armoredKey: rsa512BitsKey, config: { minRSABits: 0 } });
    const error = t.throws(() => checkKeyStrength(key));
    t.is(error.message, 'Keys shorter than 2047 bits are considered unsafe');
});

test('it warns on insecure subkey (ElGamal)', async (t) => {
    const key = await readKey({ armoredKey: eddsaElGamalSubkey });
    const error = t.throws(() => checkKeyStrength(key));
    t.is(error.message, 'elgamal keys are considered unsafe');
});

test('it does not warn on secure key (x25519)', async (t) => {
    const key = await readKey({ armoredKey: ecc25519Key });
    checkKeyStrength(key);
    t.pass();
});
