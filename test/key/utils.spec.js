import test from 'ava';
import '../helper';
import {
    concatArrays,
    decodeBase64,
    encodeBase64,
    stripArmor,
    binaryStringToArray,
    genPublicEphemeralKey,
    genPrivateEphemeralKey
} from '../../lib/pmcrypto';

test('it can correctly encode base 64', async (t) => {
    t.is(encodeBase64('foo'), 'Zm9v');
});

test('it can correctly decode base 64', async (t) => {
    t.is(decodeBase64('Zm9v'), 'foo');
});

test('it can correctly concat arrays', async (t) => {
    t.deepEqual(concatArrays([new Uint8Array(1), new Uint8Array(1)]), new Uint8Array(2));
});

test('it can correctly dearmor a message', async (t) => {
    const x = await stripArmor(`
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.19 (GNU/Linux)

jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg
GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==
=VZ0/
-----END PGP MESSAGE-----`);
    t.deepEqual(
        x,
        new Uint8Array([
            140,
            13,
            4,
            9,
            3,
            2,
            166,
            142,
            200,
            241,
            106,
            172,
            121,
            180,
            201,
            210,
            74,
            1,
            154,
            110,
            191,
            162,
            167,
            71,
            92,
            149,
            61,
            104,
            247,
            190,
            62,
            143,
            167,
            147,
            249,
            56,
            252,
            246,
            107,
            46,
            105,
            87,
            195,
            61,
            165,
            134,
            160,
            96,
            24,
            9,
            88,
            246,
            188,
            85,
            74,
            210,
            193,
            174,
            13,
            7,
            159,
            238,
            96,
            146,
            28,
            135,
            35,
            208,
            124,
            230,
            179,
            53,
            4,
            70,
            23,
            67,
            202,
            79,
            228,
            36,
            133,
            185,
            60,
            27,
            39,
            115,
            182,
            179,
            174,
            221,
            205
        ])
    );
});

test('it can correctly perform an ECDHE roundtrip', async (t) => {
    const Q = binaryStringToArray(decodeBase64('QPOClKt3wRFh6I0D7ItvuRqQ9eIfJZfOcBK3qJ/J++oj'));
    const d = binaryStringToArray(decodeBase64('TG4WP1jLiWurBSTrpTCeYrdpJUqFTVFg1PzD2/m26Jg='));
    const Fingerprint = binaryStringToArray(decodeBase64('sbd0e0yF9dSX8+xH9VYDqGVK0Wk='));
    const Curve = 'curve25519';

    const { V, Z } = await genPublicEphemeralKey({ Curve, Q, Fingerprint });
    const Zver = await genPrivateEphemeralKey({ Curve, V, d, Fingerprint });

    t.deepEqual(Zver, Z);
});
