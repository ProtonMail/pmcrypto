import test from 'ava';
import '../helper';
import { enums, generateKey, revokeKey } from 'openpgp';
import {
    concatArrays,
    decodeBase64,
    encodeBase64,
    isExpiredKey,
    isRevokedKey,
    reformatKey,
    signMessage,
    getMatchingKey,
    // @ts-ignore missing stripArmor typings
    stripArmor,
    // @ts-ignore missing keyCheck typings
    keyCheck
} from '../../lib';

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

// Test issue https://github.com/ProtonMail/pmcrypto/issues/92
test('it can check userId against a given email', (t) => {
    const info = {
        version: 4,
        userIDs: ['jb'],
        algorithmName: 'ecdsa',
        encrypt: {},
        revocationSignatures: [],
        sign: {},
        user: {
            hash: [enums.hash.sha256],
            symmetric: [enums.symmetric.aes256],
            userId: 'Jacky Black <jackyblack@foo.com>'
        }
    };

    t.is(info, keyCheck(info, 'jackyblack@foo.com'));

    try {
        keyCheck(info, 'jack.black@foo.com');
        t.fail();
    } catch (e: any) {
        e.message === 'UserID does not contain correct email address' ? t.pass() : t.fail();
    }
});

test('it reformats a key using the key creation time', async (t) => {
    const date = new Date(0);
    const { privateKey } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        date,
        format: 'object'
    });
    
    const { privateKey: reformattedKey } = await reformatKey({ privateKey, passphrase: '123', userIDs: [{ name: 'reformatted', email: 'reformatteed@test.com' }], format: 'object' });
    const primaryUser = await reformattedKey.getPrimaryUser();
    t.is(primaryUser.user.userID?.userID, 'reformatted <reformatteed@test.com>');
    // @ts-ignore missing `created` field declaration in signature packet
    t.deepEqual((await reformattedKey.getPrimaryUser()).selfCertification.created, date);
});

test('it can correctly detect an expired key', async (t) => {
    const now = new Date();
    // key expires in one second
    const { privateKey: expiringKey } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        date: now,
        keyExpirationTime: 1,
        format: 'object'
    });
    t.is(await isExpiredKey(expiringKey, now), false);
    t.is(await isExpiredKey(expiringKey, new Date(+now + 1000)), true);
    t.is(await isExpiredKey(expiringKey, new Date(+now - 1000)), true);

    const { privateKey: key } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        date: now,
        format: 'object'
    });
    t.is(await isExpiredKey(key), false);
    t.is(await isExpiredKey(key, new Date(+now - 1000)), true);
});

test('it can correctly detect a revoked key', async (t) => {
    const past = new Date(0);
    const now = new Date();

    const { privateKey: key, revocationCertificate } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        date: past,
        format: 'object'
    });
    const { publicKey: revokedKey } = await revokeKey({
        key,
        revocationCertificate,
        format: 'object'
    });
    t.is(await isRevokedKey(revokedKey, past), true);
    t.is(await isRevokedKey(revokedKey, now), true);
    t.is(await isRevokedKey(key, now), false);
});

test('it can get a matching primary key', async (t) => {
    const { privateKey: key1 } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        format: 'object',
        subkeys: [{ sign: true }]
    });

    const { privateKey: key2 } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        format: 'object'
    });

    const { signature: signatureFromSubkey } = await signMessage({
        data: 'a message',
        signingKeys: [key1],
        format: 'object'
    });

    const { signature: signatureFromPrimaryKey } = await signMessage({
        data: 'a message',
        signingKeys: [key2],
        format: 'object'
    });

    t.is(signatureFromSubkey.packets[0].issuerKeyID, key1.subkeys[0].getKeyID());
    t.deepEqual(await getMatchingKey(signatureFromSubkey, [key1, key2]), key1);
    t.is(signatureFromPrimaryKey.packets[0].issuerKeyID, key2.getKeyID());
    t.deepEqual(await getMatchingKey(signatureFromPrimaryKey, [key1, key2]), key2);
});
