import { expect } from 'chai';
import { enums, generateKey, PrivateKey, readKey, revokeKey, sign, createMessage } from '../../lib/openpgp';
import {
    concatArrays,
    decodeBase64,
    encodeBase64,
    isExpiredKey,
    isRevokedKey,
    reformatKey,
    getKey,
    getMatchingKey,
    generateSessionKey,
    generateSessionKeyFromKeyPreferences,
    // @ts-ignore missing stripArmor typings
    stripArmor,
    // @ts-ignore missing keyCheck typings
    keyCheck
} from '../../lib';

describe('key utils', () => {
    it('it can correctly encode base 64', async () => {
        expect(encodeBase64('foo')).to.equal('Zm9v');
    });

    it('it can correctly decode base 64', async () => {
        expect(decodeBase64('Zm9v')).to.equal('foo');
    });

    it('it can correctly concat arrays', async () => {
        expect(concatArrays([
            new Uint8Array([1]),
            new Uint8Array([255])
        ])).to.deep.equal(new Uint8Array([1, 255]));
    });

    it('it can correctly dearmor a message', async () => {
        const x = await stripArmor(`
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.19 (GNU/Linux)

jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg
GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==
=VZ0/
-----END PGP MESSAGE-----`);
        expect(x).to.deep.equal(new Uint8Array([
            140, 13, 4, 9, 3, 2, 166, 142, 200, 241, 106, 172, 121, 180, 201,
            210, 74, 1, 154, 110, 191, 162, 167, 71, 92, 149, 61, 104, 247,
            190, 62, 143, 167, 147, 249, 56, 252, 246, 107, 46, 105, 87, 195,
            61, 165, 134, 160, 96, 24, 9, 88, 246, 188, 85, 74, 210, 193, 174,
            13, 7, 159, 238, 96, 146, 28, 135, 35, 208, 124, 230, 179, 53, 4,
            70, 23, 67, 202, 79, 228, 36, 133, 185, 60, 27, 39, 115, 182, 179,
            174, 221, 205
        ]));
    });

    // Test issue https://github.com/ProtonMail/pmcrypto/issues/92
    it('keyCheck - it can check userId against a given email', () => {
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

        expect(keyCheck(info, 'jackyblack@foo.com')).to.deep.equal(info);

        expect(
            () => keyCheck(info, 'jack.black@foo.com')
        ).to.throw(/UserID does not contain correct email address/);
    });

    it('reformatKey - it reformats a key using the key creation time', async () => {
        const date = new Date(0);
        const { privateKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date,
            format: 'object'
        });

        const { privateKey: reformattedKey } = await reformatKey({ privateKey, passphrase: '123', userIDs: [{ name: 'reformatted', email: 'reformatteed@test.com' }], format: 'object' });
        const primaryUser = await reformattedKey.getPrimaryUser();
        expect(primaryUser.user.userID?.userID).to.equal('reformatted <reformatteed@test.com>');
        // @ts-ignore missing `created` field declaration in signature packet
        expect((await reformattedKey.getPrimaryUser()).selfCertification.created).to.deep.equal(date);
    });

    it('isExpiredKey - it can correctly detect an expired key', async () => {
        const now = new Date();
        // key expires in one second
        const { privateKey: expiringKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: now,
            keyExpirationTime: 1,
            format: 'object'
        });
        expect(await isExpiredKey(expiringKey, now)).to.be.false;
        expect(await isExpiredKey(expiringKey, new Date(+now + 1000))).to.be.true;
        expect(await isExpiredKey(expiringKey, new Date(+now - 1000))).to.be.true;

        const { privateKey: key } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: now,
            format: 'object'
        });
        expect(await isExpiredKey(key)).to.be.false;
        expect(await isExpiredKey(key, new Date(+now - 1000))).to.be.true;
    });

    it('isRevokedKey - it can correctly detect a revoked key', async () => {
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
        expect(await isRevokedKey(revokedKey, past)).to.be.true;
        expect(await isRevokedKey(revokedKey, now)).to.be.true;
        expect(await isRevokedKey(key, now)).to.be.false;
    });

    it('it can get a matching primary key', async () => {
        const keyWithoutSubkeys = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYYqcWBYJKwYBBAHaRw8BAQdAesbhqiOxbLV+P9Dt8LV+Q8hRBLbwsSf6
emoCS30uQpEAAQDFgBruRj6Zqb0OULkaaNz+QK4+gvc006UtTgz2wdrP8xFv
zRE8ZW1haWwyQHRlc3QuY29tPsKMBBAWCgAdBQJhipxYBAsJBwgDFQgKBBYA
AgECGQECGwMCHgEAIQkQJCJW2HYCeYIWIQTdZGjv9WwTyL+azOUkIlbYdgJ5
gm9nAQDY//xzc2hy6Efz8NqDJeLg1lh2sZkKcMXP3L+CJbhWJQEAuI6UDakE
+XVcDsBS+CIi3qg74r/80Ysb7tmRC06znwA=
=I0d7
-----END PGP PRIVATE KEY BLOCK-----`;

        const keyWithSigningSubkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYYqb5xYJKwYBBAHaRw8BAQdA0zCRw6gyovlI8V6pQoDtmAoIr7YPNPxm
jQa5PfiQq5gAAQDQ1o8+YXQg34FUNbbo+PUuRDAar37n9RFQiNrkH+vvlBHW
zRA8ZW1haWxAdGVzdC5jb20+wowEEBYKAB0FAmGKm+cECwkHCAMVCAoEFgAC
AQIZAQIbAwIeAQAhCRCqDK8y54tXERYhBELBCpl0aMYXdXBljKoMrzLni1cR
v44BAI826OYoikU8aMs6wBiHd/SVqPU/ZVLz5VUGriEkJoqGAPwLOztUuX1Q
zmtAq8mQUQjlrmAm50DctKQeug8rrn30BcdYBGGKm+cWCSsGAQQB2kcPAQEH
QGNOppjS4p71QAy6MvBX6JK9zt8YeUo7dm4b7RaFq0ejAAD/ZcyhjL8LEIZO
t/8qU7LJn+lxPSl6tFZ7TBgXj4RkldMQccLALwQYFgoACQUCYYqb5wIbAgCY
CRCqDK8y54tXEXYgBBkWCgAGBQJhipvnACEJEF5S2ZJhJACOFiEElQ0ZXBPe
9UZzI0KoXlLZkmEkAI6EuQD+JRU3Z+u6RHCRdKupZlLuzCFzWmvJvZGktcuQ
40bYgFQA/iwWv5vDkw8zTxw5GRTahnnp0shs/YOG4GgB6EHXom8FFiEEQsEK
mXRoxhd1cGWMqgyvMueLVxHYNAD+NaLEsrzFxvgu3c8nVN5sjVETTZZdHjly
wSeOoh9ocbsA/joCCpHxxH061g/tjEhP76tWJX17ShZ9wT7KZ6aPejoM
=FkBc
-----END PGP PRIVATE KEY BLOCK-----`;

        const key1 = await getKey(keyWithSigningSubkey) as PrivateKey;
        const key2 = await getKey(keyWithoutSubkeys) as PrivateKey;

        const signatureFromSubkey = await sign({
            message: await createMessage({ text: 'a message' }),
            signingKeys: key1,
            format: 'object'
        });

        const signatureFromPrimaryKey = await sign({
            message: await createMessage({ text: 'a message' }),
            signingKeys: key2,
            format: 'object'
        });

        expect(signatureFromSubkey.getSigningKeyIDs().includes(key1.subkeys[0].getKeyID())).to.be.true;
        expect(getMatchingKey(signatureFromSubkey, [key1, key2])).to.deep.equal(key1);
        expect(signatureFromPrimaryKey.getSigningKeyIDs().includes(key2.getKeyID())).to.be.true;
        expect(getMatchingKey(signatureFromPrimaryKey, [key1, key2])).to.deep.equal(key2);
    });

    it('generateSessionKey - it can generate an AES256 session key', async () => {
        const sessionKey = await generateSessionKey('aes256');
        expect(sessionKey.length).to.equal(32);
    });

    it('it can generate a session key from the preferences of the given public keys', async () => {
        const key = await readKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYYqcWBYJKwYBBAHaRw8BAQdAesbhqiOxbLV+P9Dt8LV+Q8hRBLbwsSf6
emoCS30uQpEAAQDFgBruRj6Zqb0OULkaaNz+QK4+gvc006UtTgz2wdrP8xFv
zRE8ZW1haWwyQHRlc3QuY29tPsKMBBAWCgAdBQJhipxYBAsJBwgDFQgKBBYA
AgECGQECGwMCHgEAIQkQJCJW2HYCeYIWIQTdZGjv9WwTyL+azOUkIlbYdgJ5
gm9nAQDY//xzc2hy6Efz8NqDJeLg1lh2sZkKcMXP3L+CJbhWJQEAuI6UDakE
+XVcDsBS+CIi3qg74r/80Ysb7tmRC06znwA=
=I0d7
-----END PGP PRIVATE KEY BLOCK-----`});
        const sessionKey = await generateSessionKeyFromKeyPreferences(key);
        expect(sessionKey.data.length).to.equal(32);
        expect(sessionKey.algorithm).to.equal('aes256');
    });
});
