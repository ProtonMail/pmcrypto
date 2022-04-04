import { expect } from 'chai';
import { enums, PrivateKey, readKey, revokeKey, sign, createMessage } from '../../lib/openpgp';
import {
    isExpiredKey,
    isRevokedKey,
    reformatKey,
    getKey,
    generateKey,
    getMatchingKey,
    generateSessionKey,
    generateSessionKeyFromKeyPreferences,
    // @ts-ignore missing keyCheck typings
    keyCheck
} from '../../lib';

describe('key utils', () => {

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

    it('generateKey - it has valid default creation time', async () => {
        const { privateKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });
        const now = new Date();
        expect(Math.abs(+privateKey.getCreationTime() - +now) < 24 * 3600).to.be.true;
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
