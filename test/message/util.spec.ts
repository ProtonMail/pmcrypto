import test from 'ava';
import '../helper';
import { readKey, readSignature, generateKey } from 'openpgp';
import { createMessage, getSignature, verifyMessage, signMessage, getMessage, binaryStringToArray } from '../../lib';
import { VERIFICATION_STATUS } from '../../lib/constants';

const detachedSignatureFromTwoKeys = `-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmCCo8gAIQkQyQtnL+EYbekWIQTopSabUSqDUEv/FMHJC2cv
4Rht6VeGAP4mUJl+WYN9nLE57YByTh95OmcZmwfgz5Z4R570YqTVngD/VBym
icc7YREcxij1gC6SSAe8kgKW6oVOWzxJ8HkOSQrCdQQBFgoABgUCYIK9vQAh
CRCGHCX3YYW5NRYhBErDPc6OYkUaNQCLhoYcJfdhhbk1W1QBAPhrkAjimO22
jh1V2A8pRCOs53Ig/AMAFbN37BaAIEVKAP0SVMTL6zTxYJcxWNPog7Bv5lM4
Px4G+hZ2Kia//qlgBg==
=0aeU
-----END PGP SIGNATURE-----`;

const armoredPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYIKjXxYJKwYBBAHaRw8BAQdAbmODPSLO5tOI0GxfV+x5bgiiFriCcH3t
6lbJkS+OzKbNEHRlc3QgPHRlc3RAYS5pdD7CjAQQFgoAHQUCYIKjXwQLCQcI
AxUICgQWAAIBAhkBAhsDAh4BACEJEMkLZy/hGG3pFiEE6KUmm1Eqg1BL/xTB
yQtnL+EYbenOlAEAn7A7RXQJ9FUzhuiOHeKqczdslgOO5LFcng1LuSIWn1UB
ANWHrxnH63jnFLE82mfhpRZ5FYJ1fEXA9+3v6at3ZE8IzjgEYIKjXxIKKwYB
BAGXVQEFAQEHQA5moGr1AKlYvKI+JpyB6W640eXpQFNSiV6LBjuMteNbAwEI
B8J2BBgWCAAJBQJggqNfAhsMACEJEMkLZy/hGG3pFiEE6KUmm1Eqg1BL/xTB
yQtnL+EYben97QD4hf6DttxyczHGqxGbboatBZ3IufJgFm6r2xNf9d9lSAD3
U12oHbxyYUhapbFFkSIBo7DWJqWvx3iUEPqzY6jIAA==
=ZWrn
-----END PGP PUBLIC KEY BLOCK-----`;

const armoredPublicKey2 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYIKjgxYJKwYBBAHaRw8BAQdARyd9iDlrlozcTG144XFIjWozyWLz0KQv
fL4lqIrwM8XNEHRlc3QgPHRlc3RAYi5pdD7CjAQQFgoAHQUCYIKjgwQLCQcI
AxUICgQWAAIBAhkBAhsDAh4BACEJEIYcJfdhhbk1FiEESsM9zo5iRRo1AIuG
hhwl92GFuTVPRAD6A6//tK5pLPa1d7mgsoqyJ9BZyTAmnzxtbIgmOU9/TDcB
AI4cGBfCOLzRPw6L0il5Rt78TX1jz4Dlzu6YixJcJ2AFzjgEYIKjgxIKKwYB
BAGXVQEFAQEHQMjb0Q1FWvHzj0hyOiEN5ndChBDceUqxmQ0wOYDVqq8JAwEI
B8J4BBgWCAAJBQJggqODAhsMACEJEIYcJfdhhbk1FiEESsM9zo5iRRo1AIuG
hhwl92GFuTXz4AEAqn4L+ayYgphejF/ZTRIseHPK+t521CT6NZKoVaHnTWQA
/0+kMEB5d+CH3Mb54cUganYHPLj5utO2PexEJc3xARIG
=IEm4
-----END PGP PUBLIC KEY BLOCK-----`;

test('it verifies a message with multiple signatures', async (t) => {
    const publicKey1 = await readKey({ armoredKey: armoredPublicKey });
    const publicKey2 = await readKey({ armoredKey: armoredPublicKey2 });
    const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: await createMessage('hello world'),
        signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
        verificationKeys: [publicKey1, publicKey2]
    });
    t.deepEqual(data, 'hello world');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    t.is(signatures.length, 2);
    t.is(errors, undefined);
    const signaturePackets = signatures.map(({ packets: [sigPacket] }) => sigPacket);
    t.is(signatureTimestamp, signaturePackets[0].created);
});

test('it verifies a message with multiple signatures and returns the timestamp of the valid signature', async (t) => {
    const publicKey1 = await readKey({ armoredKey: armoredPublicKey });
    const publicKey2 = await readKey({ armoredKey: armoredPublicKey2 });
    const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: await createMessage('hello world'),
        signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
        verificationKeys: [publicKey1] // the second public key is missing, expect only one signature to be verified
    });
    t.deepEqual(data, 'hello world');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    t.is(signatures.length, 2);
    t.is(errors, undefined);
    const signaturePackets = signatures.map(({ packets: [sigPacket] }) => sigPacket);
    const validSignature = signaturePackets.find((sigPacket) => sigPacket.issuerKeyID.equals(publicKey1.getKeyID()));
    const invalidSignature = signaturePackets.find((sigPacket) => sigPacket.issuerKeyID.equals(publicKey2.getKeyID()));
    t.is(signatureTimestamp, validSignature?.created);
    t.not(signatureTimestamp, invalidSignature?.created);
});

test('it does not verify a message given wrong public key', async (t) => {
    const { publicKey: wrongPublicKey } = await generateKey({
        userIDs: [{ name: 'test', email: 'a@b.com' }],
        format: 'object'
    });
    const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: await createMessage('hello world'),
        signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
        verificationKeys: [wrongPublicKey]
    });
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_INVALID);
    t.is(signatures.length, 2);
    t.not(errors, undefined);
    t.is(errors!.length, 2);
    errors?.forEach(err => t.regex(err.message, /Could not find signing key/))
    t.is(signatureTimestamp, null);
});

test('it does not verify a message with corrupted signature', async (t) => {
    const publicKey = await readKey({ armoredKey: armoredPublicKey });
    const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: await createMessage('corrupted'),
        signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
        verificationKeys: [publicKey]
    });
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_INVALID);
    t.is(signatures.length, 2);
    t.not(errors, undefined);
    t.is(errors!.length, 2);
    t.regex(errors?.[0].message!, /digest did not match/);
    t.is(signatureTimestamp, null);
});

test('it detects missing signatures', async (t) => {
    const publicKey = await readKey({ armoredKey: armoredPublicKey });
    const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: await createMessage('no signatures'),
        verificationKeys: [publicKey]
    });
    t.is(verified, VERIFICATION_STATUS.NOT_SIGNED);
    t.is(signatures.length, 0);
    t.is(errors, undefined);
    t.is(signatureTimestamp, null);
});

test('it verifies a message it has signed', async (t) => {
    const { privateKey, publicKey } = await generateKey({
        userIDs: [{ name: 'name', email: 'email@test.com' }],
        date: new Date(),
        keyExpirationTime: 10000,
        format: 'object'
    });

    const signature = await signMessage({
        message: await createMessage('message'),
        signingKeys: [privateKey]
    });

    const verificationResult = await verifyMessage({
        message: await getMessage(signature),
        verificationKeys: [publicKey]
    });

    t.is(verificationResult.verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});
