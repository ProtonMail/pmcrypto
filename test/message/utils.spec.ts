import { expect } from 'chai';
// @ts-ignore missing web-stream-tools types
import { WritableStream, ReadableStream, readToEnd } from '@openpgp/web-stream-tools';
import { readKey, readSignature } from '../../lib/openpgp';
import { verifyMessage, signMessage, getSignature, stringToUtf8Array, generateKey } from '../../lib';
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

describe('message utils', () => {
    it('verifyMessage - it verifies a message with multiple signatures', async () => {
        const publicKey1 = await readKey({ armoredKey: armoredPublicKey });
        const publicKey2 = await readKey({ armoredKey: armoredPublicKey2 });
        const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            textData: 'hello world',
            signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
            verificationKeys: [publicKey1, publicKey2]
        });
        expect(data).to.equal('hello world');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.be.undefined;
        const signaturePackets = signatures.map(({ packets: [sigPacket] }) => sigPacket);
        expect(signatureTimestamp).to.equal(signaturePackets[0].created);
    });

    it('verifyMessage - it verifies a message with multiple signatures and returns the timestamp of the valid signature', async () => {
        const publicKey1 = await readKey({ armoredKey: armoredPublicKey });
        const publicKey2 = await readKey({ armoredKey: armoredPublicKey2 });
        const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            textData: 'hello world',
            signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
            verificationKeys: [publicKey1] // the second public key is missing, expect only one signature to be verified
        });
        expect(data).to.equal('hello world');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.be.undefined;
        const signaturePackets = signatures.map(({ packets: [sigPacket] }) => sigPacket);
        const validSignature = signaturePackets.find(
            (sigPacket) => sigPacket.issuerKeyID.equals(publicKey1.getKeyID())
        );
        const invalidSignature = signaturePackets.find(
            (sigPacket) => sigPacket.issuerKeyID.equals(publicKey2.getKeyID())
        );
        expect(signatureTimestamp).to.equal(validSignature?.created);
        expect(signatureTimestamp).to.not.equal(invalidSignature?.created);
    });

    it('verifyMessage - it does not verify a message given wrong public key', async () => {
        const { publicKey: wrongPublicKey } = await generateKey({
            userIDs: [{ name: 'test', email: 'a@b.com' }],
            format: 'object'
        });
        const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            textData: 'hello world',
            signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
            verificationKeys: [wrongPublicKey]
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.not.be.undefined;
        expect(errors!.length).to.equal(2);
        errors?.forEach((err) => expect(err.message).to.match(/Could not find signing key/))
        expect(signatureTimestamp).to.be.null;
    });

    it('verifyMessage - it does not verify a message with corrupted signature', async () => {
        const publicKey = await readKey({ armoredKey: armoredPublicKey });
        const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            textData: 'corrupted',
            signature: await readSignature({ armoredSignature: detachedSignatureFromTwoKeys }),
            verificationKeys: [publicKey]
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.not.be.undefined;
        expect(errors?.length).to.equal(2);
        expect(errors?.[0].message).to.match(/digest did not match/);
        expect(signatureTimestamp).to.be.null;
    });

    it('verifyMessage - it detects missing signatures', async () => {
        const publicKey = await readKey({ armoredKey: armoredPublicKey });
        const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            textData: 'no signatures',
            verificationKeys: [publicKey]
        });
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures.length).to.equal(0);
        expect(errors).to.be.undefined;
        expect(signatureTimestamp).to.be.null;
    });

    it('signMessage/verifyMessage - it verifies a text message it has signed (format = armored)', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const armoredSignature = await signMessage({
            textData: 'message',
            signingKeys: [privateKey],
            detached: true
        });

        const verificationResult = await verifyMessage({
            textData: 'message',
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a text message it has signed (format = binary)', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const binarySignature = await signMessage({
            textData: 'message',
            signingKeys: [privateKey],
            detached: true,
            format: 'binary'
        });

        const verificationResult = await verifyMessage({
            textData: 'message',
            signature: await readSignature({ binarySignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a binary message it has signed', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const signature = await signMessage({
            binaryData: stringToUtf8Array('message'),
            signingKeys: [privateKey],
            detached: true
        });

        const verificationResult = await verifyMessage({
            binaryData: stringToUtf8Array('message'),
            signature: await getSignature(signature),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a streamed message it has signed', async () => {
        const inputStream: ReadableStream<string> = new ReadableStream({
            pull: (controller: WritableStream) => { for (let i = 0; i < 10000; i++ ) { controller.enqueue('string'); } controller.close() }
        });
        const inputData = 'string'.repeat(10000);

        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const streamedSignature = await signMessage({
            textData: inputStream,
            signingKeys: [privateKey],
            detached: true
        });

        const armoredSignature = await readToEnd(streamedSignature);

        const verificationResult = await verifyMessage({
            textData: inputData,
            signature: await getSignature(armoredSignature),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.data).to.equal(inputData);
        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
})
