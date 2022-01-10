import { expect } from 'chai';

import { openpgp } from '../../lib/openpgp';
import { createMessage, verifyMessage } from '../../lib';
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
    it('it verifies a message with multiple signatures', async () => {
        const publicKey1 = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
        const publicKey2 = (await openpgp.key.readArmored(armoredPublicKey2)).keys[0];
        const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            message: createMessage('hello world'),
            signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
            publicKeys: [publicKey1, publicKey2]
        });
        expect(data).to.deep.equal(openpgp.util.str_to_Uint8Array('hello world'));
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.be.undefined;
        const signaturePackets = signatures.map(({
                                                     // @ts-ignore openpgp.packet.List not declared as iterator
                                                     packets: [sigPacket]
                                                 }) => sigPacket);
        signaturePackets.forEach(({ verified }) => {
            expect(verified).to.equal(true);
        });
        expect(signatureTimestamp).to.equal(signaturePackets[0].created);
    });

    it('it verifies a message with multiple signatures and returns the timestamp of the valid signature', async () => {
        const publicKey1 = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
        const publicKey2 = (await openpgp.key.readArmored(armoredPublicKey2)).keys[0];
        const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            message: createMessage('hello world'),
            signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
            publicKeys: [publicKey1] // the second public key is missing, expect only one signature to be verified
        });
        expect(data).to.deep.equal(openpgp.util.str_to_Uint8Array('hello world'));
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.equal(undefined);
        const signaturePackets = signatures.map(({
                                                     // @ts-ignore openpgp.packet.List not declared as iterator
                                                     packets: [sigPacket]
                                                 }) => sigPacket);
        const validSignature = signaturePackets.find((sigPacket) => sigPacket.issuerKeyId.equals(publicKey1.getKeyId()));
        const invalidSignature = signaturePackets.find((sigPacket) => sigPacket.issuerKeyId.equals(publicKey2.getKeyId()));
        expect(validSignature.verified).to.equal(true);
        expect(signatureTimestamp).to.equal(validSignature.created);
        expect(invalidSignature.verified).to.equal(null);
        expect(signatureTimestamp).to.not.equal(invalidSignature.created);
    });

    it('it does not verify a message given wrong public key', async () => {
        const { key: wrongPublicKey } = await openpgp.generateKey({ userIds: [{ name: 'it', email: 'a@b.com' }] });
        const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            message: createMessage('hello world'),
            signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
            publicKeys: [wrongPublicKey]
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(signatures.length).to.equal(2);
        expect(errors).to.not.equal(undefined);
        expect(errors?.length).to.equal(0);
        const verifiedSignatures = signatures
            // @ts-ignore openpgp.packet.List not declared as iterator
            .map(({ packets: [sigPacket] }) => sigPacket)
            .filter((sigPacket) => sigPacket.verified);
        expect(verifiedSignatures.length).to.equal(0);
        expect(signatureTimestamp).to.equal(null);
    });

    it('it does not verify a message with corrupted signature', async () => {
        const publicKey = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
        const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            message: createMessage('corrupted'),
            signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
            publicKeys: [publicKey]
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(signatures.length).to.equal(2);
        expect(errors).not.to.equal(undefined);
        expect(errors!.length).to.equal(1);
        const verifiedSignatures = signatures
            // @ts-ignore openpgp.packet.List not declared as iterator
            .map(({ packets: [sigPacket] }) => sigPacket)
            .filter((sigPacket) => sigPacket.verified);
        expect(verifiedSignatures.length).to.equal(0);
        expect(signatureTimestamp).to.equal(null);
    });

    it('it detects missing signatures', async () => {
        const publicKey = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
        const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
            message: createMessage('no signatures'),
            publicKeys: [publicKey]
        });
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures.length).to.equal(0);
        expect(errors).to.be.undefined;
        expect(signatureTimestamp).to.be.null;
    });
});
