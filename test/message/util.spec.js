import test from 'ava';
import '../helper';

import { openpgp } from '../../lib/openpgp';
import { verifyMessage } from '../../lib/message/utils';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { createMessage } from '../../lib';

const detachedSignatureFromTwoKeys = `-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmCCm2wAIQkQ2WdF8CsF19UWIQQ1dEimEZorFsTlaU3ZZ0Xw
KwXX1aQtAQDItpxggXie0/j68KSun/N+4v27j85NU541xATv0TV/SQEAqvH8
WKpeRk/iCFEaAcTPvxxeVrLLWqhrCiLWKFFCsAXCdQQBFgoABgUCYIKbbAAh
CRArVw5Kj4m/khYhBA7Q0tE0M2e8lpmxVytXDkqPib+SpC0A/0ISxzab1VbK
XqYY4hV6v78cc0/mMQHx6S8Ywdn5v79lAQDmc77Yo+lHN7o0X155r8KtUwIi
hOOX3oYkoNh2f/G0Cg==
=uoHK
-----END PGP SIGNATURE-----`;

const armoredPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYIGi4hYJKwYBBAHaRw8BAQdAyVB7z3DBQoPkR9R65EJrWOM5dZ4W3LaC
qILzlmjG7j7NEHRlc3QgPHRlc3RAYS5pdD7CjAQQFgoAHQUCYIGi4gQLCQcI
AxUICgQWAAIBAhkBAhsDAh4BACEJENlnRfArBdfVFiEENXRIphGaKxbE5WlN
2WdF8CsF19UExAD/Tpei9iGj+bBFjU9y4AXFZ+vxhYZp/S0pXgPOLcN7+WYA
/ihD0b+EOkATniqREyFHzmKSIsy2oNlwSbekNUhJ23oCzjgEYIGi4hIKKwYB
BAGXVQEFAQEHQDH6hToBmVyfGJT48RKhPt/SGSuzlzFUFtZzqKN9Pw9uAwEI
B8J4BBgWCAAJBQJggaLiAhsMACEJENlnRfArBdfVFiEENXRIphGaKxbE5WlN
2WdF8CsF19XbJwEAygvtdQPSZ9XOK/hdbhTGyO2KUwcFTKhsFAYiB2V45MUA
/iWbqJFGXCN2KnGAFldAFHYz4Bpusz1GaHqIcoI8YSsD
=C9dE
-----END PGP PUBLIC KEY BLOCK-----`;

test('it verifies a message with multiple signatures and returns the valid signature timestamp', async (t) => {
    const publicKey = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
    const { data, verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: createMessage('hello world'),
        signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
        publicKeys: [publicKey] // the second public key is missing, expect only one signature to be verified
    });
    t.deepEqual(data, openpgp.util.str_to_Uint8Array('hello world'));
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    t.is(signatures.length, 2);
    t.is(errors, undefined);
    const verifiedSignature = signatures
        .map(({ packets: [sigPacket] }) => sigPacket)
        .find((sigPacket) => sigPacket.issuerKeyId.equals(publicKey.getKeyId()));
    t.is(verifiedSignature.verified, true);
    t.is(signatureTimestamp, verifiedSignature.created);
});

test('it does not verify a message given wrong public key', async (t) => {
    const { key: wrongPublicKey } = await openpgp.generateKey({ userIds: [{ name: 'test', email: 'a@b.com' }] });
    const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: createMessage('hello world'),
        signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
        publicKeys: [wrongPublicKey] // the second public key is missing, expect only one signature to be verified
    });
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_INVALID);
    t.is(signatures.length, 2);
    t.is(errors.length, 0);
    const verifiedSignatures = signatures
        .map(({ packets: [sigPacket] }) => sigPacket)
        .filter((sigPacket) => sigPacket.verified);
    t.is(verifiedSignatures.length, 0);
    t.is(signatureTimestamp, null);
});

test('it does not verify a message with corrupted signature', async (t) => {
    const publicKey = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
    const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: createMessage('corrupted'),
        signature: await openpgp.signature.readArmored(detachedSignatureFromTwoKeys),
        publicKeys: [publicKey]
    });
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_INVALID);
    t.is(signatures.length, 2);
    t.is(errors.length, 1);
    const verifiedSignatures = signatures
        .map(({ packets: [sigPacket] }) => sigPacket)
        .filter((sigPacket) => sigPacket.verified);
    t.is(verifiedSignatures.length, 0);
    t.is(signatureTimestamp, null);
});

test('it detects missing signatures', async (t) => {
    const publicKey = (await openpgp.key.readArmored(armoredPublicKey)).keys[0];
    const { verified, signatureTimestamp, signatures, errors } = await verifyMessage({
        message: createMessage('no signatures'),
        publicKeys: [publicKey]
    });
    t.is(verified, VERIFICATION_STATUS.NOT_SIGNED);
    t.is(signatures.length, 0);
    t.is(errors, undefined);
    t.is(signatureTimestamp, null);
});
