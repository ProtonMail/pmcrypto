import { expect } from 'chai';
import { verifyMessage, signMessage, generateKey, readSignature, readMessage, decryptMessage, encryptMessage, readKey, ContextError } from '../../lib';
import { VERIFICATION_STATUS } from '../../lib/constants';

// verification without passing context should fail
// verification passing wrong context should fail
// verification of unsigned notation data should fail
describe('context', () => {
    it('signMessage/verifyMessage - it verifies a message with context (critical)', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });
        const textData = 'message with context';

        const armoredSignature = await signMessage({
            textData,
            signingKeys: [privateKey],
            context: { value: 'test-context', critical: true },
            detached: true
        });

        const verificationValidContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context', required: true }
        });

        const verificationWrongContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'unexpected-context', required: true }
        });

        const verificationMissingContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationValidContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(verificationWrongContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(verificationMissingContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        // check errors
        expect(verificationValidContext.errors).to.be.undefined;
        expect(verificationWrongContext.errors).to.have.length(1);
        expect(verificationWrongContext.errors![0]).to.be.instanceOf(ContextError);
        expect(verificationMissingContext.errors).to.have.length(1);
        expect(verificationMissingContext.errors![0]).to.match(/Unknown critical notation: context@proton/);
    });

    it('signMessage/verifyMessage - it verifies a message with context (non critical)', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });
        const textData = 'message with context';

        const armoredSignature = await signMessage({
            textData,
            signingKeys: [privateKey],
            context: { value: 'test-context', critical: false },
            detached: true
        });

        const verificationValidContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context', required: true }
        });

        const verificationWrongContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'unexpected-context', required: true }
        });

        const verificationWrongContextNotRequired = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'unexpected-context', required: false } // should still fail to verify
        });

        const verificationMissingContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationValidContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(verificationWrongContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(verificationWrongContextNotRequired.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(verificationMissingContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        // check errors
        expect(verificationValidContext.errors).to.be.undefined;
        expect(verificationWrongContext.errors).to.have.length(1);
        expect(verificationWrongContext.errors![0]).to.be.instanceOf(ContextError);
        expect(verificationWrongContextNotRequired.errors).to.have.length(1);
        expect(verificationWrongContextNotRequired.errors![0]).to.be.instanceOf(ContextError);
        expect(verificationMissingContext.errors).to.be.undefined;
    });

    it('encryptMessage/decryptMessage - it verifies a message with context', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });

        const { message: armoredMessage } = await encryptMessage({
            textData: 'message with context',
            encryptionKeys: publicKey,
            signingKeys: privateKey,
            context: { value: 'test-context', critical: true }
        });

        const decryptionValidContext = await decryptMessage({
            message: await readMessage({ armoredMessage }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey,
            context: { value: 'test-context', required: true }
        });

        const decryptionWrongContext = await decryptMessage({
            message: await readMessage({ armoredMessage }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey,
            context: { value: 'unexpected-context', required: true }
        });

        const decryptionMissingContext = await await decryptMessage({
            message: await readMessage({ armoredMessage }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey
        });

        expect(decryptionValidContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(decryptionWrongContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(decryptionMissingContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        // check errors
        expect(decryptionValidContext.verificationErrors).to.be.undefined;
        expect(decryptionWrongContext.verificationErrors).to.have.length(1);
        expect(decryptionWrongContext.verificationErrors![0]).to.be.instanceOf(ContextError);
        expect(decryptionMissingContext.verificationErrors).to.have.length(1);
        expect(decryptionMissingContext.verificationErrors![0]).to.match(/Unknown critical notation: context@proton/);
    });

    it('encryptMessage/decryptMessage - it verifies an encrypted signature with context', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });

        const { message: armoredMessage, encryptedSignature } = await encryptMessage({
            textData: 'message with context',
            encryptionKeys: publicKey,
            signingKeys: privateKey,
            context: { value: 'test-context', critical: true },
            detached: true
        });

        const decryptionValidContext = await decryptMessage({
            message: await readMessage({ armoredMessage }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey,
            context: { value: 'test-context', required: true }
        });

        const decryptionWrongContext = await decryptMessage({
            message: await readMessage({ armoredMessage }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey,
            context: { value: 'unexpected-context', required: true }
        });

        const decryptionMissingContext = await await decryptMessage({
            message: await readMessage({ armoredMessage }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey
        });

        expect(decryptionValidContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(decryptionWrongContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(decryptionMissingContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        // check errors
        expect(decryptionValidContext.verificationErrors).to.be.undefined;
        expect(decryptionWrongContext.verificationErrors).to.have.length(1);
        expect(decryptionWrongContext.verificationErrors![0]).to.be.instanceOf(ContextError);
        expect(decryptionMissingContext.verificationErrors).to.have.length(1);
        expect(decryptionMissingContext.verificationErrors![0]).to.match(/Unknown critical notation: context@proton/);
    });

    it('does not verify a message without context', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });
        const textData = 'message without context';

        const armoredSignature = await signMessage({
            textData,
            signingKeys: [privateKey],
            detached: true
        });

        const verificationExpectedContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context', required: true }
        });

        const verificationNoExpectedContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context', required: false }
        });

        expect(verificationExpectedContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(verificationNoExpectedContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

        expect(verificationNoExpectedContext.errors).to.be.undefined;
        expect(verificationExpectedContext.errors).to.have.length(1);
        expect(verificationExpectedContext.errors![0]).to.be.instanceOf(ContextError);
    });

    it('does not verify a message without context based on cutoff date (`expectFrom`)', async () => {
        const now = new Date();
        const nextHour = new Date(+now + (3600 * 1000));
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object',
            date: now
        });
        const textData = 'message without context';

        const armoredSignature = await signMessage({
            textData,
            signingKeys: [privateKey],
            detached: true,
            date: now
        });

        const verificationExpectedContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context', requiredAfter: now }
        });

        const verificationNoExpectedContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context', requiredAfter: nextHour }
        });

        expect(verificationExpectedContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(verificationNoExpectedContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

        expect(verificationNoExpectedContext.errors).to.be.undefined;
        expect(verificationExpectedContext.errors).to.have.length(1);
        expect(verificationExpectedContext.errors![0]).to.be.instanceOf(ContextError);
    });

    it('does not verify signature with unsigned notation data', async () => {
        // this signature contains context (i.e. notation data) but it is under the unhashed subpackets,
        // hence it is not signed. If context is requested on verification, the signature must fail to verify.
        const armoredSignature = `-----BEGIN PGP SIGNATURE-----

wqUEARYKACcFgmPzZJwJkF8qvvnS11F+FiEECOeCETwii9eyPf0HXyq++dLX
UX4AMC+UgAAAAAARABVjb250ZXh0QHByb3Rvbi5jaHRlc3QtY29udGV4dC11
bnNpZ25lZPQKAQDKi7isJlPfxwgpYg9KagZ1sxuWd3FRyfUyMJOwOkZdwwEA
6ldLiUgk/6BrpsGNTLWAT4O7YuM3IYOuZ8vZJejewQU=
=gtRt
-----END PGP SIGNATURE-----`;
        const publicKey = await readKey({ armoredKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEY/NkkRYJKwYBBAHaRw8BAQdA3sPX38x7/uqy9u4NyPCwrqToJk/jQuyP
xlXfcQSsxFrNFnRlc3QgPHRlc3RAY29udGV4dC5jaD7CjAQQFgoAPgWCY/Nk
kQQLCQcICZBfKr750tdRfgMVCAoEFgACAQIZAQKbAwIeARYhBAjnghE8IovX
sj39B18qvvnS11F+AACnNAEAqw9Y3I8kRKBmWUoSYaYVqt0sm3WAFCIy4cFj
vMeC6QYBAIszizj9K6Gupu700k5VfkbX4zugd+zohD5/yo5k4kEEzjgEY/Nk
kRIKKwYBBAGXVQEFAQEHQO8irSRCCChqiAc29oERDIYPjQRhVYNq8ZmqVain
rdNNAwEIB8J4BBgWCAAqBYJj82SRCZBfKr750tdRfgKbDBYhBAjnghE8IovX
sj39B18qvvnS11F+AAB7igEAqwmlDXMzeNNLc3skdyQWZoP0fPyI/ol7pMa+
7KJS6W4BAKDInHhNEuH3N5DnqwARs8kPDDSNaRNGipxcuYTbFLAO
=PFUt
-----END PGP PUBLIC KEY BLOCK-----` });
        const textData = 'message with unsigned context';

        const verificationWithContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            context: { value: 'test-context-unsigned', required: true }
        });

        // no context expected, so unsigned notation data should be simply ignored
        const verificationWithoutContext = await verifyMessage({
            textData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: publicKey
        });

        expect(verificationWithContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(verificationWithoutContext.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
});
