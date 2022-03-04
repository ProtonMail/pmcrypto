import { expect, use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import {
    readPrivateKey as openpgp_readPrivateKey,
    decryptKey as openpgp_decryptKey,
    readKey as openpgp_readKey
} from '../../lib/openpgp';
import { VERIFICATION_STATUS, CryptoWorker } from '../../lib';
import { stringToUtf8Array, generateKey, SessionKey } from '../../lib/pmcrypto';
import { testMessageEncryptedLegacy, testPrivateKeyLegacy, testMessageResult, testMessageEncryptedStandard } from '../message/decryptMessageLegacy.data';

chaiUse(chaiAsPromised);
const workerPath = '/dist/worker.js';

before(() => {
    CryptoWorker.init(workerPath);
});

afterEach(() => {
    CryptoWorker.clearKeyStore();
})

describe('WorkerAPI and Proxy Integration', () => {
    it('init - should throw if already initialised', async () => {
        expect(() => CryptoWorker.init(workerPath)).to.throw(/already initialised/);
    })

    it('decryptMessage - should decrypt message with correct password', async () => {
        const armoredMessage = `-----BEGIN PGP MESSAGE-----

wy4ECQMIxybp91nMWQIAa8pGeuXzR6zIs+uE6bUywPM4GKG8sve4lJoxGbVS
/xN10jwBEsZQGe7OTWqxJ9NNtv6X6qFEkvABp4PD3xvi34lo2WUAaUN2wb0g
tBiO7HKQxoGj3FnUTJnI52Y0pIg=
=HJfc
-----END PGP MESSAGE-----`;
        const decryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage,
            passwords: 'password'
        });
        expect(decryptionResult.data).to.equal('hello world');
        expect(decryptionResult.signatures).to.have.length(0);
        expect(decryptionResult.errors).to.not.exist;
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED)

        const decryptWithWrongPassword = CryptoWorker.decryptMessage({
            armoredMessage,
            passwords: 'wrong password'
        });
        await expect(decryptWithWrongPassword).to.be.rejectedWith(/Error decrypting message/);
    });

    it('decryptMessage - message with signature', async () => {
        const messageWithSignature = `-----BEGIN PGP MESSAGE-----

wy4ECQMIUxTg50RvG9EAMkSwKLgTqzpEMlGv1+IKf52HmId83iK4kku8nBzR
FxcD0sACAc9hM9NVeaAhGQdsTqt9zRcRmMRhyWqoAsR0+uZukqPxGZfOw0+6
ouguW3wrVd+/niaHPaDs87sATldw5KK5WI9xcR+mBid4Bq7hugXNcZDMa8qN
gqM8VJm8262cvZAtjwbH50TjBNl+q/YN7DDr+BXd6gRzrvMM+hl5UwYiiYfW
qXGo4MRQBT+B41Yjh/2rUdlCmWoRw2OGWzQTmTspNm4EEolrT6jdYQMxn9IZ
GzGRkb+Rzb42pnKcuihith40374=
=ccav
-----END PGP MESSAGE-----
`;
        const decryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage: messageWithSignature,
            passwords: 'password'
        });

        expect(decryptionResult.data).to.equal('hello world');
        expect(decryptionResult.signatures).to.have.length(1);
        expect(decryptionResult.errors).to.have.length(1);
        expect(decryptionResult.errors![0]).instanceOf(Error); // Errors should be automatically reconstructed by comlink
        expect(decryptionResult.errors![0]).to.match(/Could not find signing key/);
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID)
    });

    it('decryptMessage - output binary data should be transferred', async () => {
        const decryptionResult = await CryptoWorker.decryptMessage({
        armoredMessage: `-----BEGIN PGP MESSAGE-----

wy4ECQMIxybp91nMWQIAa8pGeuXzR6zIs+uE6bUywPM4GKG8sve4lJoxGbVS
/xN10jwBEsZQGe7OTWqxJ9NNtv6X6qFEkvABp4PD3xvi34lo2WUAaUN2wb0g
tBiO7HKQxoGj3FnUTJnI52Y0pIg=
=HJfc
-----END PGP MESSAGE-----`,
            passwords: 'password',
            format: 'binary'
        });
        expect(decryptionResult.data).to.deep.equal(stringToUtf8Array('hello world'));
        expect(decryptionResult.signatures).to.have.length(0);
        expect(decryptionResult.errors).to.not.exist;
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
    });

    it('decryptMessageLegacy - it can decrypt a legacy message', async () => {
        const privateKeyRef = await CryptoWorker.importPrivateKey({ armoredKey: testPrivateKeyLegacy, passphrase: '123' });

        const decryptionResult = await CryptoWorker.decryptMessageLegacy({
            armoredMessage: testMessageEncryptedLegacy,
            decryptionKeys: privateKeyRef,
            messageDate: new Date('2015-01-01')
        });
        expect(decryptionResult.data).to.equal(testMessageResult);
        expect(decryptionResult.signatures).to.have.length(0);
        expect(decryptionResult.errors).to.not.exist;
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
    });

    it('decryptMessageLegacy - it can decrypt a non-legacy armored message', async () => {
        const privateKeyRef = await CryptoWorker.importPrivateKey({ armoredKey: testPrivateKeyLegacy, passphrase: '123' });

        const decryptionResult = await CryptoWorker.decryptMessageLegacy({
            armoredMessage: testMessageEncryptedStandard,
            decryptionKeys: privateKeyRef,
            verificationKeys: privateKeyRef,
            messageDate: new Date('2015-01-01')
        });
        expect(decryptionResult.data).to.equal(testMessageResult);
        expect(decryptionResult.signatures).to.have.length(1);
        expect(decryptionResult.errors).to.not.exist;
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('encryptMessage - output binary message and signatures should be transferred', async () => {
        const encryptionResult = await CryptoWorker.encryptMessage({
            textData: 'hello world',
            passwords: 'password',
            format: 'binary'
        });
        expect(encryptionResult.message.length > 0).to.be.true;

        const decryptionResult = await CryptoWorker.decryptMessage({
            binaryMessage: encryptionResult.message,
            passwords: 'password'
        });
        expect(decryptionResult.signatures).to.have.length(0);
        expect(decryptionResult.errors).to.not.exist;
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED)
    });

    it('encryptMessage/decryptMessage - should encrypt and decrypt text and binary data', async () => {
        const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
        const { message: encryptedArmoredMessage } = await CryptoWorker.encryptMessage({
            textData: 'hello world',
            encryptionKeys: privateKeyRef
        });

        const textDecryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage: encryptedArmoredMessage,
            decryptionKeys: privateKeyRef
        });
        expect(textDecryptionResult.data).to.equal('hello world');
        expect(textDecryptionResult.signatures).to.have.length(0);
        expect(textDecryptionResult.errors).to.not.exist;
        expect(textDecryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);

        const { message: encryptedBinaryMessage } = await CryptoWorker.encryptMessage({
            binaryData: new Uint8Array([1, 2, 3]),
            encryptionKeys: privateKeyRef,
            format: 'binary'
        });

        const binaryDecryptionResult = await CryptoWorker.decryptMessage({
            binaryMessage: encryptedBinaryMessage,
            decryptionKeys: privateKeyRef,
            format: 'binary'
        });
        expect(binaryDecryptionResult.data).to.deep.equal(new Uint8Array([1, 2, 3]));
        expect(binaryDecryptionResult.signatures).to.have.length(0);
        expect(binaryDecryptionResult.errors).to.not.exist;
        expect(binaryDecryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
    });

    it('encryptMessage/decryptMessage - with returned session key', async () => {
        const { message: encryptedArmoredMessage, sessionKey } = await CryptoWorker.encryptMessage({
            textData: 'hello world',
            returnSessionKey: true
        });

        const textDecryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage: encryptedArmoredMessage,
            sessionKeys: sessionKey
        });
        expect(textDecryptionResult.data).to.equal('hello world');
        expect(textDecryptionResult.signatures).to.have.length(0);
        expect(textDecryptionResult.errors).to.not.exist;
        expect(textDecryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
    });

  it('signMessage/verifyMessage - output binary signature and data should be transferred', async () => {
        const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
        const binarySignature = await CryptoWorker.signMessage({
            textData: 'hello world',
            format: 'binary',
            detached: true,
            signingKeys: privateKeyRef
        });
        expect(binarySignature.length > 0).to.be.true;

        const verificationResult = await CryptoWorker.verifyMessage({
            textData: 'hello world',
            verificationKeys: privateKeyRef,
            binarySignature
        });
        expect(verificationResult.data).to.equal('hello world');
        expect(verificationResult.signatures).to.have.length(1);
        expect(verificationResult.errors).to.not.exist;
        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

        const invalidVerificationResult = await CryptoWorker.verifyMessage({
            textData: 'not signed data',
            binarySignature,
            verificationKeys: privateKeyRef,
            format: 'binary'
        });
        expect(invalidVerificationResult.data).to.deep.equal(stringToUtf8Array('not signed data'));
        expect(invalidVerificationResult.signatures).to.have.length(1);
        expect(invalidVerificationResult.errors).to.have.length(1);
        expect(invalidVerificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID)
    });

    it('should encrypt/sign and decrypt/verify text and binary data', async () => {
        const aliceKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'alice', email: 'alice@test.com' } });
        const bobKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'bob', email: 'bob@test.com' } });

        const { message: encryptedArmoredMessage } = await CryptoWorker.encryptMessage({
            textData: 'hello world',
            encryptionKeys: bobKeyRef,
            signingKeys: aliceKeyRef
        });

        const textDecryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage: encryptedArmoredMessage,
            decryptionKeys: bobKeyRef,
            verificationKeys: aliceKeyRef
        });
        expect(textDecryptionResult.data).to.equal('hello world');
        expect(textDecryptionResult.signatures).to.have.length(1);
        expect(textDecryptionResult.errors).to.not.exist;
        expect(textDecryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

        const { message: encryptedBinaryMessage } = await CryptoWorker.encryptMessage({
            binaryData: new Uint8Array([1, 2, 3]),
            encryptionKeys: bobKeyRef,
            signingKeys: aliceKeyRef,
            format: 'binary'
        });

        const binaryDecryptionResult = await CryptoWorker.decryptMessage({
            binaryMessage: encryptedBinaryMessage,
            decryptionKeys: bobKeyRef,
            verificationKeys: aliceKeyRef,
            format: 'binary'
        });
        expect(binaryDecryptionResult.data).to.deep.equal(new Uint8Array([1, 2, 3]));
        expect(binaryDecryptionResult.signatures).to.have.length(1);
        expect(binaryDecryptionResult.errors).to.not.exist;
        expect(binaryDecryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('should encrypt/sign and decrypt/verify binary data with detached signatures', async () => {
        const aliceKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'alice', email: 'alice@test.com' } });
        const bobKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'bob', email: 'bob@test.com' } });

        const plaintext = stringToUtf8Array('hello world');
        const {
            message: encryptedBinaryMessage,
            signature: detachedBinarySignature,
            encryptedSignature: encryptedBinarySignature
        } = await CryptoWorker.encryptMessage({
            binaryData: plaintext,
            encryptionKeys: bobKeyRef,
            signingKeys: aliceKeyRef,
            format: 'binary',
            detached: true
        });

        const decryptionResult = await CryptoWorker.decryptMessage({
            binaryMessage: encryptedBinaryMessage,
            binarySignature: detachedBinarySignature,
            decryptionKeys: bobKeyRef,
            verificationKeys: aliceKeyRef,
            format: 'binary'
        });
        expect(decryptionResult.data).to.deep.equal(plaintext);
        expect(decryptionResult.signatures).to.have.length(1);
        expect(decryptionResult.errors).to.not.exist;
        expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

        const decryptionResultWithEncryptedSignature = await CryptoWorker.decryptMessage({
            binaryMessage: encryptedBinaryMessage,
            binaryEncryptedSignature: encryptedBinarySignature,
            decryptionKeys: bobKeyRef,
            verificationKeys: aliceKeyRef,
            format: 'binary'
        });
        expect(decryptionResultWithEncryptedSignature.data).to.deep.equal(plaintext);
        expect(decryptionResultWithEncryptedSignature.signatures).to.have.length(1);
        expect(decryptionResultWithEncryptedSignature.errors).to.not.exist;
        expect(decryptionResultWithEncryptedSignature.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('generateSessionKey - should return session key of expected size', async () => {
        const sessionKey128 = await CryptoWorker.generateSessionKey('aes128');
        expect(sessionKey128.length).to.equal(16);
        const sessionKey192 = await CryptoWorker.generateSessionKey('aes192');
        expect(sessionKey192.length).to.equal(24);
        const sessionKey256 = await CryptoWorker.generateSessionKey('aes256');
        expect(sessionKey256.length).to.equal(32);
    });

    it('generateSessionKeyFromKeyPreferences - should return shared algo preference', async () => {
        const aliceKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'alice', email: 'alice@test.com' } });
        const bobKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'bob', email: 'bob@test.com' } });

        const sessionKey = await CryptoWorker.generateSessionKeyFromKeyPreferences({
            targetKeys: [aliceKeyRef, bobKeyRef]
        });
        expect(sessionKey.algorithm).to.equal('aes256');
    });

    it('generate/encrypt/decryptSessionKey - should encrypt and decrypt with key and password', async () => {
        const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'test', email: 'test@test.com' } });
        const password = 'password';

        const sessionKey: SessionKey = {
            data: new Uint8Array(16).fill(123),
            algorithm: 'aes128'
        };

        // armored result
        await CryptoWorker.encryptSessionKey({
            ...sessionKey,
            encryptionKeys: privateKeyRef,
            passwords: password
        }).then(async (armoredEncryptedSessionKey) => {
            const decryptedSessionKeyWithPassword = await CryptoWorker.decryptSessionKey({
                armoredMessage: armoredEncryptedSessionKey,
                passwords: password
            });
            expect(decryptedSessionKeyWithPassword).to.deep.equal(sessionKey);
            const decryptedSessionKeyWithKey = await CryptoWorker.decryptSessionKey({
                armoredMessage: armoredEncryptedSessionKey,
                decryptionKeys: privateKeyRef
            });
            expect(decryptedSessionKeyWithKey).to.deep.equal(sessionKey);
        });

        // binary result
        await CryptoWorker.encryptSessionKey({
            ...sessionKey,
            encryptionKeys: privateKeyRef,
            passwords: password,
            format: 'binary'
        }).then(async (binaryEncryptedSessionKey) => {
            const decryptedSessionKeyWithPassword = await CryptoWorker.decryptSessionKey({
                binaryMessage: binaryEncryptedSessionKey,
                passwords: password
            });
            expect(decryptedSessionKeyWithPassword).to.deep.equal(sessionKey);
            const decryptedSessionKeyWithKey = await CryptoWorker.decryptSessionKey({
                binaryMessage: binaryEncryptedSessionKey,
                decryptionKeys: privateKeyRef
            });
            expect(decryptedSessionKeyWithKey).to.deep.equal(sessionKey);
        });
    });

    describe('Key management API', () => {

        it('can export a generated key', async () => {
            const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });

            const passphrase = 'passphrase';
            const armoredKey = await CryptoWorker.exportPrivateKey({ keyReference: privateKeyRef, passphrase });
            const binaryKey = await CryptoWorker.exportPrivateKey({ keyReference: privateKeyRef, passphrase, format: 'binary' });

            const decryptedKeyFromArmored = await openpgp_decryptKey({
                privateKey: await openpgp_readPrivateKey({ armoredKey }),
                passphrase
            });
            expect(decryptedKeyFromArmored.isDecrypted()).to.be.true;

            const decryptedKeyFromBinary = await openpgp_decryptKey({
                privateKey: await openpgp_readPrivateKey({ binaryKey }),
                passphrase
            });
            expect(decryptedKeyFromBinary.isDecrypted()).to.be.true;
        });

        it('can export an imported key', async () => {
            const passphrase = 'passphrase';
            const { privateKey: keyToImport } = await generateKey({ userIDs: { name: 'name', email: 'email@test.com' }, format: 'object', passphrase });

            const importedKeyRef = await CryptoWorker.importPrivateKey({ armoredKey: keyToImport.armor(), passphrase });
            expect(importedKeyRef.creationTime).to.deep.equal(keyToImport.getCreationTime())
            const armoredPublicKey = await CryptoWorker.exportPublicKey({ keyReference: importedKeyRef });
            const exportedPublicKey = await openpgp_readKey({ armoredKey: armoredPublicKey });
            expect(exportedPublicKey.isPrivate()).to.be.false;
            expect(exportedPublicKey.getKeyID().equals(keyToImport.getKeyID()));

            const exportPassphrase = 'another passphrase';
            const armoredPrivateKey = await CryptoWorker.exportPrivateKey({
                keyReference: importedKeyRef, passphrase: exportPassphrase
            });
            const exportedPrivateKey = await openpgp_readPrivateKey({ armoredKey: armoredPrivateKey });
            expect(exportedPrivateKey.getKeyID().equals(keyToImport.getKeyID()));
            // make sure the exported key is encrypted with the new passphrase
            const decryptedExportedKey = await openpgp_decryptKey({
                privateKey: exportedPrivateKey,
                passphrase: exportPassphrase
            });
            expect(decryptedExportedKey.isDecrypted()).to.be.true;
        });

        it('cannot import or export a public key as a private key', async () => {
            const passphrase = 'passphrase';
            const { publicKey: publicKeyToImport } = await generateKey({ userIDs: { name: 'name', email: 'email@test.com' }, format: 'object', passphrase });

            // this give no typescript error since serialised keys are indistinguishable for TS
            await expect(CryptoWorker.importPrivateKey({ armoredKey: publicKeyToImport.armor(), passphrase })).to.be.rejectedWith(/not of type private key/);
            const importedKeyRef = await CryptoWorker.importPublicKey({ armoredKey: publicKeyToImport.armor() });
            expect(importedKeyRef.isPrivate()).to.be.false;
            expect(importedKeyRef.creationTime).to.deep.equal(publicKeyToImport.getCreationTime());
            // @ts-expect-error for non-private key reference
            await expect(CryptoWorker.exportPrivateKey({ keyReference: importedKeyRef })).to.be.rejectedWith(/Cannot encrypt a public key/);
            const armoredPublicKey = await CryptoWorker.exportPublicKey({ keyReference: importedKeyRef });
            const exportedPublicKey = await openpgp_readKey({ armoredKey: armoredPublicKey });
            expect(exportedPublicKey.isPrivate()).to.be.false;
            expect(exportedPublicKey.getKeyID().equals(publicKeyToImport.getKeyID()));
        });

        it('allows importing a private key as long as it can be decrypted', async () => {
            const passphrase = 'passphrase';
            const { privateKey } = await generateKey({ userIDs: { name: 'name', email: 'email@test.com' }, passphrase, format: 'object' });

            const importedKeyRef = await CryptoWorker.importPrivateKey({ armoredKey: privateKey.armor(), passphrase });
            expect(importedKeyRef.isPrivate()).to.be.true;

            await expect(
                CryptoWorker.importPrivateKey({ armoredKey: privateKey.armor(), passphrase: 'wrong passphrase' })
            ).to.be.rejectedWith(/Error decrypting private key: Incorrect key passphrase/);
        });

        it('allows importing a decrypted key only when given a null passphrase', async () => {
            const decryptedArmoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYgQEWRYJKwYBBAHaRw8BAQdAhR6qir63dgL1bSt19bLFQfCIhvYnrk6f
OmvFwcYNf4wAAQCV4uj6Pg+08r+ztuloyzTDAV7eC/jenjm7AdYikQ0MZxFC
zQDCjAQQFgoAHQUCYgQEWQQLCQcIAxUICgQWAAIBAhkBAhsDAh4BACEJENDb
nirC49EHFiEEDgVXCWrFg3oEwWgN0NueKsLj0QdayAD+O1Qq4UrAn1Tz67d7
O3uWdpRWmbgfUr7XygeyWr57crYA/0/37SvtPoI6MHyrVYijXspJlVo0ZABb
dueO4TQCpPkAx10EYgQEWRIKKwYBBAGXVQEFAQEHQCVlPjHtTH0KaiZmgAeQ
f1tglgIeoZuT1fYWQMR5s0QkAwEIBwAA/1T9jghk9P2FAzix+Fst0go8OQ6l
clnLKMx9jFlqLmqAD57CeAQYFggACQUCYgQEWQIbDAAhCRDQ254qwuPRBxYh
BA4FVwlqxYN6BMFoDdDbnirC49EHobgA/R/1yGmo8/xrdipXIWTbL38sApGf
XU0oD7GPQhGsaxZjAQCmjVBDdt+CgmU9NFYwtTIWNHxxJtyf7TX7DY9RH1t2
DQ==
=2Lb6
-----END PGP PRIVATE KEY BLOCK-----`;
            const importedKeyRef = await CryptoWorker.importPrivateKey({
                armoredKey: decryptedArmoredKey,
                passphrase: null
            });
            expect(importedKeyRef.isPrivate()).to.be.true;

            await expect(
                CryptoWorker.importPrivateKey({ armoredKey: decryptedArmoredKey, passphrase: 'passphrase' })
            ).to.be.rejectedWith(/Key packet is already decrypted/);
        });

        it('clearKey - cannot reference a cleared key', async () => {
            const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            // confirm key is in the store
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef })).length.above(0);
            await CryptoWorker.clearKey(privateKeyRef);

            await expect(CryptoWorker.exportPublicKey({ keyReference: privateKeyRef })).to.be.rejectedWith(/Key not found/);
        });

        it('clearKeyStore - cannot reference any key after clearing the store', async () => {
            const privateKeyRef1 = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            const privateKeyRef2 = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            // (lazily) confirm that keys are in the store
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef1 })).length.above(0);
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef2 })).length.above(0);
            await CryptoWorker.clearKeyStore();

            await expect(CryptoWorker.exportPublicKey({ keyReference: privateKeyRef1 })).to.be.rejectedWith(/Key not found/);
            await expect(CryptoWorker.exportPublicKey({ keyReference: privateKeyRef2 })).to.be.rejectedWith(/Key not found/);
        });

    });
});
