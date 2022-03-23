import { expect, use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import {
    readPrivateKey as openpgp_readPrivateKey,
    decryptKey as openpgp_decryptKey,
    encryptKey as openpgp_encryptKey,
    readKey as openpgp_readKey,
    revokeKey as openpgp_revokeKey
} from '../../lib/openpgp';
import { VERIFICATION_STATUS, CryptoWorker } from '../../lib';
import { utf8ArrayToString, stringToUtf8Array, generateKey, SessionKey, reformatKey, getSHA256Fingerprints } from '../../lib/pmcrypto';
import { testMessageEncryptedLegacy, testPrivateKeyLegacy, testMessageResult, testMessageEncryptedStandard } from '../message/decryptMessageLegacy.data';
import { hexToUint8Array } from '../../lib/utils';
import {
    multipartSignedMessage,
    multipartSignedMessageBody,
    multipartMessageWithAttachment,
    key as mimeKey
} from '../key/processMIME.data';
import {
    rsa512BitsKey,
    ecc25519Key,
    eddsaElGamalSubkey
} from '../key/check.spec'

chaiUse(chaiAsPromised);

before(async () => {
    await CryptoWorker.init();
});

afterEach(() => {
    CryptoWorker.clearKeyStore();
});

after(() => {
    CryptoWorker.destroy();
})

describe('WorkerAPI and Proxy Integration', () => {
    it('init - should throw if already initialised', async () => {
        await expect(CryptoWorker.init()).to.be.rejectedWith(/already initialised/);
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

    it('encryptMessage - output binary message should be transferred', async () => {
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

    it('encryptMessage/decryptMessage - with elgamal key', async () => {
        // an elgamal key is considered insecure by OpenPGP.js by default, but we need to allow existing keys to be used for now.
        const weakKeyRef = await CryptoWorker.importPrivateKey({ armoredKey: eddsaElGamalSubkey, passphrase: null })
        const { message: encryptedArmoredMessage } = await CryptoWorker.encryptMessage({
            textData: 'hello world',
            encryptionKeys: weakKeyRef
        });

        const textDecryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage: encryptedArmoredMessage,
            decryptionKeys: weakKeyRef
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

    it('processMIME - it can process multipart/signed mime messages and verify the signature', async () => {
        const mimeKeyRef = await CryptoWorker.importPublicKey({ armoredKey: mimeKey })
        const { body, verified, signatures } = await CryptoWorker.processMIME({
            data: multipartSignedMessage,
            verificationKeys: mimeKeyRef
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(1);
        expect(signatures[0].length > 0).to.be.true; // check that serialized signature is transferred
        expect(body).to.equal(multipartSignedMessageBody);
    });

    it('processMIME - it can parse message with text attachment', async () => {
        const { verified, body, signatures, attachments } = await CryptoWorker.processMIME({
            data: multipartMessageWithAttachment
        });
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures.length).to.equal(0);
        expect(body).to.equal('this is the body text\n');
        expect(attachments.length).to.equal(1);
        const [attachment] = attachments;
        expect(attachment.fileName).to.equal('test.txt');
        expect(attachment.checksum).to.equal('94ee2b41f2016f2ec79a7b3a2faf920e');
        expect(attachment.content.length > 0).to.be.true;
        expect(utf8ArrayToString(attachment.content)).to.equal('this is the attachment text\r\n')
    });

    it('getMessageInfo - it returns correct keyIDs', async () => {
        const signedMessage = `-----BEGIN PGP MESSAGE-----

xA0DAQoWaZjmpnshsL8Bywt1AGIyFfFoZWxsb8J1BAEWCgAGBQJiMhXxACEJ
EGmY5qZ7IbC/FiEE3C2Gg07gzeD8liPcaZjmpnshsL9atgD+PiNipUtpGyv7
Jky/kRH9ikiCFdnNCPmXpGM/HXBQsnAA/jZVt+uBEVIgTeTJ9c7AqEgV3x9K
2Dj4M71DOHZr/lAL
=gTiI
-----END PGP MESSAGE-----`;
        const encryptedMessage = `-----BEGIN PGP MESSAGE-----

wV4DmdSzzm35uOMSAQdAfIPK4Iteh+VVFIddVCaR60ETJ8mhx6ytbR7ppS4h
qiAwqc/J464YnVgZ8BbGLt0k2ipAsR5y0M+I+GivWhCXMSKtRwvBmwiCgiE7
PzIOge9V0jYBuRj2e07jffFN7LDy9Q6kaLdkj+R/pAJi1StBntsW0sBBSkcN
xMT1c31ROTrAe4C6g21wLAY=
=2VmX
-----END PGP MESSAGE-----`;

        const signedMessageInfo = await CryptoWorker.getMessageInfo({ armoredMessage: signedMessage });
        expect(signedMessageInfo.encryptionKeyIDs).to.deep.equal([]);
        expect(signedMessageInfo.signingKeyIDs).to.deep.equal(['6998e6a67b21b0bf']);

        const encryptedMessageInfo = await CryptoWorker.getMessageInfo({ armoredMessage: encryptedMessage });
        expect(encryptedMessageInfo.encryptionKeyIDs).to.deep.equal(['99d4b3ce6df9b8e3']);
        expect(encryptedMessageInfo.signingKeyIDs).to.deep.equal([]);
    });

    it('getSignatureInfo - it returns correct keyIDs', async () => {
        const armoredSignature = `-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmIyIZcAIQkQaZjmpnshsL8WIQTcLYaDTuDN4PyWI9xpmOam
eyGwv58uAQDBVzpXdSjXtEleTrlCDV0Ai7edrGelnbYl5M5QWHsO6AEA7ylY
M8uical4EQWijKwbwpfCViRXlPLbWED7HjRFJAQ=
=jrvP
-----END PGP SIGNATURE-----`;

        const signatureInfo = await CryptoWorker.getSignatureInfo({ armoredSignature });
        expect(signatureInfo.signingKeyIDs).to.deep.equal(['6998e6a67b21b0bf']);
    });

    it('getKeyInfo - it returns correct key type and encryption status', async () => {
        const armoredPublicKey = ecc25519Key;
        const armoredDecryptedPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYjn/DRYJKwYBBAHaRw8BAQdACQUzjf/48LfAqt/iJoCLvNh82ezGNLad
uLoCyyqP+kMAAQDlR+FqVc7sOXkWw9Ce21H9U75JbXkQZdopNT6rmUP5eRDN
zRE8dGVzdEB3b3JrZXIuY29tPsKMBBAWCgAdBQJiOf8NBAsJBwgDFQgKBBYA
AgECGQECGwMCHgEAIQkQgXhWyqdTIuIWIQSLE8CDw3U8LVFQRY6BeFbKp1Mi
4kBPAQCHH7+sA6/Rvn/cABOPdGuDz6LtBB2pai5ahUuYTyBP1QEAgG/KR/AX
fWuidzPVytVcHmE7PH0ZUe/J8qAxszespALHXQRiOf8NEgorBgEEAZdVAQUB
AQdAi+mqfJuhbYqNNrCRb0w8dDMImkdk9ygaZZXgzh6REWwDAQgHAAD/eBLr
qR+dnBSXPk7n+0+/6bWjBWrYc6vDElTpPSA3stARasJ4BBgWCAAJBQJiOf8N
AhsMACEJEIF4VsqnUyLiFiEEixPAg8N1PC1RUEWOgXhWyqdTIuLV3QD/e6jQ
Y9qpG8A3sC7ZB29GClPXVJy6uL2Ai5R37cGozfUA/REr1bi6Ac4FauZsge1+
Z3SSOseslp6+4nnQ3zOqnisO
=pEmk
-----END PGP PRIVATE KEY BLOCK-----`;
        const encryptedPrivateKey = await openpgp_encryptKey({
            privateKey: await openpgp_readPrivateKey({ armoredKey: armoredDecryptedPrivateKey }),
            passphrase: 'passphrase'
        });

        const publicKeyInfo = await CryptoWorker.getKeyInfo({ armoredKey: armoredPublicKey });
        expect(publicKeyInfo.keyIsPrivate).to.be.false;
        expect(publicKeyInfo.keyIsDecrypted).to.be.null;
        const decryptedKeyInfo = await CryptoWorker.getKeyInfo({ armoredKey: armoredDecryptedPrivateKey });
        expect(decryptedKeyInfo.keyIsPrivate).to.be.true;
        expect(decryptedKeyInfo.keyIsDecrypted).to.be.true;

        const encryptedKeyInfo = await CryptoWorker.getKeyInfo({ armoredKey: encryptedPrivateKey.armor() });
        expect(encryptedKeyInfo.keyIsPrivate).to.be.true;
        expect(encryptedKeyInfo.keyIsDecrypted).to.be.false;
        expect(encryptedKeyInfo.fingerprint).to.equal(encryptedPrivateKey.getFingerprint());
    });

    it('getArmoredKeys - it returns a valid armored key', async () => {
        const hexBinaryPublicKey = `c63304623b4fac16092b06010401da470f010107405787b1d537d9974a40fea2f239578b81c355991ac4fe619a1595c3f21ecfb3abcd113c7465737440776f726b65722e636f6d3ec28c0410160a001d0502623b4fac040b0907080315080a0416000201021901021b03021e0100210910db8c8a5d901c2766162104d26cda9d40b4fea61b6cb65adb8c8a5d901c2766f80e00fd1eb4b4c4917d18436081ff9f463b9cc595af7805c789ba3b57a6b66511ff95d600fe36072060165618fed927051527d585ff26c3293b42671f2a169f47a4df6ba50cce3804623b4fac120a2b06010401975501050101074057571d1c77fbcb8f9fd0abd3d4f0e95ea725f569a49ec4faf0d2d0df8df3cd4103010807c2780418160800090502623b4fac021b0c00210910db8c8a5d901c2766162104d26cda9d40b4fea61b6cb65adb8c8a5d901c27665f760100e650904af11ea8933e9b91028df04375867f15b2542e8f8f86c2069081f66ed000fb06ddfa8ce3370eb9b92e93c40f7a624c1bf3b190f26beba3a9a93107b9ad310e`;

        const armoredKeys = await CryptoWorker.getArmoredKeys({
            binaryKeys: hexToUint8Array(hexBinaryPublicKey)
        });
        expect(armoredKeys).to.have.length(1);
        const key = await openpgp_readKey({ armoredKey: armoredKeys[0] });
        expect(key.isPrivate()).to.be.false;
    });

    it('getArmoredSignature - it returns a valid armored signature', async () => {
        const hexBinarySignature = `c2750401160a0006050262351cc9002109101a5092c9a2df33531621041f75b4729655e143dc146f941a5092c9a2df33532cba0100ab31401b4aca8b449dc490d16927e37c9510c076745795b3e73bba0209b826770100dc6a6fcc1aaa6fcbce51a5b20682ea201414ec923d387a4eb88932df87f6e60c`;

        const armoredSignature = await CryptoWorker.getArmoredSignature({
            binarySignature: hexToUint8Array(hexBinarySignature)
        });
        const signatureInfo = await CryptoWorker.getSignatureInfo({ armoredSignature });
        expect(signatureInfo.signingKeyIDs).to.not.be.empty;
    });

    it('isExpiredKey/canKeyEncrypt - it can correctly detect an expired key', async () => {
        const now = new Date();
        const future = new Date(+now + 1000);
        const past = new Date(+now - 1000);
        // key expires in one second
        const expiringKeyRef = await CryptoWorker.generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: now,
            keyExpirationTime: 1
        });
        expect(await CryptoWorker.isExpiredKey({ keyReference: expiringKeyRef, date: now })).to.be.false;
        expect(await CryptoWorker.isExpiredKey({ keyReference: expiringKeyRef, date: future })).to.be.true;
        expect(await CryptoWorker.isExpiredKey({ keyReference: expiringKeyRef, date: past })).to.be.true;
        // canKeyEncrypt should return false for expired keys
        expect(await CryptoWorker.canKeyEncrypt({ keyReference: expiringKeyRef, date: now })).to.be.true;
        expect(await CryptoWorker.canKeyEncrypt({ keyReference: expiringKeyRef, date: past })).to.be.false;

        const keyReference = await CryptoWorker.generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: now
        });
        expect(await CryptoWorker.isExpiredKey({ keyReference })).to.be.false;
        expect(await CryptoWorker.isExpiredKey({ keyReference, date: past })).to.be.true;
    });

    it('isRevokedKey/canKeyEncrypt - it can correctly detect a revoked key', async () => {
        const past = new Date(0);
        const now = new Date();

        const { privateKey: key, revocationCertificate } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: past,
            format: 'object'
        });
        const { publicKey: armoredRevokedKey } = await openpgp_revokeKey({
            key,
            revocationCertificate
        });

        const keyRef = await CryptoWorker.importPublicKey({ armoredKey: key.armor() });
        const revokedKeyRef = await CryptoWorker.importPublicKey({ armoredKey: armoredRevokedKey });
        expect(await CryptoWorker.isRevokedKey({ keyReference: revokedKeyRef, date: past })).to.be.true;
        expect(await CryptoWorker.isRevokedKey({ keyReference: revokedKeyRef, date: now })).to.be.true;
        expect(await CryptoWorker.isRevokedKey({ keyReference: keyRef, date: now })).to.be.false;
        // canKeyEncrypt should return false for revoked key
        expect(await CryptoWorker.canKeyEncrypt({ keyReference: revokedKeyRef, date: now })).to.be.false;
        expect(await CryptoWorker.canKeyEncrypt({ keyReference: keyRef, date: now })).to.be.true;
    });

    it('getSHA256Fingerprints - it returns the expected fingerprints', async () => {
        const key = await openpgp_readKey({ armoredKey: ecc25519Key });
        const keyReference = await CryptoWorker.importPublicKey({ armoredKey: ecc25519Key });
        const sha256Fingerprings = await CryptoWorker.getSHA256Fingerprints({ keyReference });
        expect(sha256Fingerprings).to.deep.equal(await getSHA256Fingerprints(key));
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
            expect(importedKeyRef.getCreationTime()).to.deep.equal(keyToImport.getCreationTime());
            expect(
                importedKeyRef.subkeys.map((subkey) => subkey.getAlgorithmInfo())
            ).to.deep.equal(keyToImport.subkeys.map((subkey) => subkey.getAlgorithmInfo()));
            expect(importedKeyRef.getUserIDs()).to.deep.equal(['name <email@test.com>']);
            const armoredPublicKey = await CryptoWorker.exportPublicKey({ keyReference: importedKeyRef });
            const exportedPublicKey = await openpgp_readKey({ armoredKey: armoredPublicKey });
            expect(exportedPublicKey.isPrivate()).to.be.false;
            expect(exportedPublicKey.getKeyID().toHex()).equals(importedKeyRef.getKeyID())
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

        it('exports an unencrypted key only when given a null passphrase', async () => {
            const keyReference = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });

            // empty passphrase not allowed
            await expect(CryptoWorker.exportPrivateKey({ keyReference, passphrase: '' })).to.be.rejectedWith(/passphrase is required for key encryption/);
            const armoredEncryptedKey = await CryptoWorker.exportPrivateKey({ keyReference, passphrase: 'passphrase' });
            const encryptedKey = await openpgp_readPrivateKey({ armoredKey: armoredEncryptedKey })
            expect(encryptedKey.isDecrypted()).to.be.false;
            const armoredUnencryptedKey = await CryptoWorker.exportPrivateKey({
                keyReference, passphrase: null
            });
            const unencryptedKey = await openpgp_readPrivateKey({ armoredKey: armoredUnencryptedKey })
            expect(unencryptedKey.isDecrypted()).to.be.true;
        });

        it('cannot import or export a public key as a private key', async () => {
            const passphrase = 'passphrase';
            const { publicKey: publicKeyToImport } = await generateKey({ userIDs: { name: 'name', email: 'email@test.com' }, format: 'object', passphrase });

            // this give no typescript error since serialised keys are indistinguishable for TS
            await expect(CryptoWorker.importPrivateKey({ armoredKey: publicKeyToImport.armor(), passphrase })).to.be.rejectedWith(/not of type private key/);
            const importedKeyRef = await CryptoWorker.importPublicKey({ armoredKey: publicKeyToImport.armor() });
            expect(importedKeyRef.isPrivate()).to.be.false;
            expect(importedKeyRef.getCreationTime()).to.deep.equal(publicKeyToImport.getCreationTime());
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

        it('reformatted key has a separate key reference', async () => {
            const passphrase = 'passphrase';
            const originalKeyRef = await CryptoWorker.importPrivateKey({
                armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEYjh/NRYJKwYBBAHaRw8BAQdAAJW2i9biFMIXiH15J6vGU1GCAqcp5utw
C+y+CeZ+h4L+CQMI/K3Ebi8BpsUAzexw43SwgpD0mDGd/d4ORX77AiUoq/rp
DKjS+0lpIszAa6SVWcA6xQZsz1ztdNBktEg4t/gybivH88kGTIprO/HWetM+
j80RPHRlc3RAd29ya2VyLmNvbT7CjAQQFgoAHQUCYjh/NQQLCQcIAxUICgQW
AAIBAhkBAhsDAh4BACEJEFx55sPEaXlKFiEE+PdMNIqw4jCyqqnuXHnmw8Rp
eUoC8QD+NdQzOAWdIJEp1eMeEa3xx9rkCpD2TXUeV7goHtixyQIBANcgmRTg
gN0O2hdiL9kjN4MPhbkz3dNTpkiO/K6O8UIDx4sEYjh/NRIKKwYBBAGXVQEF
AQEHQF3XUaFXbb6O9Qcas72x5nhNupZ3iIrIx8wKeUdgdkBNAwEIB/4JAwjK
CPlfkyHxBABYJC70HwO36TjRBxROY480CvL40r1bJ3NSLlV4aIZXLP2723PH
tsnD3fhK5ZbGqC7FCmmDKEh1ibl3Lw6rEoE0Z6Fq72x6wngEGBYIAAkFAmI4
fzUCGwwAIQkQXHnmw8RpeUoWIQT490w0irDiMLKqqe5ceebDxGl5Sl9wAQC+
9Jb0r5pG7sMbNclmp3s1OIfWG9tJ9RoXSHU/bCFHlgEA/ggjJKzRuja0MWZ6
8IDTErKCgaYSPES5+mwT27LYvw0=
=D7EW
-----END PGP PRIVATE KEY BLOCK-----`,
                passphrase
            });

            const reformattedKeyRef = await CryptoWorker.reformatKey({ keyReference: originalKeyRef, userIDs: { email: 'reformatted@worker.com' } });
            expect(reformattedKeyRef.getUserIDs()).to.have.length(1);
            expect(reformattedKeyRef.getUserIDs().includes('<reformatted@worker.com>'));
            expect(originalKeyRef.getUserIDs()).to.have.length(1);
            expect(originalKeyRef.getUserIDs()).includes('<test@worker.com>');

            await CryptoWorker.clearKey({ keyReference: originalKeyRef }); // this clears the private params as well

            const armoredKey = await CryptoWorker.exportPrivateKey({ keyReference: reformattedKeyRef, passphrase });
            const decryptedKeyFromArmored = await openpgp_decryptKey({
                privateKey: await openpgp_readPrivateKey({ armoredKey }),
                passphrase
            });
            expect(decryptedKeyFromArmored.isDecrypted()).to.be.true;
        });

        it('isWeak() - it correctly marks a weak key', async () => {
            const weakKeyReference = await CryptoWorker.importPublicKey({ armoredKey: rsa512BitsKey });
            expect(weakKeyReference.isWeak()).to.be.true;

            const keyReference = await CryptoWorker.importPublicKey({ armoredKey: ecc25519Key });
            expect(keyReference.isWeak()).to.be.false;
        });

        it('equals - returns true for equal public keys', async () => {
            const userIDs = { name: 'name', email: 'email@test.com' };
            const { privateKey, publicKey } = await generateKey({ userIDs, format: 'object' });

            const privateKeyRef = await CryptoWorker.importPrivateKey({
                armoredKey: privateKey.armor(), passphrase: null
            });
            const publicKeyRef = await CryptoWorker.importPublicKey({ armoredKey: publicKey.armor() });
            expect(privateKeyRef.equals(publicKeyRef)).to.be.true;

            // change expiration time
            const { privateKey: armoredReformattedKey } = await reformatKey({
                privateKey, userIDs, keyExpirationTime: 3600
            })
            const reformattedKeyRef = await CryptoWorker.importPrivateKey({
                armoredKey: armoredReformattedKey, passphrase: null
            });
            expect(privateKeyRef.equals(reformattedKeyRef)).to.be.false;
        });

        it('clearKey - cannot reference a cleared key', async () => {
            const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            // confirm key is in the store
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef })).length.above(0);
            await CryptoWorker.clearKey({ keyReference: privateKeyRef });

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
