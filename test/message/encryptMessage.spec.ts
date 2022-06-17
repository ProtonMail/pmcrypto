import { expect } from 'chai';
// @ts-ignore missing web-stream-tools types
import { readToEnd, ReadableStream, WritableStream, toStream, WebStream } from '@openpgp/web-stream-tools';
import { config, CompressedDataPacket, enums } from '../../lib/openpgp';

import { decryptKey, readPrivateKey, verifyMessage, encryptMessage, decryptMessage, generateSessionKey, readSignature, readMessage } from '../../lib';
import { hexStringToArray, arrayToBinaryString, stringToUtf8Array } from '../../lib/utils';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';

const generateStreamOfData = (): { stream: WebStream<string>, data: string } => ({
    stream: new ReadableStream({ pull: (controller: WritableStream) => { for (let i = 0; i < 10000; i++ ) { controller.enqueue('string'); } controller.close() } }),
    data: 'string'.repeat(10000)
});

describe('message encryption and decryption', () => {
    const { minRSABits } = config;
    before('downgrade openpgp config', () => {
        config.minRSABits = 512;
    });
    after('restore openpgp config', async () => {
        config.minRSABits = minRSABits;
    });

    it('it can encrypt and decrypt a text message', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey]
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary message', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { message: encrypted } = await encryptMessage({
            binaryData: stringToUtf8Array('Hello world!'),
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey]
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey],
            format: 'binary'
        });
        expect(decrypted).to.deep.equal(stringToUtf8Array('Hello world!'));
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with a given session key', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt a message with a session key from `generateSessionKey`', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const sessionKey = await generateSessionKey({ recipientKeys: decryptedPrivateKey });

        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: decryptedPrivateKey.toPublic(),
            sessionKey
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            decryptionKeys: decryptedPrivateKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
    });

    it('it does not compress a message by default', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey
        });
        const encryptedMessage = await readMessage({ armoredMessage: encrypted });
        const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKey]);
        expect(decryptedMessage.packets.findPacket(enums.packet.compressedData)).to.be.undefined;
    });

    it('it compresses the message if the compression option is specified', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey,
            // NB: the specified compression algo must appear in the encryption key preferences, or it won't be used
            config: { preferredCompressionAlgorithm: enums.compression.zlib }
        });
        const encryptedMessage = await readMessage({ armoredMessage: encrypted });
        const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKey]);
        const compressedPacket = decryptedMessage.packets.findPacket(
            enums.packet.compressedData
        ) as CompressedDataPacket;
        expect(compressedPacket).to.not.be.undefined;
        // @ts-ignore undeclared algorithm field
        expect(compressedPacket.algorithm).to.equal(enums.compression.zlib);
    });

    it('it can encrypt and decrypt a message with an unencrypted detached signature', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { message: encrypted, signature: armoredSignature } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        const { verified: verifiedAgain } = await verifyMessage({
            textData: 'Hello world!',
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [decryptedPrivateKey.toPublic()]
        });
        expect(verifiedAgain).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with an encrypted detached signature', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { message: encrypted, encryptedSignature } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };
        const { message: encrypted, encryptedSignature } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            detached: true,
            sessionKey
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: encrypted }),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a streamed message with an unencrypted detached signature (format = armored)', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted, encryptedSignature } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey,
            format: 'armored',
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: await readToEnd(encrypted) }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            sessionKeys: sessionKey,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal(inputData);
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a streamed message with an unencrypted detached signature (format = binary)', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted, encryptedSignature } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey,
            format: 'binary',
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ binaryMessage: await readToEnd(encrypted) as Uint8Array }),
            encryptedSignature: await readMessage({ binaryMessage: encryptedSignature }),
            sessionKeys: sessionKey,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal(inputData);
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted, encryptedSignature } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey,
            format: 'armored',
            detached: true
        });
        const encryptedArmoredMessage = await readToEnd(encrypted);

        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: toStream(encryptedArmoredMessage) }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            sessionKeys: sessionKey,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal(inputData);
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with in-message signature', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const sessionKey = {
            data: hexStringToArray('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };

        const { message: encrypted } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey,
            format: 'object'
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: encrypted,
            sessionKeys: sessionKey,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(await readToEnd(decrypted).then(arrayToBinaryString)).to.equal(inputData);
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
})
