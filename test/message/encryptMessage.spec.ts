import { expect } from 'chai';
// @ts-ignore missing web-stream-tools types
import { readToEnd, ReadableStream, WritableStream, toStream } from '@openpgp/web-stream-tools';
import { config, readMessage, CompressedDataPacket, enums } from '../../lib/openpgp';

import { decryptPrivateKey, getMessage, verifyMessage, encryptMessage, decryptMessage, getSignature, stringToUtf8Array  } from '../../lib';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { hexToUint8Array, arrayToBinaryString } from '../../lib/utils';

const generateStreamOfData = (): { stream: ReadableStream<string>, data: string } => ({
    stream: new ReadableStream({ pull: (controller: WritableStream) => { for (let i = 0; i < 10000; i++ ) { controller.enqueue('string'); } controller.close() } }),
    data: 'string'.repeat(10000)
});

describe('encryptMessage', () => {
    const { minRSABits } = config;
    before('downgrade openpgp config', () => {
        config.minRSABits = 512;
    });
    after('restore openpgp config', async () => {
        config.minRSABits = minRSABits;
    });

    it('it can encrypt and decrypt a text message', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey]
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary message', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted } = await encryptMessage({
            binaryData: stringToUtf8Array('Hello world!'),
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey]
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey],
            format: 'binary'
        });
        expect(decrypted).to.deep.equal(stringToUtf8Array('Hello world!'));
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session keys', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            returnSessionKey: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it does not compress a message by default', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            returnSessionKey: true
        });
        const encryptedMessage = await getMessage(encrypted);
        const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKey]);
        expect(decryptedMessage.packets.findPacket(enums.packet.compressedData)).to.be.undefined;
    });

    it('it compresses the message if the compression option is specified', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            returnSessionKey: true,
            // NB: the specified compression algo must appear in the encryption key preferences, or it won't be used
            config: { preferredCompressionAlgorithm: enums.compression.zlib }
        });
        const encryptedMessage = await getMessage(encrypted);
        const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKeys]);
        const compressedPacket = decryptedMessage.packets.findPacket(
            enums.packet.compressedData
        ) as CompressedDataPacket;
        expect(compressedPacket).to.not.be.undefined;
        // @ts-ignore undeclared algorithm field
        expect(compressedPacket.algorithm).to.equal(enums.compression.zlib);
    });

    it('it can encrypt and decrypt a message with an unencrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, signature } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            signature: await getSignature(signature),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        const { verified: verifiedAgain } = await verifyMessage({
            textData: 'Hello world!',
            signature: await getSignature(signature),
            verificationKeys: [decryptedPrivateKey.toPublic()]
        });
        expect(verifiedAgain).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, encryptedSignature } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            encryptedSignature: await getMessage(encryptedSignature),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            decryptionKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt a message and decrypt it unarmored using session keys along with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            returnSessionKey: true,
            detached: true,
            format: 'object'
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            encryptedSignature: await getMessage(encryptedSignature),
            sessionKeys
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session key without setting returnSessionKey', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const sessionKey = {
            data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
        };
        const { message: encrypted } = await encryptMessage({
            textData: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            sessionKey
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const sessionKey = {
            data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
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
            message: await getMessage(encrypted),
            verificationKeys: [decryptedPrivateKey.toPublic()],
            encryptedSignature: await getMessage(encryptedSignature),
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a streamed message with an unencrypted detached signature (format = armored)', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            format: 'armored',
            returnSessionKey: true,
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: await readToEnd(encrypted) }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            sessionKeys,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal(inputData);
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a streamed message with an unencrypted detached signature (format = binary)', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            format: 'binary',
            returnSessionKey: true,
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ binaryMessage: await readToEnd(encrypted) }),
            encryptedSignature: await readMessage({ binaryMessage: encryptedSignature }),
            sessionKeys,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal(inputData);
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            format: 'armored',
            returnSessionKey: true,
            detached: true
        });
        const encryptedArmoredMessage = await readToEnd(encrypted);

        const { data: decrypted, verified } = await decryptMessage({
            message: await readMessage({ armoredMessage: toStream(encryptedArmoredMessage) }),
            encryptedSignature: await readMessage({ armoredMessage: encryptedSignature }),
            sessionKeys,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal(inputData);
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with in-message signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { stream: inputStream, data: inputData }  = generateStreamOfData();
        const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
            textData: inputStream,
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            format: 'object',
            returnSessionKey: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            sessionKeys,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(await readToEnd(decrypted).then(arrayToBinaryString)).to.equal(inputData);
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
})
