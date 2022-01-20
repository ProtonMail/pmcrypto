import { expect } from 'chai';
// @ts-ignore missing web-stream-tools types
import { readToEnd, toStream, ReadableStream} from '@openpgp/web-stream-tools';
import { config, readMessage, CompressedDataPacket, enums } from '../../lib/openpgp';

import { decryptPrivateKey, getMessage, verifyMessage, encryptMessage, decryptMessage, createMessage, getSignature  } from '../../lib';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { hexToUint8Array, arrayToBinaryString } from '../../lib/utils';

describe('encryptMessage', () => {
    const { minRSABits } = config;
    before('downgrade openpgp config', () => {
        config.minRSABits = 512;
    });
    after('restore openpgp config', async () => {
        config.minRSABits = minRSABits;
    });

    it('it can encrypt and decrypt a message', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted } = await encryptMessage({
            text: 'Hello world!',
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

    it('it can encrypt and decrypt a message with session keys', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, sessionKey } = await encryptMessage({
            text: 'Hello world!',
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
        const { data: encrypted, sessionKey } = await encryptMessage({
            text: 'Hello world!',
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
        const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
            text: 'Hello world!',
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
        const { data: encrypted, signature } = await encryptMessage({
            text: 'Hello world!',
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
            message: await createMessage('Hello world!'),
            signature: await getSignature(signature),
            verificationKeys: [decryptedPrivateKey.toPublic()]
        });
        expect(verifiedAgain).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, encryptedSignature } = await encryptMessage({
            text: 'Hello world!',
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
            text: 'Hello world!',
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            returnSessionKey: true,
            detached: true,
            armor: false
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
        const { data: encrypted } = await encryptMessage({
            text: 'Hello world!',
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
        const { data: encrypted, encryptedSignature } = await encryptMessage({
            text: 'Hello world!',
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

    it('it can encrypt and decrypt a streamed message with an unencrypted detached signature (format = armor)', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const input = new ReadableStream({ pull: (controller: any) => { for(let i = 0; i< 10000; i++ ) { controller.enqueue('string'); } controller.close() } })
        const { data: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            text: input, // toStream('Hello world!'),
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            armor: true,
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
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal('string'.repeat(10000));
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            text: toStream('Hello world!'),
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            armor: true,
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
        expect(arrayToBinaryString(await readToEnd(decrypted))).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with in-message signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
            text: toStream('Hello world!'),
            encryptionKeys: [decryptedPrivateKey.toPublic()],
            signingKeys: [decryptedPrivateKey],
            armor: false,
            returnSessionKey: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            sessionKeys,
            verificationKeys: [decryptedPrivateKey.toPublic()],
            format: 'binary'
        });
        expect(await readToEnd(decrypted).then(arrayToBinaryString)).to.equal('Hello world!');
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
})
