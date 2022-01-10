import { expect } from 'chai';
import {
    util,
    // @ts-ignore not declared as exported
    stream,
    enums
} from 'openpgp';

import {
    decryptPrivateKey,
    getMessage,
    verifyMessage,
    encryptMessage,
    decryptMessage,
    createMessage,
    getSignature
} from '../../lib';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { openpgp } from '../../lib/openpgp';

describe('encryptMessage', () => {
    it('it can encrypt and decrypt a message', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey]
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session keys', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, sessionKey } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            returnSessionKey: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            publicKeys: [decryptedPrivateKey.toPublic()],
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it does not compress a message by default', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, sessionKey } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            returnSessionKey: true
        });
        const encryptedMessage = await getMessage(encrypted);
        const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKey]);
        expect(decryptedMessage.packets.findPacket(enums.packet.compressed)).to.equal(undefined);
    });

    it('it compresses the message if the compression option is specified', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            returnSessionKey: true,
            compression: enums.compression.zip
        });
        const encryptedMessage = await getMessage(encrypted);
        const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKeys]);
        const compressedPacket = decryptedMessage.packets.findPacket(enums.packet.compressed) as openpgp.packet.Compressed;
        expect(compressedPacket).to.not.be.undefined;
        expect(compressedPacket.algorithm).to.equal('zip');
    });

    it('it can encrypt and decrypt a message with an unencrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, signature } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            signature: await getSignature(signature),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        const { verified: verifiedAgain } = await verifyMessage({
            message: await createMessage('Hello world!'),
            signature: await getSignature(signature),
            publicKeys: [decryptedPrivateKey.toPublic()]
        });
        expect(verifiedAgain).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { data: encrypted, encryptedSignature } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            encryptedSignature: await getMessage(encryptedSignature),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey]
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt a message and decrypt it unarmored using session keys along with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            returnSessionKey: true,
            detached: true,
            armor: false
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            publicKeys: [decryptedPrivateKey.toPublic()],
            encryptedSignature: await getMessage(encryptedSignature),
            sessionKeys
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session key without setting returnSessionKey', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const sessionKey = {
            data: util.hex_to_Uint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: 'aes256'
        };
        const { data: encrypted } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            sessionKey
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            publicKeys: [decryptedPrivateKey.toPublic()],
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const sessionKey = {
            data: util.hex_to_Uint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
            algorithm: 'aes256'
        };
        const { data: encrypted, encryptedSignature } = await encryptMessage({
            message: await createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            detached: true,
            sessionKey
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            publicKeys: [decryptedPrivateKey.toPublic()],
            encryptedSignature: await getMessage(encryptedSignature),
            sessionKeys: sessionKey
        });
        expect(decrypted).to.equal('Hello world!');
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with an unencrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys, signature } = await encryptMessage({
            message: createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            armor: false,
            returnSessionKey: true,
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            signature: await getSignature(signature),
            sessionKeys,
            publicKeys: [decryptedPrivateKey.toPublic()],
            streaming: 'web',
            format: 'binary'
        });
        expect(util.Uint8Array_to_str(await stream.readToEnd(decrypted))).to.equal('Hello world!');
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
            message: createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            streaming: 'web',
            armor: false,
            returnSessionKey: true,
            detached: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            encryptedSignature: await getMessage(encryptedSignature),
            sessionKeys,
            publicKeys: [decryptedPrivateKey.toPublic()],
            streaming: 'web',
            format: 'binary'
        });
        expect(util.Uint8Array_to_str(await stream.readToEnd(decrypted))).to.equal('Hello world!');
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it can encrypt and decrypt a binary streamed message with in-message signature', async () => {
        const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
        const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
            message: createMessage('Hello world!'),
            publicKeys: [decryptedPrivateKey.toPublic()],
            privateKeys: [decryptedPrivateKey],
            streaming: 'web',
            armor: false,
            returnSessionKey: true
        });
        const { data: decrypted, verified } = await decryptMessage({
            message: await getMessage(encrypted),
            sessionKeys,
            publicKeys: [decryptedPrivateKey.toPublic()],
            streaming: 'web',
            format: 'binary'
        });
        expect(util.Uint8Array_to_str(await stream.readToEnd(decrypted))).to.equal('Hello world!');
        expect(await verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
});
