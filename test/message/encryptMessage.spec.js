import test from 'ava';
import '../helper';
import { util, stream, enums } from 'openpgp';

import { createMessage, getMessage, getSignature, verifyMessage } from '../../lib/message/utils';
import encryptMessage from '../../lib/message/encrypt';
import { decryptMessage } from '../../lib/message/decrypt';
import { decryptPrivateKey } from '../../lib';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';

test('it can encrypt and decrypt a message', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey]
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey]
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session keys', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey],
        returnSessionKey: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        publicKeys: [decryptedPrivateKey.toPublic()],
        sessionKeys
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it does not compress a message by default', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey],
        returnSessionKey: true
    });
    const encryptedMessage = await getMessage(encrypted);
    const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKeys]);
    t.is(decryptedMessage.packets.findPacket(enums.packet.compressed), undefined);
});

test('it compresses the message if the compression option is specified', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey],
        returnSessionKey: true,
        compression: enums.compression.zip
    });
    const encryptedMessage = await getMessage(encrypted);
    const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKeys]);
    const compressedPacket = decryptedMessage.packets.findPacket(enums.packet.compressed);
    t.not(compressedPacket, undefined);
    t.is(compressedPacket.algorithm, 'zip');
});

test('it can encrypt and decrypt a message with an unencrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, signature } = await encryptMessage({
        message: createMessage('Hello world!'),
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
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    const { verified: verifiedAgain } = await verifyMessage({
        message: createMessage('Hello world!'),
        signature: await getSignature(signature),
        publicKeys: [decryptedPrivateKey.toPublic()]
    });
    t.is(verifiedAgain, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, encryptedSignature } = await encryptMessage({
        message: createMessage('Hello world!'),
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
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt a message and decrypt it unarmored using session keys along with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
        message: createMessage('Hello world!'),
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
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: util.hex_to_Uint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
        algorithm: 'aes256'
    };
    const { data: encrypted } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey],
        sessionKey
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        publicKeys: [decryptedPrivateKey.toPublic()],
        sessionKeys: sessionKey
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: util.hex_to_Uint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
        algorithm: 'aes256'
    };
    const { data: encrypted, encryptedSignature } = await encryptMessage({
        message: createMessage('Hello world!'),
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
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with an unencrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, signature } = await encryptMessage({
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
        signature: await getSignature(signature),
        sessionKeys,
        publicKeys: [decryptedPrivateKey.toPublic()],
        streaming: 'web',
        format: 'binary'
    });
    t.is(util.Uint8Array_to_str(await stream.readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async (t) => {
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
    t.is(util.Uint8Array_to_str(await stream.readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with in-message signature', async (t) => {
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
    t.is(util.Uint8Array_to_str(await stream.readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});
