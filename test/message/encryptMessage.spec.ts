import test from 'ava';
import '../helper';
// @ts-ignore missing web-stream-tools types
import { readToEnd, toStream, loadStreamsPonyfill } from '@openpgp/web-stream-tools';
// eslint-disable-next-line camelcase
import { config, readMessage, createMessage as openpgp_createMessage, CompressedDataPacket, enums } from 'openpgp';

import { decryptPrivateKey, getMessage, verifyMessage, encryptMessage, decryptMessage, createMessage, getSignature,  } from '../../lib';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { hexToUint8Array, arrayToBinaryString } from '../../lib/utils';

const { minRSABits } = config;
test.before('setup streaming helpers and downgrade openpgp config', async () => {
    await loadStreamsPonyfill();

    config.minRSABits = 512;
});
test.after('restore openpgp config', async () => {
    config.minRSABits = minRSABits;
});

test('it can encrypt and decrypt a message', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey]
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey]
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session keys', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        returnSessionKey: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        sessionKeys: sessionKey
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it does not compress a message by default', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey } = await encryptMessage({
        message: createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        returnSessionKey: true
    });
    const encryptedMessage = await getMessage(encrypted);
    const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKey]);
    t.is(decryptedMessage.packets.findPacket(enums.packet.compressedData), undefined);
});

test('it compresses the message if the compression option is specified', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        returnSessionKey: true,
        // compression: enums.compression.zip TODO fix compression test
    });
    const encryptedMessage = await getMessage(encrypted);
    const decryptedMessage = await encryptedMessage.decrypt([], [], [sessionKeys]);
    const compressedPacket = decryptedMessage.packets.findPacket(enums.packet.compressedData) as CompressedDataPacket;
    t.not(compressedPacket, undefined);
    // @ts-ignore undeclared algorithm field
    t.is(compressedPacket.algorithm, 'zip');
});

test('it can encrypt and decrypt a message with an unencrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, signature } = await encryptMessage({
        message: await createMessage('Hello world!'),
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
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    const { verified: verifiedAgain } = await verifyMessage({
        message: await createMessage('Hello world!'),
        signature: await getSignature(signature),
        verificationKeys: [decryptedPrivateKey.toPublic()]
    });
    t.is(verifiedAgain, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        detached: true,
        armor: false
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        encryptedSignature: await getMessage(encryptedSignature),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey]
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt a message and decrypt it unarmored using session keys along with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        returnSessionKey: true,
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        encryptedSignature: await getMessage(encryptedSignature),
        sessionKeys
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
        algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
    };
    const { data: encrypted } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        sessionKey
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey],
        sessionKeys: sessionKey
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
        algorithm: enums.read(enums.symmetric, enums.symmetric.aes256)
    };
    const { data: encrypted, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        detached: true,
        sessionKey
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        encryptedSignature: await getMessage(encryptedSignature),
        sessionKeys: sessionKey
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with an unencrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, signature } = await encryptMessage({
        message: await openpgp_createMessage({ text: toStream('Hello world!') }),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        armor: false,
        returnSessionKey: true,
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await readMessage({ binaryMessage: encrypted.write() }), // TODO re-enable streaming
        signature,
        sessionKeys,
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey],
        format: 'binary'
    });
    t.is(arrayToBinaryString(await readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
        message: await openpgp_createMessage({ text: toStream('Hello world!') }),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        armor: false,
        returnSessionKey: true,
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        encryptedSignature: await getMessage(encryptedSignature),
        sessionKeys,
        verificationKeys: [decryptedPrivateKey.toPublic()],
        format: 'binary'
    });
    t.is(arrayToBinaryString(await readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with in-message signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: await openpgp_createMessage({ text: toStream('Hello world!') }),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        armor: false,
        returnSessionKey: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        sessionKeys,
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        format: 'binary'
    });
    t.is(arrayToBinaryString(await readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});
