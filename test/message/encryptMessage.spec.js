import test from 'ava';
import '../helper';
import { hexToUint8Array, arrayToBinaryString } from '../../lib/utils';
import { readMessage, stream } from 'openpgp';

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
        data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
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
        data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
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
        message: await readMessage(encrypted),
        signature: await getSignature(signature),
        sessionKeys,
        publicKeys: [decryptedPrivateKey.toPublic()],
        streaming: 'web',
        format: 'binary'
    });
    t.is(arrayToBinaryString(await stream.readToEnd(decrypted)), 'Hello world!');
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
        message: await readMessage(encrypted),
        encryptedSignature: await readMessage(encryptedSignature),
        sessionKeys,
        publicKeys: [decryptedPrivateKey.toPublic()],
        streaming: 'web',
        format: 'binary'
    });
    t.is(arrayToBinaryString(await stream.readToEnd(decrypted)), 'Hello world!');
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
        message: await readMessage(encrypted),
        sessionKeys,
        publicKeys: [decryptedPrivateKey.toPublic()],
        streaming: 'web',
        format: 'binary'
    });
    t.is(arrayToBinaryString(await stream.readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it fails to verfify incorrect signatures', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data: encrypted } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        signature: await createMessage('Good Bye World!').signDetached([decryptedPrivateKey])
    });
    const { verified } = await decryptMessage({
        message: await getMessage(encrypted),
        privateKeys: [decryptedPrivateKey],
        publicKeys: [decryptedPrivateKey.toPublic()]
    });
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_INVALID);
});

test('it can verify a message with nonbreaking spaces both with in-message and detached signatures', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const validMessage = createMessage('Hello world!');

    const { verified } = await verifyMessage({
        message: createMessage('Hello\xa0world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        signature: await validMessage.signDetached([decryptedPrivateKey])
    });
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});
