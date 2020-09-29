import test from 'ava';
import '../helper';

import { createMessage, getMessage, getSignature, verifyMessage } from '../../lib/message/utils';
import encryptMessage from '../../lib/message/encrypt';
import { decryptMessage } from '../../lib/message/decrypt';
import { decryptPrivateKey, generateSessionKey } from '../../lib';
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
        data: new Uint8Array([
            197,
            98,
            157,
            132,
            15,
            214,
            78,
            245,
            90,
            234,
            71,
            79,
            135,
            220,
            222,
            239,
            118,
            187,
            199,
            152,
            163,
            64,
            239,
            103,
            4,
            83,
            21,
            235,
            121,
            36,
            163,
            111
        ]),
        algorithm: 'aes256'
    };
    const { data: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: createMessage('Hello world!'),
        publicKeys: [decryptedPrivateKey.toPublic()],
        privateKeys: [decryptedPrivateKey],
        sessionKey
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        publicKeys: [decryptedPrivateKey.toPublic()],
        sessionKeys
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: new Uint8Array([
            197,
            98,
            157,
            132,
            15,
            214,
            78,
            245,
            90,
            234,
            71,
            79,
            135,
            220,
            222,
            239,
            118,
            187,
            199,
            152,
            163,
            64,
            239,
            103,
            4,
            83,
            21,
            235,
            121,
            36,
            163,
            111
        ]),
        algorithm: 'aes256'
    };
    const { data: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
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
        sessionKeys
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});
