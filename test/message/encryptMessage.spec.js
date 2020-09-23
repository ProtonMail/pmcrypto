import test from 'ava';
import '../helper';

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
