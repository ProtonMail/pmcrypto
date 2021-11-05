import test from 'ava';
import '../helper';

import { decryptPrivateKey, decryptMessageLegacy } from '../../lib';
import { testMessageEncryptedLegacy, testPrivateKeyLegacy, testMessageResult, testMessageEncryptedStandard } from './decryptMessageLegacy.data';

test('it can decrypt a legacy message', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data } = await decryptMessageLegacy({
        message: testMessageEncryptedLegacy,
        decryptionKeys: [decryptedPrivateKey],
        messageDate: new Date('2015-01-01')
    });
    t.is(data, testMessageResult);
});

test('it can decrypt a non-legacy armored message', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');

    const { data } = await decryptMessageLegacy({
        message: testMessageEncryptedStandard,
        decryptionKeys: [decryptedPrivateKey],
        messageDate: new Date('2015-01-01')
    });

    t.is(data, testMessageResult);
});
