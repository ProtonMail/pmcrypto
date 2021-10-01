import test from 'ava';
import '../helper';

import { decryptPrivateKey, decryptMessageLegacy } from '../../lib';
import { testMessageEncryptedLegacy, testPrivateKeyLegacy, testMessageResult } from './decryptMessageLegacy.data';

test('it can decrypt a legacy message', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { data } = await decryptMessageLegacy({
        message: testMessageEncryptedLegacy,
        privateKeys: [decryptedPrivateKey],
        messageDate: new Date('2015-01-01')
    });
    t.is(data, testMessageResult);
});
