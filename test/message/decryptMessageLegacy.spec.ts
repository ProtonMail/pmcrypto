import { expect } from 'chai';
import { decryptMessageLegacy, decryptKey, readPrivateKey } from '../../lib';
import { testMessageEncryptedLegacy, testPrivateKeyLegacy, testMessageResult, testMessageEncryptedStandard } from './decryptMessageLegacy.data';

describe('decryptMessageLegacy', () => {
    it('it can decrypt a legacy message', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { data } = await decryptMessageLegacy({
            armoredMessage: testMessageEncryptedLegacy,
            decryptionKeys: [decryptedPrivateKey],
            messageDate: new Date('2015-01-01')
        });
        expect(data).to.equal(testMessageResult);
    });

    it('it can decrypt a non-legacy armored message', async () => {
        const privateKey = await readPrivateKey({ armoredKey: testPrivateKeyLegacy });
        const decryptedPrivateKey = await decryptKey({ privateKey, passphrase: '123' });
        const { data } = await decryptMessageLegacy({
            armoredMessage: testMessageEncryptedStandard,
            decryptionKeys: [decryptedPrivateKey],
            messageDate: new Date('2015-01-01')
        });

        expect(data).to.equal(testMessageResult);
    });
});
