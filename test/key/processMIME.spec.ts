import { expect } from 'chai';

import processMIME from '../../lib/message/processMIME';
import { getKeys } from '../../lib';
import { VERIFICATION_STATUS } from '../../lib/constants';
import {
    invalidMultipartSignedMessage,
    multipartSignedMessage,
    multipartSignedMessageBody,
    extraMultipartSignedMessage,
    multiPartMessageWithSpecialCharacter,
    key
} from './processMIME.data';

describe('processMIME', () => {
    it('it can process multipart/signed mime messages and verify the signature', async () => {
        const { body, verified } = await processMIME(
            {
                publicKeys: await getKeys(key)
            },
            multipartSignedMessage
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(body).to.equal(multipartSignedMessageBody);
    });

    it('it can process multipart/signed mime messages and verify the signature with extra parts at the end', async () => {
        const { body, verified } = await processMIME(
            {
                publicKeys: await getKeys(key)
            },
            extraMultipartSignedMessage
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(body).to.equal('hello');
    });
    
    it('it does not verify invalid messages', async () => {
        const { verified, body } = await processMIME(
            {
                publicKeys: await getKeys(key)
            },
            invalidMultipartSignedMessage
        );
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(body).to.equal('message with missing signature');
    });
    
    it('it can parse messages with special characters in the boundary', async () => {
        const { verified, body } = await processMIME(
            {
                publicKeys: await getKeys(key)
            },
            multiPartMessageWithSpecialCharacter
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(body).to.equal('hello');
    });
    
})


