import test from 'ava';
import '../helper';

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

test('it can process multipart/signed mime messages and verify the signature', async (t) => {
    const { body, verified } = await processMIME(
        {
            publicKeys: await getKeys(key)
        },
        multipartSignedMessage
    );
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    t.is(body, multipartSignedMessageBody);
});

test('it can process multipart/signed mime messages and verify the signature with extra parts at the end', async (t) => {
    const { body, verified } = await processMIME(
        {
            publicKeys: await getKeys(key)
        },
        extraMultipartSignedMessage
    );
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    t.is(body, 'hello');
});

test('it does not verify invalid messages', async (t) => {
    const { verified, body } = await processMIME(
        {
            publicKeys: await getKeys(key)
        },
        invalidMultipartSignedMessage
    );
    t.is(verified, VERIFICATION_STATUS.NOT_SIGNED);
    t.is(body, 'message with missing signature');
});

test('it can parse messages with special characters in the boundary', async (t) => {
    const { verified, body } = await processMIME(
        {
            publicKeys: await getKeys(key)
        },
        multiPartMessageWithSpecialCharacter
    );
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    t.is(body, 'hello');
});
