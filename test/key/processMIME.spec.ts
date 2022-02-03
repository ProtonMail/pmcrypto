import { expect } from 'chai';

import { getKeys, processMIME, utf8ArrayToString } from '../../lib/pmcrypto';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { Signature } from '../../lib/openpgp';
import {
    invalidMultipartSignedMessage,
    multipartSignedMessage,
    multipartSignedMessageBody,
    extraMultipartSignedMessage,
    multiPartMessageWithSpecialCharacter,
    multipartMessageWithAttachment,
    multipartMessageWithEncryptedSubject,
    key
} from './processMIME.data';

describe('processMIME', () => {
    it('it can process multipart/signed mime messages and verify the signature', async () => {
        const { body, verified, signatures, attachments, encryptedSubject } = await processMIME(
            {
                data: multipartSignedMessage,
                verificationKeys: await getKeys(key)
            }
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(1);
        expect(signatures[0]).to.be.instanceOf(Signature);
        expect(body).to.equal(multipartSignedMessageBody);
        expect(attachments.length).to.equal(0);
        expect(encryptedSubject).to.equal('');
    });

    it('it can process multipart/signed mime messages and verify the signature with extra parts at the end', async () => {
        const { body, verified,signatures } = await processMIME(
            {
                data: extraMultipartSignedMessage,
                verificationKeys: await getKeys(key)
            }
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(body).to.equal('hello');
        expect(signatures.length).to.equal(1);
    });

    it('it does not verify invalid messages', async () => {
        const { verified, body, signatures } = await processMIME(
            {
                data: invalidMultipartSignedMessage,
                verificationKeys: await getKeys(key)
            }
        );
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures.length).to.equal(0);
        expect(body).to.equal('message with missing signature');
    });

    it('it can parse messages with special characters in the boundary', async () => {
        const { verified, body, signatures } = await processMIME(
            {
                data: multiPartMessageWithSpecialCharacter,
                verificationKeys: await getKeys(key)
            }
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(1);
        expect(body).to.equal('hello');
    });

    it('it can parse message with text attachment', async () => {
        const { verified, body, signatures, attachments } = await processMIME({
            data: multipartMessageWithAttachment,
            verificationKeys: await getKeys(key)
        });
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures.length).to.equal(0);
        expect(body).to.equal('this is the body text\n');
        expect(attachments.length).to.equal(1);
        const [attachment] = attachments;
        expect(attachment.fileName).to.equal('test.txt');
        expect(attachment.generatedFileName).to.equal('test.txt');
        expect(attachment.contentType).to.equal('text/plain');
        expect(attachment.contentDisposition).to.equal('attachment');
        expect(attachment.checksum).to.equal('94ee2b41f2016f2ec79a7b3a2faf920e');
        expect(attachment.content).to.be.instanceOf(Uint8Array);
        expect(utf8ArrayToString(attachment.content)).to.equal('this is the attachment text\r\n')
    });

    it('it can parse message with encrypted subject', async () => {
        const { verified, body, signatures, encryptedSubject } = await processMIME({
            data: multipartMessageWithEncryptedSubject,
            verificationKeys: await getKeys(key)
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(signatures.length).to.equal(1);
        expect(encryptedSubject).to.equal('Encrypted subject');
        expect(body).to.equal('hello');
    });
});
