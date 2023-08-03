import { expect } from 'chai';

import { readKey, processMIME } from '../../lib';
import { utf8ArrayToString } from '../../lib/utils';
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
    key,
    multipartMessageWithUnnamedAttachments,
    multipartMessageWithEncryptedSubjectUTF8,
    messageWithEmptyBody,
    messageWithEmptySignature
} from './processMIME.data';

describe('processMIME', () => {
    it('it correctly decodes UTF-8 body with 8bit transfer encoding', async () => {
        const { body } = await processMIME({
            data: `From: Some One <someone@example.com>
To: "Someone Else" <someone-else@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed;
    boundary="------------cJMvmFk1NneB7MT4jwYHY7ap"

This is a multi-part message in MIME format.
--------------cJMvmFk1NneB7MT4jwYHY7ap
Content-Type: text/plain; charset=UTF-8;
Content-Transfer-Encoding: 8bit

Import HTML cöntäct//Subjεέςτ//

--------------cJMvmFk1NneB7MT4jwYHY7ap--`,
            verificationKeys: []
        });
        expect(body).to.equal('Import HTML cöntäct//Subjεέςτ//\n');
    });

    it('it can process multipart/signed mime messages and verify the signature', async () => {
        const { body, verified, signatures, attachments, encryptedSubject } = await processMIME(
            {
                data: multipartSignedMessage,
                verificationKeys: await readKey({ armoredKey: key })
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
        const { body, verified, signatures, attachments } = await processMIME(
            {
                data: extraMultipartSignedMessage,
                verificationKeys: await readKey({ armoredKey: key })
            }
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(body).to.equal('hello');
        expect(signatures.length).to.equal(1);
        expect(attachments.length).to.equal(0);
    });

    it('it does not verify invalid messages', async () => {
        const { verified, body, signatures } = await processMIME(
            {
                data: invalidMultipartSignedMessage,
                verificationKeys: await readKey({ armoredKey: key })
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
                verificationKeys: await readKey({ armoredKey: key })
            }
        );
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
        expect(signatures.length).to.equal(1);
        expect(body).to.equal('hello');
    });

    it('it can parse message with empty body', async () => {
        const { body } = await processMIME({
            data: messageWithEmptyBody
        });
        expect(body).to.equal('');
    });

    it('it can parse message with empty signature', async () => {
        const { body, signatures, verified, attachments } = await processMIME({
            data: messageWithEmptySignature
        });
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures).to.have.length(0);
        expect(body).to.equal('<div>Hello</div>\n');
        expect(attachments).to.have.length(1); // signature part that failed to parse
        expect(attachments[0].content).to.have.length(0);
    });

    it('it can parse message with text attachment', async () => {
        const { verified, body, signatures, attachments } = await processMIME({
            data: multipartMessageWithAttachment,
            verificationKeys: await readKey({ armoredKey: key })
        });
        expect(verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED);
        expect(signatures.length).to.equal(0);
        expect(body).to.equal('this is the body text\n');
        expect(attachments.length).to.equal(1);
        const [attachment] = attachments;
        expect(attachment.fileName).to.equal('test.txt');
        expect(attachment.contentType).to.equal('text/plain');
        expect(attachment.contentDisposition).to.equal('attachment');
        expect(attachment.contentId.indexOf('pmcrypto')).to.not.equal(-1);
        expect(attachment.content).to.be.instanceOf(Uint8Array);
        expect(utf8ArrayToString(attachment.content)).to.equal('this is the attachment text\n');
    });

    it('it can parse message with encrypted subject', async () => {
        const { verified, body, signatures, encryptedSubject } = await processMIME({
            data: multipartMessageWithEncryptedSubject,
            verificationKeys: await readKey({ armoredKey: key })
        });
        expect(verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID);
        expect(signatures.length).to.equal(1);
        expect(encryptedSubject).to.equal('Encrypted subject');
        expect(body).to.equal('hello');
    });

    it('it generates different filenames for multiple attachments with empty names', async () => {
        const { attachments } = await processMIME({
            data: multipartMessageWithUnnamedAttachments
        });
        expect(attachments).to.have.length(2);
        expect(attachments[0].fileName).to.equal('attachment.txt');
        expect(attachments[1].fileName).to.equal('attachment.txt (1)');
        expect(attachments[0].contentId).to.not.equal(attachments[1].contentId);
    });

    it('it can parse message with encrypted subject containing non-ASCII chars', async () => {
        const { body, encryptedSubject } = await processMIME({
            data: multipartMessageWithEncryptedSubjectUTF8,
            verificationKeys: []
        });
        expect(encryptedSubject).to.equal('subject with emojis 😃😇');
        expect(body).to.equal('test utf8 in encrypted subject\n');
    });
});
