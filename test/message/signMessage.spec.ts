import { expect } from 'chai';
// @ts-ignore missing web-stream-tools types
import { WritableStream, ReadableStream, readToEnd, WebStream } from '@openpgp/web-stream-tools';
import { verifyMessage, signMessage, generateKey, readSignature } from '../../lib';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { stringToUtf8Array } from '../../lib/utils';

describe('message signing', () => {
    it('signMessage/verifyMessage - it verifies a text message it has signed (format = armored)', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const armoredSignature = await signMessage({
            textData: 'message',
            signingKeys: [privateKey],
            detached: true
        });

        const verificationResult = await verifyMessage({
            textData: 'message',
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a text message it has signed (format = binary)', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const binarySignature = await signMessage({
            textData: 'message',
            signingKeys: [privateKey],
            detached: true,
            format: 'binary'
        });

        const verificationResult = await verifyMessage({
            textData: 'message',
            signature: await readSignature({ binarySignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a binary message it has signed', async () => {
        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const armoredSignature = await signMessage({
            binaryData: stringToUtf8Array('message'),
            signingKeys: [privateKey],
            detached: true
        });

        const verificationResult = await verifyMessage({
            binaryData: stringToUtf8Array('message'),
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it normalises a text message with trailing whitespaces', async () => {
        const textData = 'BEGIN:VCARD\r\nVERSION:4.0\r\nFN;PREF=1:   \r\nITEM1.EMAIL;TYPE=x-email;PREF=1:email@email.it\r\nPRODID;VALUE=TEXT:-//ProtonMail//ProtonMail vCard 1.0.0//EN\r\nUID:proton-web\r\nITEM1.X-PM-ENCRYPT:false\r\nITEM1.X-PM-SIGN:true\r\nITEM1.X-PM-SCHEME:pgp-mime\r\nEND:VCARD';

        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            format: 'object'
        });

        const armoredSignature = await signMessage({
            textData,
            stripTrailingSpaces: true,
            signingKeys: [privateKey],
            detached: true
        });

        await expect(verifyMessage({
            textData, // stripTrailingSpaces: false
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            expectSigned: true
        })).to.be.rejectedWith(/Signed digest did not match/);

        const verificationResult = await verifyMessage({
            textData,
            stripTrailingSpaces: true,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey],
            expectSigned: true
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a streamed message it has signed', async () => {
        const inputStream: WebStream<string> = new ReadableStream({
            pull: (controller: WritableStream) => { for (let i = 0; i < 10000; i++) { controller.enqueue('string'); } controller.close(); }
        });
        const inputData = 'string'.repeat(10000);

        const { privateKey, publicKey } = await generateKey({
            userIDs: [{ name: 'name', email: 'email@test.com' }],
            date: new Date(),
            keyExpirationTime: 10000,
            format: 'object'
        });

        const streamedSignature = await signMessage({
            textData: inputStream,
            signingKeys: [privateKey],
            detached: true
        });

        const armoredSignature = await readToEnd(streamedSignature);

        const verificationResult = await verifyMessage({
            textData: inputData,
            signature: await readSignature({ armoredSignature }),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.data).to.equal(inputData);
        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
});
