import { expect } from 'chai';
// @ts-ignore missing web-stream-tools types
import { WritableStream, ReadableStream, readToEnd, WebStream } from '@openpgp/web-stream-tools';
import { readSignature } from '../../lib/openpgp';
import { verifyMessage, signMessage, getSignature, generateKey } from '../../lib';
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

        const signature = await signMessage({
            binaryData: stringToUtf8Array('message'),
            signingKeys: [privateKey],
            detached: true
        });

        const verificationResult = await verifyMessage({
            binaryData: stringToUtf8Array('message'),
            signature: await getSignature(signature),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('signMessage/verifyMessage - it verifies a streamed message it has signed', async () => {
        const inputStream: WebStream<string> = new ReadableStream({
            pull: (controller: WritableStream) => { for (let i = 0; i < 10000; i++ ) { controller.enqueue('string'); } controller.close() }
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
            signature: await getSignature(armoredSignature),
            verificationKeys: [publicKey]
        });

        expect(verificationResult.data).to.equal(inputData);
        expect(verificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });
})
