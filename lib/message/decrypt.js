import { isStream, readToEnd } from '@openpgp/web-stream-tools';
import { decrypt, readSignature } from '../openpgp';
import { decodeUtf8Base64, binaryStringToArray, arrayToBinaryString } from '../utils';
import { serverTime } from '../serverTime';
import { getMessage, handleVerificationResult } from './utils';
import processMIME from './processMIME';
import { getEncMessageFromEmailPM, getEncRandomKeyFromEmailPM } from './compat';
import { VERIFICATION_STATUS } from '../constants';
import { AES256 as AES_CFB } from '../crypto/cfb';

export async function decryptMessage({ date = serverTime(), encryptedSignature, ...options }) {
    const sanitizedOptions = { ...options, date };

    try {
        // If encryptedSignature exists, decrypt and use it
        if (encryptedSignature) {
            const { data: decryptedSignature } = await decrypt({
                ...sanitizedOptions,
                message: encryptedSignature,
                format: 'binary'
            });
            sanitizedOptions.signature = await readSignature({ binarySignature: await readToEnd(decryptedSignature) });
        }

        const decryptionResult = await decrypt(sanitizedOptions);
        const verificationResult = handleVerificationResult(decryptionResult);

        let verified = verificationResult.then((result) => result.verified);
        let verifiedSignatures = verificationResult.then((result) => result.signatures);
        let errors = verificationResult.then((result) => result.errors);

        if (!isStream(decryptionResult.data)) {
            verified = await verified;
            verifiedSignatures = await verifiedSignatures;
            errors = await errors;
        }

        return {
            data: decryptionResult.data,
            filename: decryptionResult.filename,
            verified,
            signatures: verifiedSignatures,
            errors
        };
    } catch (err) {
        return Promise.reject(err);
    }
}

// Backwards-compatible decrypt message function
// `options.message` must be a string, to properly handle legacy messages (and avoid misusing this function)
export async function decryptMessageLegacy({ messageDate, ...options }) {
    const sanitizedOptions = { ...options };

    if (messageDate === undefined || !(messageDate instanceof Date)) {
        throw new Error('Missing message time');
    }

    let oldEncMessage = getEncMessageFromEmailPM(sanitizedOptions.message);
    const oldEncRandomKey = getEncRandomKeyFromEmailPM(sanitizedOptions.message);

    // OpenPGP
    if (oldEncMessage === '' || oldEncRandomKey === '') {
        // Convert message string to object
        sanitizedOptions.message = await getMessage(sanitizedOptions.message);
        return decryptMessage(sanitizedOptions);
    }

    // Old message encryption format
    const oldOptions = {
        decryptionKeys: sanitizedOptions.decryptionKeys,
        message: await getMessage(oldEncRandomKey)
    };

    const { data, errors } = await decryptMessage(oldOptions);
    const randomKey = binaryStringToArray(decodeUtf8Base64(data));

    if (randomKey.length === 0) {
        return Promise.reject(new Error('Random key is empty'));
    }

    oldEncMessage = binaryStringToArray(decodeUtf8Base64(oldEncMessage));

    const params = { verified: VERIFICATION_STATUS.NOT_SIGNED, signatures: [], errors };

    // OpenPGP CFB mode with resync (https://tools.ietf.org/html/rfc4880#section-13.9)
    const result = await AES_CFB.decrypt(
        oldEncMessage.subarray(AES_CFB.blockSize + 2),
        randomKey,
        oldEncMessage.subarray(2, AES_CFB.blockSize + 2)
    );

    // cutoff time for enabling multilanguage support
    if (+messageDate > 1399086120000) {
        params.data = decodeUtf8Base64(arrayToBinaryString(result));
    } else {
        params.data = arrayToBinaryString(result);
    }

    return params;
}

/**
 * Decrypts the mime message and parses the body and attachments in the right structure.
 * @param options
 * @return {Promise<{getBody: (function(): Promise<{body, mimetype}>), getAttachments: (function(): Promise<any>), getEncryptedSubject: (function(): Promise<any>), verify: (function(): Promise<any>), errors: (function(): Promise<any>), stop: stop}>}
 */
export async function decryptMIMEMessage(options) {
    const { data: rawData, verified, signatures, errors } = await decryptMessageLegacy(options);

    const {
        body,
        mimetype,
        verified: pgpMimeVerified,
        attachments,
        encryptedSubject,
        signatures: pgpMimeSignatures
    } = await processMIME({ ...options, data: rawData });

    const combinedVerified = verified === VERIFICATION_STATUS.NOT_SIGNED ? pgpMimeVerified : verified;

    return {
        getBody: () => Promise.resolve(body ? { body, mimetype } : undefined),
        getAttachments: () => Promise.resolve(attachments),
        getEncryptedSubject: () => Promise.resolve(encryptedSubject),
        verify: () => Promise.resolve(combinedVerified),
        errors: () => Promise.resolve(errors),
        stop() {},
        signatures: [...signatures, ...pgpMimeSignatures]
    };
}
