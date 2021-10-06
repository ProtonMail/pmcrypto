import { openpgp } from '../openpgp';
import { decodeUtf8Base64, binaryStringToArray, arrayToBinaryString } from '../utils';
import { serverTime } from '../serverTime';
import { getMessage, handleVerificationResult } from './utils';
import processMIME from './processMIME';
import { getEncMessageFromEmailPM, getEncRandomKeyFromEmailPM } from './compat';
import { VERIFICATION_STATUS } from '../constants';

export async function decryptMessage(options) {
    const { publicKeys = [] } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    try {
        // If encryptedSignature exists, decrypt and use it
        if (options.encryptedSignature) {
            const decryptedSignature = await openpgp.decrypt({
                ...options,
                message: options.encryptedSignature,
                format: 'binary'
            });
            options.signature = await openpgp.signature.read(decryptedSignature.data);
        }

        const result = await openpgp.decrypt(options);
        const verificationResult = handleVerificationResult(result, publicKeys, options.date);

        let verified = verificationResult.then((result) => result.verified);
        let verifiedSignatures = verificationResult.then((result) => result.signatures);
        let errors = verificationResult.then((result) => result.errors);

        if (!openpgp.stream.isStream(result.data)) {
            verified = await verified;
            verifiedSignatures = await verifiedSignatures;
            errors = await errors;
        }

        return {
            data: result.data,
            filename: result.filename,
            verified,
            signatures: verifiedSignatures,
            errors
        };
    } catch (err) {
        if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
            return Promise.reject(new Error('Incorrect message password')); // Bad password, reject without Error object
        }
        return Promise.reject(err);
    }
}

// Backwards-compatible decrypt message function
// `options.message` must be a string, to properly handle legacy messages (and avoid misusing this function)
export async function decryptMessageLegacy(options) {
    if (options.messageDate === undefined || !(options.messageDate instanceof Date)) {
        throw new Error('Missing message time');
    }

    let oldEncMessage = getEncMessageFromEmailPM(options.message);
    const oldEncRandomKey = getEncRandomKeyFromEmailPM(options.message);

    // OpenPGP
    if (oldEncMessage === '' || oldEncRandomKey === '') {
        // Convert message string to object
        options.message = await getMessage(options.message);
        return decryptMessage(options);
    }

    // Old message encryption format
    const oldOptions = {
        privateKeys: options.privateKeys,
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
    const result = await openpgp.crypto.cfb.decrypt(
        'aes256',
        randomKey,
        oldEncMessage.subarray(openpgp.crypto.cipher.aes256.blockSize + 2),
        oldEncMessage.subarray(2, openpgp.crypto.cipher.aes256.blockSize + 2)
    );

    // cutoff time for enabling multilanguage support
    if (+options.messageDate > 1399086120000) {
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
    } = await processMIME(options, rawData);

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
