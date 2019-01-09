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
        const result = await openpgp.decrypt(options);
        const { data, filename, verified, signatures } = await handleVerificationResult(
            result,
            publicKeys,
            options.date
        );

        return {
            data,
            filename,
            verified,
            signatures
        };
    } catch (err) {
        if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
            return Promise.reject(new Error('Incorrect message password')); // Bad password, reject without Error object
        }
        return Promise.reject(err);
    }
}

// Backwards-compatible decrypt message function
// 'message' option must be a string!
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

    const { data } = await decryptMessage(oldOptions);
    const randomKey = binaryStringToArray(decodeUtf8Base64(data));

    if (randomKey.length === 0) {
        return Promise.reject(new Error('Random key is empty'));
    }

    oldEncMessage = binaryStringToArray(decodeUtf8Base64(oldEncMessage));

    const params = { signature: 0 };

    // cutoff time for enabling multilanguage support
    if (+options.messageDate > 1399086120000) {
        params.data = decodeUtf8Base64(
            arrayToBinaryString(openpgp.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true))
        );
    } else {
        params.data = arrayToBinaryString(openpgp.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true));
    }

    return params;
}

/**
 * Decrypts the mime message and parses the body and attachments in the right structure.
 * @param options
 * @return {Promise<{getBody: (function(): Promise<{body, mimetype}>), getAttachments: (function(): Promise<any>), getEncryptedSubject: (function(): Promise<any>), verify: (function(): Promise<any>), stop: stop}>}
 */
export async function decryptMIMEMessage(options) {
    const { data: rawData, verified: embeddedVerified } = await decryptMessageLegacy(options);

    const { body, mimetype, verified: pgpVerified, attachments, encryptedSubject } = await processMIME(
        options,
        rawData
    );

    const verified = embeddedVerified === VERIFICATION_STATUS.NOT_SIGNED ? pgpVerified : embeddedVerified;

    return {
        getBody: () => Promise.resolve(body ? { body, mimetype } : undefined),
        getAttachments: () => Promise.resolve(attachments),
        getEncryptedSubject: () => Promise.resolve(encryptedSubject),
        verify: () => Promise.resolve(verified),
        stop() {}
    };
}
