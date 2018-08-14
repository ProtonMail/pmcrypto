import { decodeUtf8Base64, binaryStringToArray, arrayToBinaryString, serverTime } from '../utils';
import { getMessage, handleVerificationResult } from './utils';
import processMIME from './processMIME';
import { getEncMessageFromEmailPM, getEncRandomKeyFromEmailPM } from './compat';
import { VERIFICATION_STATUS } from '../constants';
import openpgpjs from '../openpgp';

export function decryptMessage(options) {
    const { publicKeys = [] } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return Promise.resolve()
        .then(() => {

            try {
                return openpgpjs.decrypt(options)
                    .then((result) => handleVerificationResult(result, publicKeys, options.date))
                    .then(({
                        data, filename, verified, signatures
                    }) => {
                        return {
                            data, filename, verified, signatures
                        };
                    })
                    .catch((err) => {
                        console.error(err);
                        return Promise.reject(err);
                    });
            } catch (err) {
                if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
                    return Promise.reject(new Error('Incorrect message password')); // Bad password, reject without Error object
                }
                return Promise.reject(err);
            }
        });
}

// Backwards-compatible decrypt message function
// 'message' option must be a string!
export function decryptMessageLegacy(options) {

    return Promise.resolve()
        .then(() => {

            if (options.date === undefined || !(options.date instanceof Date)) {
                throw new Error('Missing message time');
            }

            let oldEncMessage = getEncMessageFromEmailPM(options.message);
            const oldEncRandomKey = getEncRandomKeyFromEmailPM(options.message);

            // OpenPGP
            if (oldEncMessage === '' || oldEncRandomKey === '') {
                // Convert message string to object
                options.message = getMessage(options.message);
                return decryptMessage(options);
            }

            // Old message encryption format
            const oldOptions = {
                privateKeys: options.privateKeys,
                message: getMessage(oldEncRandomKey)
            };

            return decryptMessage(oldOptions)
                .then(({ data }) => decodeUtf8Base64(data))
                .then(binaryStringToArray)
                .then((randomKey) => {

                    if (randomKey.length === 0) {
                        return Promise.reject(new Error('Random key is empty'));
                    }

                    oldEncMessage = binaryStringToArray(decodeUtf8Base64(oldEncMessage));

                    let data;
                    try {
                        // cutoff time for enabling multilanguage support
                        if (+options.date > 1399086120000) {
                            data = decodeUtf8Base64(arrayToBinaryString(openpgpjs.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true)));
                        } else {
                            data = arrayToBinaryString(openpgpjs.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true));
                        }
                    } catch (err) {
                        return Promise.reject(err);
                    }
                    return { data, signature: 0 };
                });
        });
}

/**
 * Decrypts the mime message and parses the body and attachments in the right structure.
 * @param options
 * @return {Promise<{getBody: (function(): Promise<{body, mimetype}>), getAttachments: (function(): Promise<any>), getEncryptedSubject: (function(): Promise<any>), verify: (function(): Promise<any>), stop: stop}>}
 */
export async function decryptMIMEMessage(options) {
    const { data: rawData, verified: embeddedVerified } = await decryptMessageLegacy(options);

    const {
        body,
        mimetype,
        verified: pgpVerified,
        attachments,
        encryptedSubject
    } = await processMIME(options, rawData);

    const verified = embeddedVerified === VERIFICATION_STATUS.NOT_SIGNED ? pgpVerified : embeddedVerified;

    return {
        getBody: () => Promise.resolve(body ? { body, mimetype } : undefined),
        getAttachments: () => Promise.resolve(attachments),
        getEncryptedSubject: () => Promise.resolve(encryptedSubject),
        verify: () => Promise.resolve(verified),
        stop: () => {}
    };
}
