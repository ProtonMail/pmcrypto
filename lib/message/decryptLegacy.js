import { AES256 as AES_CFB } from '../crypto/cfb';
import { VERIFICATION_STATUS } from '../constants';
import { arrayToBinaryString, binaryStringToArray, decodeUtf8Base64 } from '../utils';
import decryptMessage from './decrypt';
import { readMessage } from '../openpgp';

// Deprecated, backwards compatibility
const protonmailCryptoHeaderMessage = '---BEGIN ENCRYPTED MESSAGE---';
const protonmailCryptoTailMessage = '---END ENCRYPTED MESSAGE---';
const protonmailCryptoHeaderRandomKey = '---BEGIN ENCRYPTED RANDOM KEY---';
const protonmailCryptoTailRandomKey = '---END ENCRYPTED RANDOM KEY---';

/**
 * Extract armored encrypted message from email
 * @param {String|Object} EmailPM
 * @returns {String} armored message, or empty string if not found
 */
function getEncMessageFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        const begin = EmailPM.search(protonmailCryptoHeaderMessage) + protonmailCryptoHeaderMessage.length;
        const end = EmailPM.search(protonmailCryptoTailMessage);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}

/**
 * Extract (legacy, custom) armored encrypted random key from email
 * @param {String|Object} EmailPM
 * @returns {String} armored random key, or empty string if not found
 */
function getEncRandomKeyFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        const begin = EmailPM.search(protonmailCryptoHeaderRandomKey) + protonmailCryptoHeaderRandomKey.length;
        const end = EmailPM.search(protonmailCryptoTailRandomKey);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}

// Backwards-compatible decrypt message function
// Input message must be a string, to properly handle legacy messages (and avoid misusing this function)
export default async function decryptMessageLegacy({ messageDate, armoredMessage, decryptionKeys, ...options }) {
    if (messageDate === undefined || !(messageDate instanceof Date)) {
        throw new Error('Missing message time');
    }

    let oldEncMessage = getEncMessageFromEmailPM(armoredMessage);
    const oldEncRandomKey = getEncRandomKeyFromEmailPM(armoredMessage);

    // Standard OpenPGP message
    if (oldEncMessage === '' || oldEncRandomKey === '') {
        // Convert message string to object
        return decryptMessage({
            message: await readMessage({ armoredMessage }),
            decryptionKeys,
            ...options
        });
    }

    // Legacy message encryption format
    const legacyOptions = {
        decryptionKeys,
        message: await readMessage({ armoredMessage: oldEncRandomKey }),
        config: options.config
    };

    const { data, verificationErrors } = await decryptMessage(legacyOptions);
    const randomKey = binaryStringToArray(decodeUtf8Base64(data));

    if (randomKey.length === 0) {
        throw new Error('Random key is empty');
    }

    oldEncMessage = binaryStringToArray(decodeUtf8Base64(oldEncMessage));

    const params = { verified: VERIFICATION_STATUS.NOT_SIGNED, signatures: [], verificationErrors };

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
