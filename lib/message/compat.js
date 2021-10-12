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
export function getEncMessageFromEmailPM(EmailPM) {
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
export function getEncRandomKeyFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        const begin = EmailPM.search(protonmailCryptoHeaderRandomKey) + protonmailCryptoHeaderRandomKey.length;
        const end = EmailPM.search(protonmailCryptoTailRandomKey);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}
