// Deprecated, backwards compatibility
const protonmailCryptoHeaderMessage = '---BEGIN ENCRYPTED MESSAGE---';
const protonmailCryptoTailMessage = '---END ENCRYPTED MESSAGE---';
const protonmailCryptoHeaderRandomKey = '---BEGIN ENCRYPTED RANDOM KEY---';
const protonmailCryptoTailRandomKey = '---END ENCRYPTED RANDOM KEY---';

export function getEncMessageFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        const begin = EmailPM.search(protonmailCryptoHeaderMessage) + protonmailCryptoHeaderMessage.length;
        const end = EmailPM.search(protonmailCryptoTailMessage);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}

export function getEncRandomKeyFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        const begin = EmailPM.search(protonmailCryptoHeaderRandomKey) + protonmailCryptoHeaderRandomKey.length;
        const end = EmailPM.search(protonmailCryptoTailRandomKey);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}
