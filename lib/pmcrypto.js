import { setConfig } from './openpgp';

export function init() {
    if (arguments.length) {
        throw new Error('Loading OpenPGP separately is no longer required');
    }
    setConfig();
}

export { updateServerTime, serverTime } from './serverTime';

export { SHA256, SHA512, unsafeMD5, unsafeSHA1 } from './crypto/hash';

export { checkMailboxPassword } from './mail';

export {
    generateKey,
    getKeys,
    getKey,
    reformatKey,
    generateSessionKey,
    generateSessionKeyFromKeyPreferences,
    isExpiredKey,
    isRevokedKey,
    canKeyEncrypt,
    getFingerprint,
    getMatchingKey
} from './key/utils';

export { decryptPrivateKey, decryptSessionKey } from './key/decrypt';
export { encryptPrivateKey, encryptSessionKey } from './key/encrypt';
export { decryptMessage, decryptMessageLegacy, decryptMIMEMessage } from './message/decrypt';
export { default as encryptMessage } from './message/encrypt';

export {
    getMessage,
    getSignature,
    signMessage,
    splitMessage,
    verifyMessage,
    verifyCleartextMessage,
    getCleartextMessage,
    armorBytes,
    stripArmor
} from './message/utils';

export { default as processMIME } from './message/processMIME';

export { default as keyInfo, getSHA256Fingerprints } from './key/info';

export { checkKeyStrength, keyCheck } from './key/check';

export * from './constants';
