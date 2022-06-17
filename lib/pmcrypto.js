import { setConfig } from './openpgp';

export function init() {
    if (arguments.length) {
        throw new Error('Loading OpenPGP separately is no longer required');
    }
    setConfig();
}

export { updateServerTime, serverTime } from './serverTime';

export { SHA256, SHA512, unsafeMD5, unsafeSHA1 } from './crypto/hash';

export {
    generateKey,
    getKeys,
    getKey,
    reformatKey,
    generateSessionKey,
    generateSessionKeyForAlgorithm,
    isExpiredKey,
    isRevokedKey,
    canKeyEncrypt,
    getFingerprint,
    getMatchingKey
} from './key/utils';

export { decryptPrivateKey, decryptSessionKey } from './key/decrypt';
export { encryptPrivateKey, encryptSessionKey } from './key/encrypt';
export { default as decryptMessage } from './message/decrypt';
export { default as decryptMessageLegacy } from './message/decryptLegacy';
export { default as encryptMessage } from './message/encrypt';
export { default as signMessage } from './message/sign';
export { verifyMessage, verifyCleartextMessage } from './message/verify';

export {
    getMessage,
    getSignature,
    splitMessage,
    getCleartextMessage,
    armorBytes,
    stripArmor
} from './message/utils';

export { default as processMIME } from './message/processMIME';

export { getSHA256Fingerprints } from './key/info';

export { checkKeyStrength } from './key/check';

export * from './constants';
