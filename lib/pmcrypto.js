import { setInstance, setConfig } from './openpgp';
import {
    encodeUtf8,
    decodeUtf8,
    decodeUtf8Base64,
    encodeUtf8Base64,
    encodeBase64,
    decodeBase64,
    setInstance as setBase64Instance
} from './utils';

export const init = ({ openpgp, atob, btoa }) => {
    if (!btoa || !atob || !openpgp) {
        throw new Error('OpenPGP, atob and btoa required');
    }
    if (!openpgp.config.versionstring.indexOf('OpenPGP.js v4.2') === -1) {
        throw new Error('pmcrypto relies on openpgp version ^4.2.0');
    }
    setInstance(openpgp);
    setConfig(openpgp);
    setBase64Instance(atob, btoa);
};

export {
    updateServerTime,
    getMaxConcurrency,
    decodeUtf8Base64,
    encodeUtf8Base64,
    encodeUtf8,
    decodeUtf8,
    encodeBase64,
    decodeBase64,
    concatArrays,
    getHashedPassword,
    arrayToBinaryString,
    binaryStringToArray,
    stripArmor,
    createWorker
} from './utils';

export { checkMailboxPassword } from './mail';

export {
    generateKey,
    getKeys,
    reformatKey,
    generateSessionKey,
    isExpiredKey,
    compressKey,
    getFingerprint,
    getMatchingKey,
    cloneKey
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
    getCleartextMessage,
    createMessage,
    armorBytes
} from './message/utils';

export { default as MailParser } from './message/mailparser';

export { default as keyInfo } from './key/info';

export { keyCheck } from './key/check';

export const config = { debug: true };

/* eslint-disable camelcase */
export const encode_utf8 = encodeUtf8;
export const decode_utf8 = decodeUtf8;
export const encode_base64 = encodeBase64;
export const decode_base64 = decodeBase64;
export const encode_utf8_base64 = encodeUtf8Base64;
export const decode_utf8_base64 = decodeUtf8Base64;
