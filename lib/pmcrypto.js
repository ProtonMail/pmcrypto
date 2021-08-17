import { setInstance, setConfig } from './openpgp';
import { encodeUtf8, decodeUtf8, decodeUtf8Base64, encodeUtf8Base64, encodeBase64, decodeBase64 } from './utils';

export const init = (openpgp) => {
    if (!openpgp) {
        throw new Error('OpenPGP required');
    }
    setInstance(openpgp);
    setConfig(openpgp);
};

export { updateServerTime, serverTime } from './serverTime';

export {
    getMaxConcurrency,
    decodeUtf8Base64,
    encodeUtf8Base64,
    encodeUtf8,
    decodeUtf8,
    encodeBase64,
    decodeBase64,
    concatArrays,
    stringToUtf8Array,
    utf8ArrayToString,
    arrayToBinaryString,
    arrayToHexString,
    binaryStringToArray,
    stripArmor,
    SHA256,
    SHA512,
    unsafeMD5,
    unsafeSHA1,
    createWorker
} from './utils';

export { checkMailboxPassword } from './mail';

export {
    generateKey,
    getKeys,
    reformatKey,
    generateSessionKey,
    getPreferredAlgorithm,
    isExpiredKey,
    isRevokedKey,
    canKeyEncrypt,
    compressKey,
    getFingerprint,
    getMatchingKey,
    cloneKey,
    genPublicEphemeralKey,
    genPrivateEphemeralKey
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
    createCleartextMessage,
    createMessage,
    armorBytes
} from './message/utils';

export { parseMail } from './message/processMIME';

export { default as keyInfo, getSHA256Fingerprints } from './key/info';

export { checkKeyStrength, keyCheck } from './key/check';

export * from './constants';

export const config = { debug: true };

/* eslint-disable camelcase */
export const encode_utf8 = encodeUtf8;
export const decode_utf8 = decodeUtf8;
export const encode_base64 = encodeBase64;
export const decode_base64 = decodeBase64;
export const encode_utf8_base64 = encodeUtf8Base64;
export const decode_utf8_base64 = decodeUtf8Base64;
