/* eslint-disable camelcase */
import {
    updateServerTime, getMaxConcurrency,
    decodeUtf8Base64, encodeUtf8Base64,
    encodeUtf8, decodeUtf8,
    encodeBase64, decodeBase64,
    getHashedPassword, arrayToBinaryString,
    binaryStringToArray, stripArmor
} from './utils';
import {
    generateKey, getKeys,
    reformatKey, generateSessionKey,
    isExpiredKey, compressKey,
    getFingerprint, getMatchingKey,
    cloneKey
} from './key/utils';
import { decryptPrivateKey, decryptSessionKey } from './key/decrypt';
import { encryptPrivateKey, encryptSessionKey } from './key/encrypt';
import { decryptMessage, decryptMessageLegacy, decryptMIMEMessage } from './message/decrypt';
import encryptMessage from './message/encrypt';
import { getMessage, getSignature, signMessage, splitMessage, verifyMessage, getCleartextMessage, createMessage } from './message/utils';
import keyInfo from './key/info';
import keyCheck from './key/check';
import openpgpjs from './openpgp';

const config = { debug: true };
const concatArrays = openpgpjs.util.concatUint8Array;
const encode_utf8 = encodeUtf8;
const decode_utf8 = decodeUtf8;
const encode_base64 = encodeBase64;
const decode_base64 = decodeBase64;
const encode_utf8_base64 = encodeUtf8Base64;
const decode_utf8_base64 = decodeUtf8Base64;

export {
    config,

    cloneKey,
    generateKey,
    getKeys,
    updateServerTime,
    getMaxConcurrency,

    reformatKey,
    generateSessionKey,
    isExpiredKey,

    encryptSessionKey,
    decryptSessionKey,
    encryptPrivateKey,
    decryptPrivateKey,

    compressKey,

    getMessage,
    getSignature,
    signMessage,
    splitMessage,
    verifyMessage,
    getCleartextMessage,
    createMessage,

    encryptMessage,
    decryptMessage,
    decryptMIMEMessage,
    decryptMessageLegacy,

    encodeUtf8,
    encode_utf8,
    decodeUtf8,
    decode_utf8,
    encodeBase64,
    encode_base64,
    decodeBase64,
    decode_base64,
    encodeUtf8Base64,
    encode_utf8_base64,
    decodeUtf8Base64,
    decode_utf8_base64,
    getHashedPassword,
    arrayToBinaryString,
    binaryStringToArray,
    concatArrays,
    stripArmor,

    keyInfo,
    keyCheck,
    getFingerprint,
    getMatchingKey
};
