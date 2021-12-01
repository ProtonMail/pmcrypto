// Most of these util functions are copied as-is from https://github.com/openpgpjs/openpgpjs/blob/v5.0.0/src/util.js

import { unarmor } from 'openpgp';
import { concatUint8Array, readToEnd, transform } from '@openpgp/web-stream-tools';

const localAtob = typeof atob === 'undefined' ? (str) => Buffer.from(str, 'base64').toString('binary') : atob;
const localBtoa = typeof btoa === 'undefined' ? (str) => Buffer.from(str, 'binary').toString('base64') : btoa;

const ifDefined = (cb) => (input) => {
    if (input !== undefined) {
        return cb(input);
    }
};

export const encodeUtf8 = ifDefined((input) => unescape(encodeURIComponent(input)));
export const decodeUtf8 = ifDefined((input) => decodeURIComponent(escape(input)));
export const encodeBase64 = ifDefined((input) => localBtoa(input).trim());
export const decodeBase64 = ifDefined((input) => localAtob(input.trim()));
export const encodeUtf8Base64 = ifDefined((input) => encodeBase64(encodeUtf8(input)));
export const decodeUtf8Base64 = ifDefined((input) => decodeUtf8(decodeBase64(input)));

export const concatArrays = (args) => concatUint8Array(args);

const isString = (data) => {
    return typeof data === 'string' || String.prototype.isPrototypeOf.call(data);
};

/**
 * Convert a hex string to an array of 8-bit integers
 * @param {String} hex  A hex string to convert
 * @returns {Uint8Array} An array of 8-bit integers
 */
export const hexToUint8Array = (hex) => {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < hex.length >> 1; k++) {
        result[k] = parseInt(hex.substr(k << 1, 2), 16);
    }
    return result;
};

/**
 * Convert a string to an array of 8-bit integers
 * @param {String} str String to convert
 * @returns {Uint8Array} An array of 8-bit integers
 */
export const binaryStringToArray = (str) => {
    if (!isString(str)) {
        throw new Error('binaryStringToArray: Data must be in the form of a string');
    }

    const result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        result[i] = str.charCodeAt(i);
    }
    return result;
};

export const arrayToBinaryString = (bytes) => {
    bytes = new Uint8Array(bytes);
    const result = [];
    const bs = 1 << 14;
    const j = bytes.length;

    for (let i = 0; i < j; i += bs) {
        result.push(String.fromCharCode.apply(String, bytes.subarray(i, i + bs < j ? i + bs : j)));
    }
    return result.join('');
};

/**
 * Convert an array of 8-bit integers to a hex string
 * @param {Uint8Array} bytes Array of 8-bit integers to convert
 * @returns {String} Hexadecimal representation of the array
 */
export const arrayToHexString = (bytes) => {
    const r = [];
    const e = bytes.length;
    let c = 0;
    let h;
    while (c < e) {
        h = bytes[c++].toString(16);
        while (h.length < 2) {
            h = '0' + h;
        }
        r.push('' + h);
    }
    return r.join('');
};

/**
 * Dearmor a pgp encoded message.
 * @param {String} input
 * @return {Promise<Uint8Array>}
 */
export const stripArmor = async (input) => {
    const { data } = await unarmor(input);
    const bytes = await readToEnd(data);
    return bytes;
};

/**
 * Convert a native javascript string to a Uint8Array of utf8 bytes
 * @param {String|ReadableStream} str - The string to convert
 * @returns {Uint8Array|ReadableStream} A valid squence of utf8 bytes.
 */
export function stringToUtf8Array(str) {
    const encoder = new TextEncoder();
    return transform(str, value => encoder.encode(value));
}

/**
 * Convert a Uint8Array of utf8 bytes to a native javascript string
 * @param {Uint8Array|ReadableStream} utf8 - A valid squence of utf8 bytes
 * @returns {String|ReadableStream} A native javascript string.
 */
export function utf8ArrayToString(utf8) {
    const decoder = new TextDecoder();
    function process(value, lastChunk = false) {
        return decoder.decode(value, { stream: !lastChunk });
    }
    return transform(utf8, process, () => process(new Uint8Array(), true));
}
