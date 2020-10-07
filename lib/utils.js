import { crypto, unarmor, stream } from 'openpgp';

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

const isString = (data) => {
    return typeof data === 'string' || String.prototype.isPrototypeOf(data);
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
    return stream.transform(str, (str) => {
        if (!isString(str)) {
            throw new Error('strToUint8Array: Data must be in the form of a string');
        }

        const result = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) {
            result[i] = str.charCodeAt(i);
        }
        return result;
    });
};

/**
 * Convert an array of 8-bit integers to a string
 * @param {Uint8Array} bytes An array of 8-bit integers to convert
 * @returns {String} String representation of the array
 */
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
 * Remove trailing spaces and tabs from each line
 */
export const removeTrailingSpaces = (text) => {
    return text
        .split('\n')
        .map((line) => {
            let i = line.length - 1;
            for (; i >= 0 && (line[i] === ' ' || line[i] === '\t'); i--);
            return line.substr(0, i + 1);
        })
        .join('\n');
};

export const SHA256 = (args) => crypto.hash.sha256(args);
export const SHA512 = (args) => crypto.hash.sha512(args);
/**
 * MD5 is an unsafe hash function. It should normally not be used.
 * It's exposed because it's required for old auth versions.
 * @see openpgp.crypto.hash.md5
 */
export const unsafeMD5 = (args) => crypto.hash.md5(args);
/**
 * SHA1 is an unsafe hash function. It should not be used for cryptographic purposes.
 * DO NOT USE in contexts where collision resistance is important
 * @see openpgp.crypto.hash.sha1
 */
export const unsafeSHA1 = (args) => crypto.hash.sha1(args);

/**
 * Dearmor a pgp encoded message.
 * @param {String} input
 * @return {Promise<Uint8Array>}
 */
export const stripArmor = async (input) => {
    const { data } = await unarmor(input);
    const bytes = await stream.readToEnd(data);
    return bytes;
};

export const isStream = (args) => stream.isStream(args);
export const concatArrays = (args) => stream.concatUint8Array(args);
