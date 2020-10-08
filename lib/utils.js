import { unarmor, stream } from 'openpgp';
import { Sha1 } from 'asmcrypto.js/dist_es8/hash/sha1/sha1';
import { Sha256 } from 'asmcrypto.js/dist_es8/hash/sha256/sha256';
import { Sha512 } from 'asmcrypto.js/dist_es8/hash/sha512/sha512';

const getRandomValues = require('get-random-values');

export const isStream = (args) => stream.isStream(args);
export const concatArrays = (args) => stream.concatUint8Array(args);
export const readToEnd = (args) => stream.readToEnd(args);
export const transform = (args) => stream.transform(args);

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

function asmcryptoHash(Hash) {
    return async function(data) {
        if (isStream(data)) {
            const hashInstance = new Hash();
            return transform(
                data,
                (value) => {
                    hashInstance.process(value);
                },
                () => hashInstance.finish().result
            );
        }
        return Hash.bytes(data);
    };
}

export const SHA256 = (args) => asmcryptoHash(Sha256)(args);
export const SHA512 = (args) => asmcryptoHash(Sha512)(args);
/**
 * SHA1 is an unsafe hash function. It should not be used for cryptographic purposes.
 * DO NOT USE in contexts where collision resistance is important
 */
export const unsafeSHA1 = (args) => asmcryptoHash(Sha1)(args);

/**
 * Create a hash on the specified data using the specified algorithm
 * @param {module:enums.hash} algo Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
 * @param {Uint8Array} data Data to be hashed
 * @returns {Promise<Uint8Array>} hash value
 */
export const digest = (algo, data) => {
    switch (algo) {
        case 2:
            // - SHA-1 [FIPS180]
            return unsafeSHA1(data);
        case 8:
            // - SHA256 [FIPS180]
            return SHA256(data);
        case 10:
            // - SHA512 [FIPS180]
            return SHA512(data);
        default:
            throw new Error('Invalid or not supported hash function');
    }
};

export const cipher = {
    aes128: { blockSize: 16, keySize: 16 },
    aes192: { blockSize: 16, keySize: 12 },
    aes256: { blockSize: 16, keySize: 32 }
};

export const getRandomBytes = (len) => getRandomValues(new Uint8Array(len));
