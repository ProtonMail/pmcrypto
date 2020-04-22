import { util, crypto, armor, stream } from 'openpgp';

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

export const binaryStringToArray = (args) => util.str_to_Uint8Array(args);
export const arrayToBinaryString = (args) => util.Uint8Array_to_str(args); // eslint-disable-line new-cap
export const arrayToHexString = (args) => util.Uint8Array_to_hex(args); // eslint-disable-line new-cap
export const concatArrays = (args) => util.concatUint8Array(args);

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
    const { data } = await armor.decode(input);
    const bytes = await stream.readToEnd(data);
    return bytes;
};
