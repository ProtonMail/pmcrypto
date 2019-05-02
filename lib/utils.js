import { openpgp } from './openpgp';

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

export const binaryStringToArray = (args) => openpgp.util.str_to_Uint8Array(args);
export const arrayToBinaryString = (args) => openpgp.util.Uint8Array_to_str(args); // eslint-disable-line new-cap
export const arrayToHexString = (args) => openpgp.util.Uint8Array_to_hex(args); // eslint-disable-line new-cap
export const concatArrays = (args) => openpgp.util.concatUint8Array(args);

export const SHA512 = (args) => openpgp.crypto.hash.sha512(args);
/**
 * MD5 is an unsafe hash function. It should normally not be used.
 * It's exposed because it's required for old auth versions.
 * @see openpgp.crypto.hash.md5
 */
export const unsafeMD5 = (args) => openpgp.crypto.hash.md5(args);

/**
 * Dearmor a pgp encoded message.
 * @param {String} input
 * @return {Promise<Uint8Array>}
 */
export const stripArmor = async (input) => {
    const { data } = await openpgp.armor.decode(input);
    const bytes = await openpgp.stream.readToEnd(data);
    return bytes;
};

export const getMaxConcurrency = () => {
    const { workers = [null] } = openpgp.getWorker() || {};
    return workers.length;
};

export const createWorker = ({ path = '', n }) => {
    if (!path) {
        throw new Error('Path to worker required');
    }
    const { hardwareConcurrency = 1 } = window.navigator || {};
    return openpgp.initWorker({ path, n: n || hardwareConcurrency });
};
