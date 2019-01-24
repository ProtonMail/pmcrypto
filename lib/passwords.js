import bcrypt from 'bcryptjs';

import { openpgp } from './openpgp';
import { arrayToBinaryString, binaryStringToArray, decodeBase64, encodeBase64, encodeUtf8 } from './utils';
import { getRandomValues } from './crypto';

// Version 2 of bcrypt with 10 rounds.
// https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
const BCRYPT_PREFIX = '$2y$10$';

/**
 * Clean the username, remove underscore, dashes, dots and lowercase.
 * @param {String} name
 * @returns {string}
 */
export const cleanUsername = (name = '') => name.replace(/[.\-_]/g, '').toLowerCase();

/**
 * Expand a hash
 * @param {String} str
 * @returns {Promise<Uint8Array>}
 */
export const expandHash = async (str) => {
    const list = await Promise.all([
        openpgp.crypto.hash.sha512(binaryStringToArray(str + '\x00')),
        openpgp.crypto.hash.sha512(binaryStringToArray(str + '\x01')),
        openpgp.crypto.hash.sha512(binaryStringToArray(str + '\x02')),
        openpgp.crypto.hash.sha512(binaryStringToArray(str + '\x03'))
    ]);

    return openpgp.util.concatUint8Array(list);
};

/**
 * Format a hash
 * @param {String} password
 * @param {String} salt
 * @param {Uint8Array} modulus
 * @returns {Promise<Uint8Array>}
 */
const formatHash = async (password, salt, modulus) => {
    const unexpandedHash = await bcrypt.hash(password, BCRYPT_PREFIX + salt);
    return expandHash(unexpandedHash + arrayToBinaryString(modulus));
};

/**
 * Generate salt for a key.
 * @returns {String}
 */
export const generateKeySalt = () => {
    return encodeBase64(arrayToBinaryString(getRandomValues(new Uint8Array(16))));
};

/**
 * Compute the key password.
 * @param {String} password plaintext password
 * @param {String} salt Base 64 encoded string
 * @returns {Promise<String>}
 */
export const computeKeyPassword = async (password, salt) => {
    if (salt && salt.length) {
        const saltBinary = binaryStringToArray(decodeBase64(salt));
        const hash = await bcrypt.hash(password, BCRYPT_PREFIX + bcrypt.encodeBase64(saltBinary, 16));
        // Remove bcrypt prefix and salt (first 29 characters)
        return hash.slice(29);
    }

    // No salt, old-style
    return password;
};

/**
 * Hash password in version 3.
 * @param {String} password
 * @param {String} salt
 * @param {Uint8Array} modulus
 * @returns {Promise<Uint8Array>}
 */
const hashPassword3 = (password, salt, modulus) => {
    const saltBinary = binaryStringToArray(salt + 'proton');
    return formatHash(password, bcrypt.encodeBase64(saltBinary, 16), modulus);
};

/**
 * Hash password in version 1.
 * @param {String} password
 * @param {String} username
 * @param {Uint8Array} modulus
 * @returns {Promise<Uint8Array>}
 */
const hashPassword1 = async (password, username, modulus) => {
    const value = binaryStringToArray(encodeUtf8(username.toLowerCase()));
    // eslint-disable-next-line new-cap
    const salt = openpgp.util.Uint8Array_to_hex(await openpgp.crypto.hash.md5(value));
    return formatHash(password, salt, modulus);
};

/**
 * Hash password in version 0.
 * @param {String} password
 * @param {String} username
 * @param {Uint8Array} modulus
 * @returns {Promise<Uint8Array>}
 */
const hashPassword0 = async (password, username, modulus) => {
    const value = await openpgp.crypto.hash.sha512(binaryStringToArray(username.toLowerCase() + encodeUtf8(password)));
    const prehashed = encodeBase64(arrayToBinaryString(value));
    return hashPassword1(prehashed, username, modulus);
};

/**
 * Hash a password.
 * @param {String} password
 * @param {String} salt
 * @param {String} username
 * @param {Uint8Array} modulus
 * @param {Number} version
 * @returns {Promise<Uint8Array>}
 */
export const hashPassword = ({ password, salt, username, modulus, version }) => {
    if (version === 4 || version === 3) {
        return hashPassword3(password, salt, modulus);
    }

    if (version === 2) {
        return hashPassword1(password, cleanUsername(username), modulus);
    }

    if (version === 1) {
        return hashPassword1(password, username, modulus);
    }

    if (version === 0) {
        return hashPassword0(password, username, modulus);
    }

    throw new Error('Unsupported auth version');
};
