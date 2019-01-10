import { BigNumber } from 'asmcrypto.js/asmcrypto.all.es8';

import { openpgp } from '../openpgp';
import { expandHash } from '../passwords';
import { arrayToBinaryString, binaryStringToArray, decodeBase64, withPromiseCache } from '../utils';
import { getRandomValues } from '../crypto';
import { verifyMessage } from '../message/utils';
import { VERIFICATION_STATUS, SRP_MODULUS_KEY } from '../constants';

const { NOT_SIGNED, SIGNED_AND_VALID } = VERIFICATION_STATUS;

const readArmoredWithCache = withPromiseCache((key) => openpgp.key.readArmored(key));

/**
 * Get modulus keys.
 * @return {Promise}
 */
export const getModulusKeys = () => readArmoredWithCache(SRP_MODULUS_KEY);

/**
 * @param {Uint8Array} arr
 * @return {Promise<Uint8Array>}
 */
export const srpHasher = (arr) => expandHash(arrayToBinaryString(arr));

/**
 * From Uint8Array to big number
 * @param {Uint8Array} arr
 * @return {BigNumber}
 */
export const toBN = (arr) => {
    const reversed = new Uint8Array(arr.length);
    for (let i = 0; i < arr.length; i++) {
        reversed[arr.length - i - 1] = arr[i];
    }
    return BigNumber.fromArrayBuffer(reversed);
};

/**
 * From big number to Uint8Array
 * @param {Number} len
 * @param {BigNumber} bn
 * @return {Uint8Array}
 */
export const fromBN = (len, bn) => {
    const arr = bn.toBytes();
    const reversed = new Uint8Array(len / 8);
    for (let i = 0; i < arr.length; i++) {
        reversed[arr.length - i - 1] = arr[i];
    }
    return reversed;
};

/**
 * Verify the modulus signature with the SRP public key
 * @param {Object} keys
 * @param {Object} modulus
 * @return {Promise}
 */
export const verifyModulus = async (keys, modulus) => {
    try {
        const { verified = NOT_SIGNED } = await verifyMessage({
            message: modulus,
            publicKeys: keys.keys
        });

        if (verified !== SIGNED_AND_VALID) {
            throw new Error();
        }
    } catch (e) {
        throw new Error('Unable to verify server identity');
    }
};

/**
 * Verify modulus from the API and get the value.
 * @param {String} modulus - Armored modulus string
 * @returns {Promise<Uint8Array>}
 */
export const verifyAndGetModulus = async (modulus) => {
    const [publicKeys, modulusParsed] = await Promise.all([getModulusKeys(), openpgp.cleartext.readArmored(modulus)]);
    await verifyModulus(publicKeys, modulusParsed);
    return binaryStringToArray(decodeBase64(modulusParsed.getText()));
};

/**
 * Generate a random client secret.
 * @param {Number} len
 * @return {BigNumber}
 */
export const generateClientSecret = (len) => toBN(getRandomValues(new Uint8Array(len / 8)));
