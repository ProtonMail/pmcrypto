import {
    reformatKey as openpgp_reformatKey,
    generateKey as openpgp_generateKey,
    generateSessionKey as openpgp_generateSessionKey
} from '../openpgp';
import { serverTime } from '../serverTime';
import { DEFAULT_KEY_GENERATION_OFFSET } from '../constants';
import { getSymmetricKeySize, getRandomBytes } from '../crypto/utils';
import encryptMessage from '../message/encrypt';
import { SHA256 } from '../crypto/hash';
import { arrayToHexString } from '../utils';

/**
 * Generate key and its revocation certificate
 * @param {Object} options - same options as openpgp.generateKey
 * @param {Date} [options.date] - key creation date, defaults to server time
 * @param {'armored'|'binary'|'object'} [format='armored'] - format for generated `PublicKey` and `PrivateKey` data
 * @returns {Promise<Object>} generated key data and armored revocation certificate in the form:
 *      { PrivateKey, PublicKey : String|Uint8Array|Object, revocationCertificate: String }
 */
export async function generateKey({ date = new Date(+serverTime() + DEFAULT_KEY_GENERATION_OFFSET), ...rest }) {
    return openpgp_generateKey({ date, ...rest });
}

/**
 * Generating a session key for the specified symmetric algorithm
 * @param {'aes128'|'aes192'|'aes256'}  algo  Symmetric encryption algorithm name
 * @returns {Uint8Array} Generated session key
 * @async
 */
export async function generateSessionKeyForAlgorithm(algoName) {
    const keySize = getSymmetricKeySize(algoName);
    return getRandomBytes(keySize);
}

/**
 * Generate a session key compatible with the given recipient keys.
 * @param {OpenPGPKey} options.recipientKeys - public keys to take preferences from
 * @returns {Promise<SessionKey>}
 * @async
 * @throws
 */
export function generateSessionKey({ recipientKeys, date = serverTime(), ...options }) {
    return openpgp_generateSessionKey({ encryptionKeys: recipientKeys, date, ...options });
}

/**
 * Reformat key to bind it to a new userID and generate the corresponding preferences.
 * By default, the generated self-certification signatures are set to have creation time equal to the key creation time, to avoid rendering old messages unverifiable (see https://github.com/openpgpjs/openpgpjs/pull/1422).
 */
export function reformatKey({ privateKey, passphrase, date = privateKey.getCreationTime(), ...rest }) {
    return openpgp_reformatKey({ privateKey, passphrase, date, ...rest });
}

/**
 * Returns whether the primary key is expired, or its creation time is in the future.
 * @param {OpenPGPKey} key
 * @param {Date} date - date to use instead of the server time
 * @returns {Promise<Boolean>}
 */
export async function isExpiredKey(key, date = serverTime()) {
    const now = +date;
    const expirationTime = await key.getExpirationTime(); // Always non-null for primary key expiration
    return !(key.getCreationTime() <= now && now < expirationTime);
}

/**
 * Returns whether the primary key is revoked.
 * @param {OpenPGPKey} key
 * @param {Date} date - date to use for signature verification, instead of the server time
 * @returns {Boolean}
 */
export async function isRevokedKey(key, date = serverTime()) {
    return key.isRevoked(null, null, date);
}

/**
 * Check whether a key can successfully encrypt a message.
 * This confirms that the key has encryption capabilities, it is neither expired nor revoked, and that its key material is valid.
 * @param {OpenPGPKey} publicKey - key to check
 * @param {Date} date - use the given date instead of the server time
 * @returns {Boolean}
 */
export const canKeyEncrypt = async (publicKey, date = serverTime()) => {
    try {
        await encryptMessage({ textData: 'test message', encryptionKeys: publicKey, date });
        return true;
    } catch (e) {
        return false;
    }
};

export function getFingerprint(key) {
    return key.getFingerprint();
}

export const getSHA256Fingerprints = (key) => {
    return Promise.all(
        key.getKeys().map(async ({ keyPacket }) => {
            return arrayToHexString(await SHA256(keyPacket.writeForHash(keyPacket.version)));
        })
    );
};

/**
 * Find the key entity that generated the given signature.
 * If the signature is signed by multiple keys, only one matching key is returned.
 * @param {Signature} signature
 * @param {Array<Key>} keys - keys to search
 * @return {Key|undefined} signing key, if found among `keys`
 */
export function getMatchingKey(signature, keys) {
    const keyIDs = signature.getSigningKeyIDs();
    for (const signingKeyID of keyIDs) {
        // If the signing key is a subkey, we still return the full key entity
        const signingKey = keys.find((key) => key.getKeys(signingKeyID).length > 0);
        if (signingKey) return signingKey;
    }
}
