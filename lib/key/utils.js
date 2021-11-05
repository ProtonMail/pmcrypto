import {
    encrypt,
    readKeys,
    readKey,
    // eslint-disable-next-line camelcase
    reformatKey as openpgp_reformatKey,
    enums,
    // eslint-disable-next-line camelcase
    generateKey as openpgp_generateKey,
    generateSessionKey as openpgpGenerateSessionKey
} from 'openpgp';
import { serverTime } from '../serverTime';
import { DEFAULT_OFFSET } from '../constants';
import { createMessage } from '../message/utils';
import { KDF, generateX25519PrivateEphemeralKey, generateX25519PublicEphemeralKey } from '../crypto/ecdh';

/**
 * Returns the preferred symmetric/aead/compression algorithm for a set of keys.
 * This is copied as-is from 'openpgp': https://github.com/openpgpjs/openpgpjs/blob/master/src/key/helper.js#L158
 * @param {symmetric|aead|compression} type - Type of preference to return
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<openpgp.enums.symmetric|aead|compression>} Preferred algorithm
 * @async
 */
async function getPreferredAlgorithmForType(type, keys = [], date = new Date(), userIDs = []) {
    const defaultAlgo = {
        // these are all must-implement in rfc4880bis
        symmetric: enums.symmetric.aes128,
        aead: enums.aead.eax,
        compression: enums.compression.uncompressed
    }[type];
    const preferredSenderAlgo = {
        symmetric: enums.symmetric.aes256,
        aead: enums.aead.eax,
        compression: enums.compression.uncompressed
    }[type];
    const prefPropertyName = {
        symmetric: 'preferredSymmetricAlgorithms',
        aead: 'preferredAEADAlgorithms',
        compression: 'preferredCompressionAlgorithms'
    }[type];

    // if preferredSenderAlgo appears in the prefs of all recipients, we pick it
    // otherwise we use the default algo
    // if no keys are available, preferredSenderAlgo is returned
    const senderAlgoSupport = await Promise.all(
        keys.map(async (key, i) => {
            const primaryUser = await key.getPrimaryUser(date, userIDs[i]);
            const recipientPrefs = primaryUser.selfCertification[prefPropertyName];
            return !!recipientPrefs && recipientPrefs.indexOf(preferredSenderAlgo) >= 0;
        })
    );
    return senderAlgoSupport.every(Boolean) ? preferredSenderAlgo : defaultAlgo;
}

/**
 * Generate key and its revocation certificate
 * @param {Object} options - same options as openpgp.generateKey
 * @param {String} options.passphrase - passphrase to encrypt the key
 * @param {Date} [options.date] - key creation date, defaults to server time
 * @param {'armored'|'binary'|'object'} [format='armored'] - format for generated `PublicKey` and `PrivateKey` data
 * @returns {Promise<Object>} generated key data and armored revocation certificate in the form:
 *      { PrivateKey, PublicKey : String|Uint8Array|Object, revocationCertificate: String }
 */
export async function generateKey({ passphrase, date = new Date(serverTime() + DEFAULT_OFFSET), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgp_generateKey({ passphrase, date, ...rest });
}

export function generateSessionKey(encryptionKey) {
    return openpgpGenerateSessionKey({ encryptionKeys: [encryptionKey] });
}

export async function getPreferredAlgorithm(keys, date = serverTime()) {
    return enums.read(enums.symmetric, await getPreferredAlgorithmForType('symmetric', keys, date));
}

/**
 * Reformat key to bind it to a new userID and generate the corresponding preferences.
 * By default, the generated self-certification signatures are set to have creation time equal to the key creation time, to avoid rendering old messages unverifiable (see https://github.com/openpgpjs/openpgpjs/pull/1422).
 */
export function reformatKey({ privateKey, passphrase, date = privateKey.getCreationTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgp_reformatKey({ privateKey, passphrase, date, ...rest });
}

export async function getKeys(rawKeys = '') {
    const options = rawKeys instanceof Uint8Array ? { binaryKeys: rawKeys } : { armoredKeys: rawKeys };
    const keys = await readKeys(options);
    return keys;
}

export async function getKey(rawKey = '') {
    const options = rawKey instanceof Uint8Array ? { binaryKey: rawKey } : { armoredKey: rawKey };
    const key = await readKey(options);
    return key;
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
        await encrypt({ message: await createMessage('test message'), encryptionKeys: publicKey, date });
        return true;
    } catch (e) {
        return false;
    }
};

export async function compressKey(armoredKey) {
    const k = await getKey(armoredKey);
    const { users } = k;
    users.forEach(({ otherCertifications }) => (otherCertifications.length = 0));
    return k.armor();
}

export function getFingerprint(key) {
    return key.getFingerprint();
}

function keyIDCheck(keyID, key) {
    if (keyID.length === 16) {
        return keyID === key.getKeyID().toHex();
    }
    return keyID === key.getFingerprint();
}

function getKeyWithID(keyID, keys) {
    for (let i = 0; i < keys.length; i++) {
        if (keyIDCheck(keyID, keys[i])) {
            return keys[i];
        }

        if (keys[i].subkeys.length) {
            for (let j = 0; j < keys[i].subkeys.length; j++) {
                if (keyIDCheck(keyID, keys[i].subkeys[j])) {
                    return keys[i];
                }
            }
        }
    }

    return undefined;
}

/**
 * Gets the key matching the signature
 * @param {Signature} signature
 * @param {Array<Key>} keys An array of keys
 * @return key
 */
export async function getMatchingKey(signature, keys) {
    const keyids = signature.packets.map(({ issuerKeyID }) => issuerKeyID.toHex());
    const key = keyids.reduce((acc, keyid) => {
        if (!acc) {
            const foundKey = getKeyWithID(keyid, keys);

            if (foundKey) {
                return foundKey;
            }
        }

        return acc;
    }, undefined);

    return key;
}

export async function cloneKey(inputKey) {
    return getKey(inputKey.toPacketList().write());
}

/**
 * Generate ECDHE ephemeral encryption keypair from the recipient's public key
 * @param {Uint8Array} options.Q - Recipient public key
 * @param {Uint8Array} fingerprint - Recipient fingerprint
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>} Ephemeral public key V and ephemeral shared secret Z
 * @async
 */
export async function generateEncryptionEphemeralKey({ Q, fingerprint }) {
    const { publicKey: V, sharedKey: S } = await generateX25519PublicEphemeralKey(Q);
    const Z = await KDF(S, fingerprint);
    return { V, Z };
}

/**
 * Reconstruct ECDHE ephemeral decryption keypair from long-term private key and public part of ephemeral key
 * @param {Uint8Array} options.d - Long-term private scalar d
 * @param {Uint8Array} options.V - Ephemeral public key
 * @param {Uint8Array} options.fingerprint - Fingerprint of long-term private key
 * @returns {Promise<Uint8Array>} Ephemeral shared secret
 * @async
 */
export async function generateDecryptionEphemeralKey({ d, V, fingerprint }) {
    const { sharedKey: S } = await generateX25519PrivateEphemeralKey(V, d);
    const Z = KDF(S, fingerprint);
    return Z;
}
