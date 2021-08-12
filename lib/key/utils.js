import {
    encrypt,
    readKey,
    reformatKey as openpgpReformatKey,
    enums,
    generateKey as openpgpGenerateKey,
    generateSessionKey as openpgpGenerateSessionKey
} from 'openpgp';
import { serverTime } from '../serverTime';
import { DEFAULT_OFFSET } from '../constants';
import { createMessage } from '../message/utils';
import { ECDHkdf, genECDHPrivateEphemeralKey, genECDHPublicEphemeralKey, ECDHHash, buildECDHParam } from './ecdh';

/**
 * Returns the preferred symmetric/aead/compression algorithm for a set of keys
 * @param {symmetric|aead|compression} type - Type of preference to return
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<module:enums.symmetric|aead|compression>} Preferred algorithm
 * @async
 */
export async function getPreferredAlgo(type, keys = [], date = new Date(), userIDs = []) {
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

// returns promise for generated RSA public and encrypted private keys
export async function generateKey({ passphrase, date = serverTime(), offset = DEFAULT_OFFSET, ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    const offsetDate = new Date(date.getTime() + offset);
    return openpgpGenerateKey({ passphrase, date: offsetDate, ...rest });
}

export function generateSessionKey(encryptionKey) {
    return openpgpGenerateSessionKey({ encryptionKeys: [encryptionKey] });
}

export async function getPreferredAlgorithm(keys, date = serverTime()) {
    return enums.read(enums.symmetric, await getPreferredAlgo('symmetric', keys, date));
}

/**
 * Reformat key to bind it to a new userID and generate the corresponding preferences.
 * By default, the generated self-certification signatures are set to have creation time equal to the key creation time, to avoid rendering old messages unverifiable (see https://github.com/openpgpjs/openpgpjs/pull/1422).
 */
export function reformatKey({ privateKey, passphrase, date = privateKey.getCreationTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgpReformatKey({ privateKey, passphrase, date, ...rest });
}

export async function getKeys(rawKeys = '') {
    const options = rawKeys instanceof Uint8Array ? { binaryKey: rawKeys } : { armoredKey: rawKeys };
    const keys = await readKey(options);

    if (!keys) {
        // keys is undefined in that case
        throw new Error('Cannot parse key(s)');
    }

    if (keys.err) {
        // openpgp.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }

    return keys;
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
    const [k] = await getKeys(armoredKey);
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
    return getKeys(inputKey.toPacketList().write());
}

/**
 * Generate ECDHE key and secret from public key
 *
 * @param {Object<Options>}                              Public key Q, fingerprint and curve (name or OID)
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
export async function genPublicEphemeralKey({ Q, Fingerprint }) {
    const { publicKey: V, sharedKey: S } = await genECDHPublicEphemeralKey(Q);

    const param = buildECDHParam(Fingerprint);

    const Z = await ECDHkdf(ECDHHash, S, param);

    return { V, Z };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param {Object<Options>}        Private key d, public part of ECDHE V, Fingerprint and curve (name or OID)
 * @returns {Promise<Uint8Array>}  Generated ephemeral secret
 * @async
 */
export async function genPrivateEphemeralKey({ d, V, Fingerprint }) {
    const { sharedKey: S } = await genECDHPrivateEphemeralKey(V, null, d);

    const param = buildECDHParam(Fingerprint);

    return ECDHkdf(ECDHHash, S, param);
}
