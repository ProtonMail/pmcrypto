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

export async function cloneKey(inputKey) {
    return getKey(inputKey.toPacketList().write());
}
