import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';
import { DEFAULT_OFFSET } from '../constants';
import { createMessage } from '../message/utils';

// returns promise for generated RSA public and encrypted private keys
export function generateKey({ date = serverTime(), offset = DEFAULT_OFFSET, ...rest }) {
    const offsetDate = new Date(date.getTime() + offset);
    return openpgp.generateKey({ date: offsetDate, ...rest });
}

export function generateSessionKey(algorithm) {
    return openpgp.crypto.generateSessionKey(algorithm);
}

export async function getPreferredAlgorithm(keys, date = serverTime()) {
    return openpgp.enums.read(openpgp.enums.symmetric, await openpgp.key.getPreferredAlgo('symmetric', keys, date));
}

/**
 * Reformat key to bind it to a new userID and generate the corresponding preferences.
 * By default, the generated self-certification signatures are set to have creation time equal to the key creation time, to avoid rendering old messages unverifiable (see https://github.com/openpgpjs/openpgpjs/pull/1422).
 */
export function reformatKey({ privateKey, date = privateKey.getCreationTime(), ...rest }) {
    return openpgp.reformatKey({ privateKey, date, ...rest });
}

export async function getKeys(rawKeys = '') {
    const method = rawKeys instanceof Uint8Array ? 'read' : 'readArmored'; // openpgp.key.read or openpgp.key.readArmored
    const keys = await openpgp.key[method](rawKeys);

    if (!keys) {
        // keys is undefined in that case
        throw new Error('Cannot parse key(s)');
    }

    if (keys.err) {
        // openpgp.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }

    if (keys.keys.length < 1 || keys.keys[0] === undefined) {
        throw new Error('Invalid key(s)');
    }

    return keys.keys;
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
        await openpgp.encrypt({ message: createMessage('test message'), publicKeys: publicKey, date });
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

/**
 * Gets the key matching the signature
 * @param {Signature} signature
 * @param {Array<Key>} keys An array of keys
 * @return key
 */
export async function getMatchingKey(signature, keys) {
    const keyring = new openpgp.Keyring({
        loadPublic: () => keys,
        loadPrivate: () => [],
        storePublic() {},
        storePrivate() {}
    });

    await keyring.load();

    const keyids = signature.packets.map(({ issuerKeyId }) => issuerKeyId.toHex());
    const key = keyids.reduce((acc, keyid) => {
        if (!acc) {
            const keys = keyring.getKeysForId(keyid, true);

            if (Array.isArray(keys) && keys.length) {
                return keys[0];
            }
        }

        return acc;
    }, undefined);

    return key;
}

export async function cloneKey(inputKey) {
    const [key] = await getKeys(inputKey.toPacketlist().write());
    return key;
}

/**
 * Generate ECDHE key and secret from public key
 *
 * @param {Object<Options>}                              Public key Q, fingerprint and curve (name or OID)
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
export async function genPublicEphemeralKey({ Curve, Q, Fingerprint }) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(Curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { publicKey: V, sharedKey: S } = await openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(
        curveObj,
        Q
    );
    const cipherAlgo = openpgp.enums.read(openpgp.enums.symmetric, curveObj.cipher);

    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        openpgp.enums.publicKey.ecdh,
        oid,
        new openpgp.KDFParams({ cipher: curveObj.cipher, hash: curveObj.hash }),
        Fingerprint
    );

    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        openpgp.crypto.cipher[cipherAlgo].keySize,
        param,
        false,
        false
    );

    return { V, Z };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param {Object<Options>}        Private key d, public part of ECDHE V, Fingerprint and curve (name or OID)
 * @returns {Promise<Uint8Array>}  Generated ephemeral secret
 * @async
 */
export async function genPrivateEphemeralKey({ Curve, d, V, Fingerprint }) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(Curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { sharedKey: S } = await openpgp.crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(curveObj, V, null, d);
    const cipherAlgo = openpgp.enums.read(openpgp.enums.symmetric, curveObj.cipher);

    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        openpgp.enums.publicKey.ecdh,
        oid,
        new openpgp.KDFParams({ cipher: curveObj.cipher, hash: curveObj.hash }),
        Fingerprint
    );

    return openpgp.crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        openpgp.crypto.cipher[cipherAlgo].keySize,
        param,
        false,
        false
    );
}
