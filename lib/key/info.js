import { openpgp } from '../openpgp';
import { dateChecks, keyCheck } from './check';
import { serverTime } from '../serverTime';
import { getKeys } from './utils';
import { createMessage } from '../message/utils';
import { EXPIRATION_TYPE } from '../constants';

const getExpirationTime = (key, type) => {
    return key.getExpirationTime(type).catch(() => undefined);
};

const createPacketInfo = async (packet, subKey, expirationType) => {
    return {
        algorithm: openpgp.enums.publicKey[packet.algorithm],
        expires: await getExpirationTime(subKey, expirationType)
    };
};

const getPacketInfo = (packet, key, expirationType) => {
    if (!packet) {
        return;
    }

    if (key.subKeys) {
        for (let i = 0; i < key.subKeys.length; i++) {
            const subKey = key.subKeys[i];
            if (packet === key.subKeys[i].subKey) {
                return createPacketInfo(packet, subKey, expirationType);
            }
        }
    }

    return createPacketInfo(packet, key, expirationType);
};

export const getSubKeysFingerprints = ({ subKeys = [] } = {}) => {
    return subKeys.map((subkey) => subkey.getFingerprint());
};

/**
 * Get primary user.
 * @param {Key} key
 * @param {Date} [date]
 * @returns {Promise<{Object}>}>}
 */
export const getPrimaryUser = async (key, date) => {
    const primary = await key.getPrimaryUser(date);

    if (!primary || !primary.user || !primary.selfCertification) {
        return;
    }

    const cert = primary.selfCertification;
    return {
        userId: primary.user.userId.userid,
        symmetric: cert.preferredSymmetricAlgorithms ? cert.preferredSymmetricAlgorithms : [],
        hash: cert.preferredHashAlgorithms ? cert.preferredHashAlgorithms : [],
        compression: cert.preferredCompressionAlgorithms ? cert.preferredCompressionAlgorithms : []
    };
};

/**
 * Get key info and perform validations
 * @param {String} rawKey
 * @param {String} [email]
 * @param {String} [expirationType]
 * @param {boolean} [expectEncrypted]
 * @param {Date} [date]
 * @returns {Promise<Object>}
 */
export const getKeyInfo = async ({
    rawKey,
    email,
    expirationType = EXPIRATION_TYPE.ENCRYPT_SIGN,
    expectEncrypted = true,
    date = serverTime()
}) => {
    const keys = await getKeys(rawKey);
    const [key] = keys;

    const created = key.getCreationTime();
    const fingerprints = [key.getFingerprint(), ...getSubKeysFingerprints(key)];
    const algorithmInfo = key.getAlgorithmInfo();

    const [fingerprint] = fingerprints;
    const { bits, curve, algorithm } = algorithmInfo;

    const [expires, user, encryptionKey, signingKey] = await Promise.all([
        getExpirationTime(key, expirationType),
        getPrimaryUser(key, date),
        key.getEncryptionKey(undefined, date),
        key.getSigningKey(undefined, date)
    ]);

    const [encrypt, sign] = await Promise.all([
        getPacketInfo(encryptionKey, key, EXPIRATION_TYPE.ENCRYPT),
        getPacketInfo(signingKey, key, EXPIRATION_TYPE.SIGN)
    ]);

    const obj = {
        version: key.primaryKey.version,
        userIds: key.getUserIds(),
        decrypted: key.isDecrypted(),
        publicKeyArmored: key.toPublic().armor(),
        fingerprint, // FIXME: deprecated, use fingerprints instead
        fingerprints,
        user,
        bitSize: bits,
        curve,
        created,
        algorithm: openpgp.enums.publicKey[algorithm],
        algorithmName: algorithm,
        expires,
        encrypt,
        sign,
        revocationSignatures: key.revocationSignatures
    };

    try {
        keyCheck(obj, email, expectEncrypted);
    } catch (err) {
        obj.validationError = err.message;
    }

    try {
        dateChecks(keys, date);
    } catch (err) {
        obj.dateError = err.message;
    }

    if (obj.encrypt) {
        await openpgp.encrypt({
            message: createMessage('test message'),
            publicKeys: keys,
            date
        });
    }

    return obj;
};

/**
 * @deprecated
 */
export async function keyInfo(rawKey, email, expectEncrypted, date) {
    return getKeyInfo({ rawKey, email, expectEncrypted, date });
}
