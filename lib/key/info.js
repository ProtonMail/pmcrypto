import { openpgp } from '../openpgp';
import { arrayToHexString, SHA256 } from '../utils';
import { dateChecks, keyCheck } from './check';
import { getKeys } from './utils';
import { serverTime } from '../serverTime';
import { createMessage } from '../message/utils';

async function createPacketInfo(packet, subKey) {
    return {
        algorithm: openpgp.enums.publicKey[packet.algorithm],
        expires: await subKey.getExpirationTime()
    };
}

const packetInfo = (packet, key) => {
    if (!packet) {
        return null;
    }

    if (key.subKeys) {
        for (let i = 0; i < key.subKeys.length; i++) {
            const subKey = key.subKeys[i];
            if (packet === key.subKeys[i].subKey) {
                return createPacketInfo(packet, subKey);
            }
        }
    }

    return createPacketInfo(packet, key);
};

const getSubkeysFingerprints = ({ subKeys = [] } = {}) => {
    return subKeys.map((subkey) => subkey.getFingerprint());
};

export const getSHA256Fingerprints = (key) => {
    return Promise.all(
        key.getKeys().map(async ({ keyPacket }) => {
            return arrayToHexString(await SHA256(keyPacket.writeForHash(keyPacket.version)));
        })
    );
};

const primaryUser = async (key, date) => {
    const primary = await key.getPrimaryUser(date).catch(() => {});

    if (!primary) {
        return null;
    }

    if (!primary.user) {
        return null;
    }

    if (!primary.selfCertification) {
        return null;
    }

    const cert = primary.selfCertification;
    return {
        userId: primary.user.userId.userid,
        symmetric: cert.preferredSymmetricAlgorithms ? cert.preferredSymmetricAlgorithms : [],
        hash: cert.preferredHashAlgorithms ? cert.preferredHashAlgorithms : [],
        compression: cert.preferredCompressionAlgorithms ? cert.preferredCompressionAlgorithms : []
    };
};

export default async function keyInfo(rawKey, email, expectEncrypted = true, date = serverTime()) {
    const keys = await getKeys(rawKey);

    const algoInfo = keys[0].getAlgorithmInfo();
    const mainFingerprint = keys[0].getFingerprint();

    const obj = {
        version: keys[0].primaryKey.version,
        publicKeyArmored: keys[0].toPublic().armor(),
        fingerprint: mainFingerprint, // FIXME: deprecated, use fingerprints instead
        fingerprints: [mainFingerprint, ...getSubkeysFingerprints(keys[0])],
        sha256Fingerprints: await getSHA256Fingerprints(keys[0]),
        userIds: keys[0].getUserIds(),
        user: await primaryUser(keys[0], date),
        bitSize: algoInfo.bits || null,
        curve: algoInfo.curve || null,
        created: keys[0].getCreationTime(),
        algorithm: openpgp.enums.publicKey[algoInfo.algorithm],
        algorithmName: algoInfo.algorithm,
        expires: await keys[0].getExpirationTime(),
        encrypt: await packetInfo(await keys[0].getEncryptionKey(undefined, date).catch(() => {}), keys[0]),
        sign: await packetInfo(await keys[0].getSigningKey(undefined, date).catch(() => {}), keys[0]),
        decrypted: keys[0].isDecrypted(), // null if public key
        revocationSignatures: keys[0].revocationSignatures,
        validationError: null,
        dateError: null
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

    const encryptCheck = obj.encrypt
        ? openpgp.encrypt({ message: createMessage('test message'), publicKeys: keys, date })
        : Promise.resolve();
    await encryptCheck;

    return obj;
}
