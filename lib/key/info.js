import { enums, encrypt } from 'openpgp';
import { arrayToHexString, SHA256 } from '../utils';
import { dateChecks, keyCheck } from './check';
import { getKeys } from './utils';
import { serverTime } from '../serverTime';
import { createMessage } from '../message/utils';

async function createPacketInfo(packet, subKey) {
    return {
        algorithm: enums.publicKey[packet.algorithm],
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
        userId: primary.user.userID.userid,
        symmetric: cert.preferredSymmetricAlgorithms ? cert.preferredSymmetricAlgorithms : [],
        hash: cert.preferredHashAlgorithms ? cert.preferredHashAlgorithms : [],
        compression: cert.preferredCompressionAlgorithms ? cert.preferredCompressionAlgorithms : []
    };
};

export default async function keyInfo(rawKey, email, expectEncrypted = true, date = serverTime()) {
    const keys = await getKeys(rawKey);

    const algoInfo = keys.getAlgorithmInfo();
    const mainFingerprint = keys.getFingerprint();

    const obj = {
        version: keys.keyPacket.version,
        publicKeyArmored: keys.toPublic().armor(),
        fingerprint: mainFingerprint, // FIXME: deprecated, use fingerprints instead
        fingerprints: [mainFingerprint, ...getSubkeysFingerprints({ subKeys: keys.subkeys })],
        sha256Fingerprints: await getSHA256Fingerprints(keys),
        userIDs: keys.getUserIDs(),
        user: await primaryUser(keys, date),
        bitSize: algoInfo.bits || null,
        curve: algoInfo.curve || null,
        created: keys.getCreationTime(),
        algorithm: enums.publicKey[algoInfo.algorithm],
        algorithmName: algoInfo.algorithm,
        expires: await keys.getExpirationTime(),
        encrypt: await packetInfo(await keys.getEncryptionKey(undefined, date).catch(() => {}), keys),
        sign: await packetInfo(await keys.getSigningKey(undefined, date).catch(() => {}), keys),
        decrypted: keys.keyPacket.isDecrypted(), // null if public key
        revocationSignatures: keys.revocationSignatures,
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
        ? encrypt({ message: await createMessage('test message'), encryptionKeys: keys, date })
        : Promise.resolve();
    await encryptCheck;

    return obj;
}
