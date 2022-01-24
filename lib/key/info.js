import { enums, encrypt, PrivateKey, createMessage } from '../openpgp';
import { SHA256 } from '../crypto/hash';
import { arrayToHexString } from '../utils';
import { dateChecks, keyCheck } from './check';
import { getKey } from './utils';
import { serverTime } from '../serverTime';

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
    const key = await getKey(rawKey);

    const algoInfo = key.getAlgorithmInfo();
    const mainFingerprint = key.getFingerprint();

    const obj = {
        version: key.keyPacket.version,
        publicKeyArmored: key.toPublic().armor(),
        fingerprint: mainFingerprint, // FIXME: deprecated, use fingerprints instead
        fingerprints: [mainFingerprint, ...getSubkeysFingerprints({ subKeys: key.subkeys })],
        sha256Fingerprints: await getSHA256Fingerprints(key),
        userIDs: key.getUserIDs(),
        user: await primaryUser(key, date),
        bitSize: algoInfo.bits || null,
        curve: algoInfo.curve || null,
        created: key.getCreationTime(),
        algorithm: enums.publicKey[algoInfo.algorithm],
        algorithmName: algoInfo.algorithm,
        expires: await key.getExpirationTime(),
        encrypt: await packetInfo(await key.getEncryptionKey(undefined, date).catch(() => {}), key),
        sign: await packetInfo(await key.getSigningKey(undefined, date).catch(() => {}), key),
        decrypted: key instanceof PrivateKey ? key.isDecrypted() : null,
        revocationSignatures: key.revocationSignatures,
        validationError: null,
        dateError: null
    };

    try {
        keyCheck(obj, email, expectEncrypted);
    } catch (err) {
        obj.validationError = err.message;
    }

    try {
        dateChecks(key, date);
    } catch (err) {
        obj.dateError = err.message;
    }

    const encryptCheck = obj.encrypt
        ? encrypt({ message: await createMessage({ text: 'test message' }), encryptionKeys: key, date })
        : Promise.resolve();
    await encryptCheck;

    return obj;
}
