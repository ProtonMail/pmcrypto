import keyCheck from './check';
import { getKeys } from './utils';
import { serverTime } from '../utils';
import openpgpjs from '../openpgp';

const packetInfo = async (packet, key) => {
    if (!packet) {
        return null;
    }

    if (key.subKeys) {
        for (let i = 0; i < key.subKeys.length; i++) {
            if (packet === key.subKeys[i].subKey) {
                return {
                    algorithm: openpgpjs.enums.publicKey[packet.algorithm],
                    expires: await key.subKeys[i].getExpirationTime('encrypt_sign')
                };
            }
        }
    }

    // Packet must be primary key
    return {
        algorithm: openpgpjs.enums.publicKey[packet.algorithm],
        expires: await key.getExpirationTime('encrypt_sign')
    };
};

const primaryUser = async (key, date) => {
    const primary = await key.getPrimaryUser(date);

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

    const obj = {
        version: keys[0].primaryKey.version,
        publicKeyArmored: keys[0].toPublic().armor(),
        fingerprint: keys[0].getFingerprint(),
        userIds: keys[0].getUserIds(),
        user: await primaryUser(keys[0], date),
        bitSize: algoInfo.bits || null,
        curve: algoInfo.curve || null,
        created: keys[0].getCreationTime(),
        algorithm: openpgpjs.enums.publicKey[algoInfo.algorithm],
        algorithmName: algoInfo.algorithm,
        expires: await keys[0].getExpirationTime('encrypt_sign').catch(() => null),
        encrypt: await packetInfo(await keys[0].getEncryptionKey(undefined, date), keys[0]),
        sign: await packetInfo(await keys[0].getSigningKey(undefined, date), keys[0]),
        decrypted: keys[0].isDecrypted(), // null if public key
        revocationSignatures: keys[0].revocationSignatures,
        validationError: null
    };

    try {
        keyCheck(obj, email, expectEncrypted);
    } catch (err) {
        obj.validationError = err.message;
    }

    const encryptCheck = obj.encrypt ? openpgpjs.encrypt({ data: 'test message', publicKeys: keys, date }) : Promise.resolve();
    await encryptCheck;

    return obj;
}
