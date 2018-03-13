const keyCheck = require('./check');
const encryptMessage = require('../message/encrypt');
const { getKeys } = require('./utils');

function keyInfo(rawKey, email, expectEncrypted = true) {

    return Promise.resolve(getKeys(rawKey))
    .then(async (keys) => {

        const packetInfo = async (packet, key) => {
            if (!packet) {
                return null;
            }

            if (key.subKeys) {
                for (let i = 0; i < key.subKeys.length; i++) {
                    if (packet === key.subKeys[i].subKey) {
                        return {
                            algorithm: openpgp.enums.publicKey[packet.algorithm],
                            expires: await key.subKeys[i].getExpirationTime()
                        };
                    }
                }
            }

            // Packet must be primary key
            return {
                algorithm: openpgp.enums.publicKey[packet.algorithm],
                expires: await key.getExpirationTime()
            };
        };

        const primaryUser = async (key) => {
            const primary = await key.getPrimaryUser();

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

        const algoInfo = keys[0].primaryKey.getAlgorithmInfo();

        const obj = {
            version: keys[0].primaryKey.version,
            publicKeyArmored: keys[0].toPublic().armor(),
            fingerprint: keys[0].primaryKey.getFingerprint(),
            userIds: keys[0].getUserIds(),
            user: await primaryUser(keys[0]),
            bitSize: algoInfo.bits || null,
            curve: algoInfo.curve || null,
            created: keys[0].primaryKey.created,
            algorithm: openpgp.enums.publicKey[algoInfo.algorithm],
            algorithmName: algoInfo.algorithm,
            expires: await keys[0].getExpirationTime(),
            encrypt: await packetInfo(await keys[0].getEncryptionKeyPacket(), keys[0]),
            sign: await packetInfo(await keys[0].getSigningKeyPacket(), keys[0]),
            decrypted: keys[0].primaryKey.isDecrypted, // null if public key
            revocationSignatures: keys[0].revocationSignatures,
            validationError: null
        };

        try {
            keyCheck(obj, email, expectEncrypted);
        } catch (err) {
            obj.validationError = err.message;
        }

        const encryptCheck = obj.encrypt ? encryptMessage({ data: 'test message', publicKeys: keys }) : Promise.resolve();
        await encryptCheck;

        return obj;
    });
}

module.exports = keyInfo;
