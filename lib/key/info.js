const keyCheck = require('./check');
const encryptMessage = require('../message/encrypt');
const { getKeys } = require('./utils');

function keyInfo(rawKey, email, expectEncrypted = true) {

    return Promise.resolve()
    .then(() => {

        const packetInfo = (packet, key) => {
            if (!packet) {
                return null;
            }

            if (key.subKeys) {
                for (let i = 0; i < key.subKeys.length; i++) {
                    if (packet === key.subKeys[i].subKey) {
                        return {
                            algorithm: openpgp.enums.publicKey[packet.algorithm],
                            expires: key.subKeys[i].getExpirationTime()
                        };
                    }
                }
            }

            // Packet must be primary key
            return {
                algorithm: openpgp.enums.publicKey[packet.algorithm],
                expires: key.getExpirationTime()
            };
        };

        const primaryUser = (key) => {

            const primary = key.getPrimaryUser();
            if (!primary) {
                return null;
            }

            if (!primary.user) {
                return null;
            }

            if (!primary.selfCertificate) {
                return null;
            }

            const cert = primary.selfCertificate;

            return {
                userId: primary.user.userId.userid,
                symmetric: cert.preferredSymmetricAlgorithms ? cert.preferredSymmetricAlgorithms : [],
                hash: cert.preferredHashAlgorithms ? cert.preferredHashAlgorithms : [],
                compression: cert.preferredCompressionAlgorithms ? cert.preferredCompressionAlgorithms : []
            };
        };

        const keys = getKeys(rawKey);

        const obj = {
            version: keys[0].primaryKey.version,
            publicKeyArmored: keys[0].toPublic().armor(),
            fingerprint: keys[0].primaryKey.getFingerprint(),
            userIds: keys[0].getUserIds(),
            user: primaryUser(keys[0]),
            bitSize: keys[0].primaryKey.getBitSize(),
            created: keys[0].primaryKey.created,
            algorithm: openpgp.enums.publicKey[keys[0].primaryKey.algorithm],
            expires: keys[0].getExpirationTime(),
            encrypt: packetInfo(keys[0].getEncryptionKeyPacket(), keys[0]),
            sign: packetInfo(keys[0].getSigningKeyPacket(), keys[0]),
            decrypted: keys[0].primaryKey.isDecrypted, // null if public key
            revocationSignature: keys[0].revocationSignature,
            validationError: null
        };

        try {
            keyCheck(obj, email, expectEncrypted);
        } catch (err) {
            obj.validationError = err.message;
        }

        const encryptCheck = obj.encrypt ? encryptMessage({ data: 'test message', publicKeys: keys }) : Promise.resolve();

        return encryptCheck.then(() => obj);
    });
}

module.exports = keyInfo;