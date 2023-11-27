import { enums } from '../openpgp';
import { serverTime } from '../serverTime';

/**
 * Checks whether the primary key and the subkeys meet our recommended security requirements.
 * These checks are lightweight and do not verify the validity of the subkeys.
 * A key is considered secure if it is:
 * - RSA of size >= 2047 bits
 * - ECC using curve 25519 or any of the NIST curves
 * @param {OpenPGPKey} publicKey - key to check
 * @throws {Error} if the key is considered too weak
 */
export function checkKeyStrength(publicKey) {
    const minRSABits = 2047; // allow 1-bit short keys due to https://github.com/openpgpjs/openpgpjs/pull/1336
    const allowedCurves = new Set([
        enums.curve.ed25519,
        enums.curve.curve25519,
        enums.curve.p256,
        enums.curve.p384,
        enums.curve.p521
    ]);
    const allowedPublicKeyAlgorithms = new Set([
        enums.publicKey.rsaEncryptSign,
        enums.publicKey.rsaSign,
        enums.publicKey.rsaEncrypt,
        enums.publicKey.ecdh,
        enums.publicKey.ecdsa,
        enums.publicKey.eddsa
    ]);

    publicKey.getKeys().forEach(({ keyPacket }) => {
        const keyInfo = keyPacket.getAlgorithmInfo();
        const keyAlgo = enums.write(enums.publicKey, keyInfo.algorithm);

        if (!allowedPublicKeyAlgorithms.has(keyAlgo)) {
            throw new Error(`${keyInfo.algorithm} keys are considered unsafe`);
        }

        if (keyInfo.curve && !allowedCurves.has(keyInfo.curve)) {
            throw new Error(`Keys using curve ${keyInfo.curve} are considered unsafe`);
        }

        if (keyInfo.bits && keyInfo.bits < minRSABits) {
            throw new Error(`Keys shorter than ${minRSABits} bits are considered unsafe`);
        }
    });
}
