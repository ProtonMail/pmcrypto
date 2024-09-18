import { type AlgorithmInfo, type PublicKey, enums } from '../openpgp';

/**
 * Checks whether the primary key and the subkeys meet our recommended security requirements.
 * These checks are lightweight and do not verify the validity of the subkeys.
 * A key is considered secure if it is:
 * - RSA of size >= 2047 bits
 * - ECC using curve 25519 or any of the NIST curves
 * @param {OpenPGPKey} publicKey - key to check
 * @throws {Error} if the key is considered too weak
 */
export function checkKeyStrength(publicKey: PublicKey) {
    const minRSABits = 2047; // allow 1-bit short keys due to https://github.com/openpgpjs/openpgpjs/pull/1336
    const allowedCurves: Set<AlgorithmInfo['curve']> = new Set([
        enums.curve.ed25519Legacy,
        enums.curve.curve25519Legacy,
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
        enums.publicKey.eddsaLegacy
    ]);

    publicKey.getKeys().forEach(({ keyPacket }) => {
        const keyInfo = keyPacket.getAlgorithmInfo();
        // @ts-ignore missing `write` declaration
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

/**
 * Checks whether the key is compatible with all Proton clients.
 */
export function checkKeyCompatibility(publicKey: PublicKey) {
    const supportedPublicKeyAlgorithms = new Set([
        enums.publicKey.dsa,
        enums.publicKey.elgamal,
        enums.publicKey.rsaEncryptSign,
        enums.publicKey.rsaSign,
        enums.publicKey.rsaEncrypt,
        enums.publicKey.ecdh,
        enums.publicKey.ecdsa,
        enums.publicKey.eddsaLegacy
    ]);

    const supportedCurves: Set<AlgorithmInfo['curve']> = new Set([
        enums.curve.ed25519Legacy,
        enums.curve.curve25519Legacy,
        enums.curve.p256,
        enums.curve.p384,
        enums.curve.p521,
        enums.curve.brainpoolP256r1,
        enums.curve.brainpoolP384r1,
        enums.curve.brainpoolP512r1,
        enums.curve.secp256k1
    ]);

    if (publicKey.keyPacket.version > 4) {
        throw new Error(`Version ${publicKey.keyPacket.version} keys are currently not supported.`);
    }

    publicKey.getKeys().forEach(({ keyPacket }) => {
        const keyInfo = keyPacket.getAlgorithmInfo();
        // @ts-ignore missing `write` declaration
        const keyAlgo = enums.write(enums.publicKey, keyInfo.algorithm);

        if (!supportedPublicKeyAlgorithms.has(keyAlgo)) {
            throw new Error(`The key algorithm ${keyInfo.algorithm} is currently not supported.`);
        }

        if (keyInfo.curve && !supportedCurves.has(keyInfo.curve)) {
            throw new Error(`Keys using curve ${keyInfo.curve} are currently not supported.`);
        }
    });
}
