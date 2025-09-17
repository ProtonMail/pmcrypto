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
        enums.curve.nistP256,
        enums.curve.nistP384,
        enums.curve.nistP521
    ]);
    const allowedPublicKeyAlgorithms = new Set([
        enums.publicKey.rsaEncryptSign,
        enums.publicKey.rsaSign,
        enums.publicKey.rsaEncrypt,
        enums.publicKey.ecdh,
        enums.publicKey.ecdsa,
        enums.publicKey.eddsaLegacy,
        // the following algos are currently only supported for v6 keys, but discriminating
        // based on the key version is not important here, as we assume `checkKeyCompatibility`
        // is used for that.
        enums.publicKey.ed25519,
        enums.publicKey.x25519,
        enums.publicKey.ed448,
        enums.publicKey.x448,
        enums.publicKey.pqc_mlkem_x25519,
        enums.publicKey.pqc_mldsa_ed25519
    ]);

    publicKey.getKeys().forEach(({ keyPacket }) => {
        const keyInfo = keyPacket.getAlgorithmInfo();
        // @ts-expect-error missing `write` declaration
        const keyAlgo = enums.write(enums.publicKey, keyInfo.algorithm) as enums.publicKey;

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
 * Checks whether the key is compatible with other Proton clients, also based on v6 key support.
 */
export function checkKeyCompatibility(publicKey: PublicKey, v6KeysAllowed = false) {
    const keyVersion = publicKey.keyPacket.version;
    const keyVersionIsSupported = keyVersion === 4 || (v6KeysAllowed && keyVersion === 6);
    if (!keyVersionIsSupported) {
        throw new Error(`Version ${publicKey.keyPacket.version} keys are currently not supported.`);
    }

    // These algo are restricted to v6 keys, since they have been added in the same RFC (RFC 9580),
    // and they are thus not implemented by clients without v6 support.
    const v6OnlyPublicKeyAlgorithms = [
        enums.publicKey.ed25519,
        enums.publicKey.ed448,
        enums.publicKey.x25519,
        enums.publicKey.x448,
        enums.publicKey.pqc_mlkem_x25519,
        enums.publicKey.pqc_mldsa_ed25519
    ];

    const supportedPublicKeyAlgorithms = new Set([
        enums.publicKey.dsa,
        enums.publicKey.elgamal,
        enums.publicKey.rsaEncryptSign,
        enums.publicKey.rsaSign,
        enums.publicKey.rsaEncrypt,
        enums.publicKey.ecdh,
        enums.publicKey.ecdsa,
        enums.publicKey.eddsaLegacy,
        ...(keyVersion === 6 ? v6OnlyPublicKeyAlgorithms : [])
    ]);

    const supportedCurves: Set<AlgorithmInfo['curve']> = new Set([
        enums.curve.ed25519Legacy,
        enums.curve.curve25519Legacy,
        enums.curve.nistP256,
        enums.curve.nistP384,
        enums.curve.nistP521,
        enums.curve.brainpoolP256r1,
        enums.curve.brainpoolP384r1,
        enums.curve.brainpoolP512r1,
        enums.curve.secp256k1
    ]);

    publicKey.getKeys().forEach(({ keyPacket }) => {
        const keyInfo = keyPacket.getAlgorithmInfo();
        // @ts-expect-error missing `write` declaration
        const keyAlgo = enums.write(enums.publicKey, keyInfo.algorithm) as enums.publicKey;

        if (!supportedPublicKeyAlgorithms.has(keyAlgo)) {
            throw new Error(`The key algorithm ${keyInfo.algorithm} is currently not supported.`);
        }

        if (keyInfo.curve && !supportedCurves.has(keyInfo.curve)) {
            throw new Error(`Keys using curve ${keyInfo.curve} are currently not supported.`);
        }
    });
}
