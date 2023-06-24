import BigIntegerInterface from '@openpgp/noble-hashes/esm/biginteger/interface';
import { KDFParams } from '../openpgp';
import { generateKey, reformatKey } from './utils';

let loadedBigInteger = false;
const getBigInteger = async () => {
    // Temporary function to be dropped once openpgpjs v6 (which will bundle noble-hashes) is integrated.
    // openpgpjs v5 internally includes a BigInteger implementation, but it is not exported.
    // noble-hashes's BigInteger export automatically imports BN.js (as BigInt fallback),
    // instead we only import it if needed to minimise the bundle size.
    if (loadedBigInteger) return BigIntegerInterface;

    const detectBigInt = () => typeof BigInt !== 'undefined';
    if (detectBigInt()) {
        // NativeBigInteger is small, so it could also be imported always
        const { default: NativeBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/native.interface');
        BigIntegerInterface.setImplementation(NativeBigInteger);
    } else {
        const { default: FallbackBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/bn.interface');
        BigIntegerInterface.setImplementation(FallbackBigInteger);
    }
    loadedBigInteger = true;

    return BigIntegerInterface;
};

export async function computeProxyParameter(originalSecret, finalRecipientSecret) {
    const BigInteger = await getBigInteger();

    const dB = BigInteger.new(originalSecret);
    const dC = BigInteger.new(finalRecipientSecret);
    const n = BigInteger.new('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed'); // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    const proxyParameter = dC.modInv(n).mul(dB).mod(n).toUint8Array('le');

    return proxyParameter;
}

/**
 * Generate a forwarding key for the final recipient, as well as the corresponding proxy factor.
 * The key in input must be a v4 primary key and must have at least one ECDH subkey using curve25519 (legacy format)
 * @param originalKey       ECC primary key of original recipient
 * @param forwardingUserIds array of user IDs of forwarding key
 * @param subkeyId          (optional) keyid of the ECDH subKey to use for the original recipient
 * @returns {Promise<Object>}                   The generated key object in the form:
 *          { proxyFactor: Uint8Array, finalRecipientKey: PrivateKey }
 * @async
 * @static
 */
export async function generateForwardingMaterial(originalKey, forwardingUserIDs, subKeyId) {
    const curveName = 'curve25519';

    const { privateKey: forwardingKey } = await generateKey({ type: 'ecc', userIDs: forwardingUserIDs, format: 'object' });
    // Setup subKey: find ECDH subkey to override
    const originalSubKey = await originalKey.getEncryptionKey(subKeyId);
    if (
        !originalSubKey ||
        originalSubKey.getAlgorithmInfo().algorithm !== 'ecdh' ||
        originalSubKey.getAlgorithmInfo().curve !== curveName
    ) {
        throw new Error('Could not find a suitable ECDH encryption key packet');
    }

    const forwardingSubkey = forwardingKey.subkeys[0];

    // Add KDF params for forwarding
    const { hash, cipher } = forwardingSubkey.keyPacket.publicParams.kdfParams;
    forwardingSubkey.keyPacket.publicParams.kdfParams = new KDFParams({
        version: 2,
        hash,
        cipher,
        replacementFingerprint: originalSubKey.keyPacket.getFingerprintBytes().subarray(0, 20)
    });

    // Update subkey binding signatures to account for updated KDF params
    const { privateKey: finalRecipientKey } = await reformatKey({
        privateKey: forwardingKey, userIDs: forwardingUserIDs, format: 'object'
    });

    // Generate proxy factor k (server secret)
    const proxyParameter = await computeProxyParameter(
        originalSubKey.keyPacket.privateParams.d,
        forwardingSubkey.keyPacket.privateParams.d
    );

    return { proxyParameter, finalRecipientKey };
}
