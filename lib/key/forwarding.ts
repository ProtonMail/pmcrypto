import { KDFParams, KeyID, PrivateKey, UserID, SecretSubkeyPacket, MaybeArray } from '../openpgp';
import { generateKey, reformatKey } from './utils';

// TODO (investigate): top-level import of BigIntegerInterface causes issues in Jest tests in web-clients;
// the dynamic import of BigIntegerInterface is a temporary fix until the problem is understood/resolved.
let BigIntegerInterface: any;
const getBigInteger = async () => {
    // Temporary function to be dropped once openpgpjs v6 (which will bundle noble-hashes) is integrated.
    // openpgpjs v5 internally includes a BigInteger implementation, but it is not exported.
    // noble-hashes's BigInteger export automatically imports BN.js (as BigInt fallback),
    // instead we only import it if needed to minimise the bundle size.
    if (BigIntegerInterface) return BigIntegerInterface;

    BigIntegerInterface = await import('@openpgp/noble-hashes/esm/biginteger/interface').then((mod) => mod.default);

    const detectBigInt = () => typeof BigInt !== 'undefined';
    if (detectBigInt()) {
        // NativeBigInteger is small, so it could also be imported always
        const { default: NativeBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/native.interface');
        BigIntegerInterface.setImplementation(NativeBigInteger);
    } else {
        const { default: FallbackBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/bn.interface');
        BigIntegerInterface.setImplementation(FallbackBigInteger);
    }

    return BigIntegerInterface;
};

export async function computeProxyParameter(forwarderSecret: Uint8Array, forwardeeSecret: Uint8Array) {
    const BigInteger = await getBigInteger();

    const dB = BigInteger.new(forwarderSecret);
    const dC = BigInteger.new(forwardeeSecret);
    const n = BigInteger.new('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed'); // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    const proxyParameter = dC.modInv(n).mul(dB).mod(n).toUint8Array('le', forwardeeSecret.length);

    return proxyParameter;
}

/**
 * Generate a forwarding key for the final recipient ('forwardee'), as well as the corresponding proxy parameter,
 * needed to transform the forwarded ciphertext.
 * The key in input must be a v4 primary key and must have at least one ECDH subkey using curve25519 (legacy format).
 * @param forwarderKey - ECC primary key of original recipient
 * @param userIDsForForwardeeKey - user IDs for generated key
 * @param subkeyID - keyID of the ECDH subKey to use for the original recipient
 * @returns The generated forwarding material
 * @async
 */
export async function generateForwardingMaterial(
    forwarderKey: PrivateKey,
    userIDsForForwardeeKey: MaybeArray<UserID>,
    subkeyID?: KeyID
) {
    const curveName = 'curve25519';

    // Setup subKey: find ECDH subkey to override
    const forwarderSubkey = await forwarderKey.getEncryptionKey(subkeyID);
    if (
        !forwarderSubkey ||
        !forwarderSubkey.isDecrypted() ||
        forwarderSubkey.getAlgorithmInfo().algorithm !== 'ecdh' ||
        forwarderSubkey.getAlgorithmInfo().curve !== curveName
    ) {
        throw new Error('Could not find a suitable ECDH encryption key packet');
    }
    const forwarderSubkeyPacket = forwarderSubkey.keyPacket as SecretSubkeyPacket; // this is necessarily an encryption subkey (ECDH keys cannot sign)

    const { privateKey: forwardeeKeyToSetup } = await generateKey({ type: 'ecc', userIDs: userIDsForForwardeeKey, format: 'object' });
    const forwardeeSubkeyPacket = forwardeeKeyToSetup.subkeys[0].keyPacket as SecretSubkeyPacket;

    // Add KDF params for forwarding
    // @ts-ignore missing publicParams definition
    const { hash, cipher } = forwardeeSubkeyPacket.publicParams.kdfParams;
    // @ts-ignore missing publicParams definition
    forwardeeSubkeyPacket.publicParams.kdfParams = new KDFParams({
        version: 2,
        hash,
        cipher,
        replacementFingerprint: forwarderSubkeyPacket.getFingerprintBytes()!.subarray(0, 20)
    });

    // Update subkey binding signatures to account for updated KDF params
    const { privateKey: finalForwardeeKey } = await reformatKey({
        privateKey: forwardeeKeyToSetup, userIDs: userIDsForForwardeeKey, format: 'object'
    });

    // Generate proxy factor k (server secret)
    const proxyParameter = await computeProxyParameter(
        // @ts-ignore privateParams fields are not defined
        forwarderSubkeyPacket.privateParams!.d,
        // @ts-ignore privateParams fields are not defined
        forwardeeSubkeyPacket.privateParams!.d
    );

    return { proxyParameter, forwardeeKey: finalForwardeeKey };
}
