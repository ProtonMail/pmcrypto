import { KDFParams, PrivateKey, UserID, SecretSubkeyPacket, SecretKeyPacket, MaybeArray, Subkey, config as defaultConfig, SubkeyOptions, enums } from '../openpgp';
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

export async function computeProxyParameter(
    forwarderSecret: Uint8Array,
    forwardeeSecret: Uint8Array
): Promise<Uint8Array> {
    const BigInteger = await getBigInteger();

    const dB = BigInteger.new(forwarderSecret);
    const dC = BigInteger.new(forwardeeSecret);
    const n = BigInteger.new('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed'); // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    const proxyParameter = dC.modInv(n).mul(dB).mod(n).toUint8Array('le', forwardeeSecret.length);

    return proxyParameter;
}

async function getEncryptionKeysForForwarding(forwarderKey: PrivateKey) {
    const curveName = 'curve25519';
    const forwarderEncryptionKeys = await forwarderKey.getDecryptionKeys(
        undefined,
        undefined,
        undefined,
        { ...defaultConfig, allowInsecureDecryptionWithSigningKeys: false }
    ) as any as (PrivateKey | Subkey)[]; // TODO wrong TS defintion for `getDecryptionKeys`

    if (forwarderEncryptionKeys.some((forwarderSubkey) => (
        !forwarderSubkey ||
        !(forwarderSubkey.keyPacket instanceof SecretKeyPacket) || // SecretSubkeyPacket is a subclass
        forwarderSubkey.keyPacket.isDummy() ||
        forwarderSubkey.keyPacket.version !== 4 || // TODO add support for v6
        forwarderSubkey.getAlgorithmInfo().algorithm !== 'ecdh' ||
        forwarderSubkey.getAlgorithmInfo().curve !== curveName
    ))) {
        throw new Error('One or more encryption key packets are unsuitable for forwarding');
    }

    return forwarderEncryptionKeys;
}

/**
 * Whether the given key can be used as input to `generateForwardingMaterial` to setup forwarding.
 */
export const doesKeySupportForwarding = async (forwarderKey: PrivateKey) => (
    forwarderKey.isDecrypted() && getEncryptionKeysForForwarding(forwarderKey)
        .then((keys) => keys.length > 0)
        .catch(() => false)
);

/**
 * Whether all the encryption-capable (sub)keys are setup as forwarding keys.
 * This function also supports encrypted private keys.
 */
export const isForwardingKey = (keyToCheck: PrivateKey) => (
    getEncryptionKeysForForwarding(keyToCheck)
        // @ts-ignore missing `bindingSignatures` definition
        .then((keys) => keys.every((key) => key.bindingSignatures[0].keyFlags & enums.keyFlags.forwardedCommunication))
        .catch(() => false)
);

/**
 * Generate a forwarding key for the final recipient ('forwardee'), as well as the corresponding proxy parameter,
 * needed to transform the forwarded ciphertext.
 * The key in input must be a v4 primary key and its encryption subkeys must be of type ECDH curve25519 (legacy format).
 * @param forwarderKey - ECC primary key of original recipient
 * @param userIDsForForwardeeKey - user IDs for generated key
 * @returns The generated forwarding material
 * @async
 */
export async function generateForwardingMaterial(
    forwarderKey: PrivateKey,
    userIDsForForwardeeKey: MaybeArray<UserID>
) {
    if (!forwarderKey.isDecrypted()) {
        throw new Error('Forwarder key must be decrypted');
    }

    const curveName = 'curve25519';
    const forwarderEncryptionKeys = await getEncryptionKeysForForwarding(forwarderKey);
    const { privateKey: forwardeeKeyToSetup } = await generateKey({ // TODO handle v6 keys
        type: 'ecc',
        userIDs: userIDsForForwardeeKey,
        subkeys: new Array<SubkeyOptions>(forwarderEncryptionKeys.length).fill({ curve: curveName, forwarding: true }),
        format: 'object'
    });

    // Setup forwardee encryption subkeys and generated corresponding proxy params
    const proxyInstances = await Promise.all(forwarderEncryptionKeys.map(async (forwarderSubkey, i) => {

        const forwarderSubkeyPacket = forwarderSubkey.keyPacket as SecretSubkeyPacket;
        const forwardeeSubkeyPacket = forwardeeKeyToSetup.subkeys[i].keyPacket as SecretSubkeyPacket;

        // Add KDF params for forwarding
        // @ts-ignore missing publicParams definition
        const { hash, cipher } = forwardeeSubkeyPacket.publicParams.kdfParams;
        // @ts-ignore missing publicParams definition
        forwardeeSubkeyPacket.publicParams.kdfParams = new KDFParams({
            version: 0xFF,
            hash,
            cipher,
            replacementFingerprint: forwarderSubkeyPacket.getFingerprintBytes()!.subarray(0, 20)
        });

        // Generate proxy factor k (server secret)
        const proxyParameter = await computeProxyParameter(
            // @ts-ignore privateParams fields are not defined
            forwarderSubkeyPacket.privateParams!.d,
            // @ts-ignore privateParams fields are not defined
            forwardeeSubkeyPacket.privateParams!.d
        );

        // fingerprint to be updated with the new KDFParams
        // @ts-ignore `computeFingerprintAndKeyID` not declared
        await forwardeeSubkeyPacket.computeFingerprintAndKeyID();

        return {
            keyVersion: forwarderSubkeyPacket.version,
            proxyParameter,
            forwarderKeyFingerprint: forwarderSubkeyPacket.getFingerprintBytes()!,
            forwardeeKeyFingerprint: forwardeeSubkeyPacket.getFingerprintBytes()!
        };
    }));

    // Update subkey binding signatures to account for updated KDF params
    const { privateKey: finalForwardeeKey } = await reformatKey({
        privateKey: forwardeeKeyToSetup, userIDs: userIDsForForwardeeKey, format: 'object'
    });

    return { proxyInstances, forwardeeKey: finalForwardeeKey };
}
