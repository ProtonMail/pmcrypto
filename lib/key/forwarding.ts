import { type PrivateKey, type UserID, type SubkeyOptions, type Subkey, KDFParams, enums, SecretSubkeyPacket, type Key, config as defaultConfig } from '../openpgp';
import { generateKey, reformatKey } from './utils';
import { serverTime } from '../serverTime';
import { bigIntToUint8Array, mod, modInv, uint8ArrayToBigInt } from '../bigInteger';
import type { MaybeArray } from '../utils';

export async function computeProxyParameter(
    forwarderSecret: Uint8Array,
    forwardeeSecret: Uint8Array
): Promise<Uint8Array> {

    const dB = uint8ArrayToBigInt(forwarderSecret);
    const dC = uint8ArrayToBigInt(forwardeeSecret);
    const n = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed'); // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    const proxyParameter = bigIntToUint8Array(mod(modInv(dC, n) * dB, n), 'le', forwardeeSecret.length);

    return proxyParameter;
}

const doesKeyPacketSupportForwarding = (maybeForwardeeKey: Key | Subkey) => {
    const curveName = 'curve25519Legacy';

    return (maybeForwardeeKey.keyPacket instanceof SecretSubkeyPacket) && // only ECDH can forward, and they are always subkeys
        !maybeForwardeeKey.keyPacket.isDummy() &&
        maybeForwardeeKey.keyPacket.version === 4 && // TODO add support for v6
        maybeForwardeeKey.getAlgorithmInfo().algorithm === 'ecdh' &&
        maybeForwardeeKey.getAlgorithmInfo().curve === curveName;
};

async function getEncryptionKeysForForwarding(forwarderKey: PrivateKey, date: Date) {
    const forwarderEncryptionKeys = (await Promise.all(forwarderKey.getKeyIDs().map(
        (maybeEncryptionKeyID) => forwarderKey.getEncryptionKey(maybeEncryptionKeyID, date).catch(() => null)
    ))).filter(((maybeKey): maybeKey is (PrivateKey | Subkey) => !!maybeKey));

    if (!forwarderEncryptionKeys.every(doesKeyPacketSupportForwarding)) {
        throw new Error('One or more encryption key packets are unsuitable for forwarding');
    }

    return forwarderEncryptionKeys;
}

/**
 * Whether the given key can be used as input to `generateForwardingMaterial` to setup forwarding.
 */
export async function doesKeySupportForwarding(forwarderKey: PrivateKey, date: Date = serverTime()): Promise<boolean> {
    if (!forwarderKey.isDecrypted()) {
        return false;
    }

    try {
        const keys = await getEncryptionKeysForForwarding(forwarderKey, date);
        return keys.length > 0;
    } catch {
        return false;
    }
}

/**
 * Whether all the decryption-capable (sub)keys are setup as forwardee keys.
 * This function also supports encrypted private keys.
 */
export const isForwardingKey = async (keyToCheck: PrivateKey, date: Date = serverTime()) => {
    // NB: we need this function to be strict since it's used by the client to determine whether a key
    // should be included in the SKL (forwarding keys are not included).
    // For this reason, we need to e.g. check binding signatures.

    const allDecryptionKeys = await keyToCheck
        .getDecryptionKeys(undefined, date, undefined, {
            ...defaultConfig,
            allowForwardedMessages: true
        })
        .catch(() => []); // throws if no valid decryption keys are found

    const hasForwardingKeyFlag = (maybeForwardingSubkey: Subkey) => (
        maybeForwardingSubkey.bindingSignatures.length > 0 &&
            maybeForwardingSubkey.bindingSignatures.every(({ keyFlags }) => {
                const flags = keyFlags?.[0];
                if (!flags) {
                    return false;
                }
                return (flags & enums.keyFlags.forwardedCommunication) !== 0;
            })
    );

    const allValidKeys = allDecryptionKeys.every(
        (key) => doesKeyPacketSupportForwarding(key) && hasForwardingKeyFlag(key as Subkey)
    );
    return allDecryptionKeys.length > 0 && allValidKeys;
};

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
    userIDsForForwardeeKey: MaybeArray<UserID>,
    date: Date = serverTime()
) {
    if (!forwarderKey.isDecrypted()) {
        throw new Error('Forwarder key must be decrypted');
    }

    const curveName = 'curve25519Legacy';
    const forwarderEncryptionKeys = await getEncryptionKeysForForwarding(forwarderKey, date);
    const { privateKey: forwardeeKeyToSetup } = await generateKey({ // TODO handle v6 keys
        type: 'ecc',
        userIDs: userIDsForForwardeeKey,
        subkeys: new Array<SubkeyOptions>(forwarderEncryptionKeys.length).fill({ curve: curveName, forwarding: true }),
        format: 'object',
        date
    });

    // Setup forwardee encryption subkeys and generated corresponding proxy params
    const proxyInstances = await Promise.all(forwarderEncryptionKeys.map(async (forwarderSubkey, i) => {

        const forwarderSubkeyPacket = forwarderSubkey.keyPacket as SecretSubkeyPacket;
        const forwardeeSubkeyPacket = forwardeeKeyToSetup.subkeys[i].keyPacket as SecretSubkeyPacket;

        // Add KDF params for forwarding
        // @ts-ignore missing publicParams definition
        const { hash, cipher } = forwarderSubkeyPacket.publicParams.kdfParams;
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
