import {
    generateKey as openpgpGenerateKey,
    reformatKey as openpgpReformatKey,
    enums,
    readKey,
    readArmoredKey,
    readKeys,
    readArmoredKeys,
    Keyring,
    KDFParams,
    getPreferredAlgo,
    OID
} from 'openpgp';
import { genCurvePublicEphemeralKey, genCurvePrivateEphemeralKey, buildEcdhParam, kdf } from './ecdh';
import { serverTime } from '../serverTime';
import { hexToUint8Array, cipher, getRandomBytes } from '../utils';

// returns promise for generated RSA public and encrypted private keys
export function generateKey({ passphrase, date = serverTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgpGenerateKey({ passphrase, date, ...rest });
}

/**
 * Generating a session key for the specified symmetric algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric}  algo  Symmetric encryption algorithm
 * @returns {Uint8Array}                  Random bytes as a string to be used as a key
 * @async
 */
export function generateSessionKey(algorithm) {
    if (!cipher.hasOwnProperty(algorithm)) {
        throw new Error('Unsopported algorithm for generating session key');
    }
    return getRandomBytes(cipher[algorithm].keySize);
}

export async function getPreferredAlgorithm(keys, date = serverTime()) {
    return enums.read(enums.symmetric, await getPreferredAlgo('symmetric', keys, date));
}

export function reformatKey({ passphrase, date = serverTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgpReformatKey({ passphrase, date, ...rest });
}

export async function getKey(rawKey = '') {
    const method = rawKey instanceof Uint8Array ? readKey : readArmoredKey;
    const key = await method(rawKey);
    return key;
}

export async function getKeys(rawKeys = '') {
    const method = rawKeys instanceof Uint8Array ? readKeys : readArmoredKeys;
    const keys = await method(rawKeys);
    return keys;
}

export async function isExpiredKey(key) {
    const time = await key.getExpirationTime('encrypt_sign');
    const timeServer = +serverTime();
    return !(key.getCreationTime() <= timeServer && timeServer < time) || key.revocationSignatures.length > 0;
}

export async function compressKey(armoredKey) {
    const k = await getKey(armoredKey);
    const { users } = k;
    users.forEach(({ otherCertifications }) => (otherCertifications.length = 0));
    return k.armor();
}

export function getFingerprint(key) {
    return key.getFingerprint();
}

/**
 * Gets the key matching the signature
 * @param {Signature} signature
 * @param {Array<Key>} keys An array of keys
 * @return key
 */
export async function getMatchingKey(signature, keys) {
    const keyring = new Keyring({
        loadPublic: () => keys,
        loadPrivate: () => [],
        storePublic() {},
        storePrivate() {}
    });

    await keyring.load();

    const keyids = signature.packets.map(({ issuerKeyId }) => issuerKeyId.toHex());
    const key = keyids.reduce((acc, keyid) => {
        if (!acc) {
            const keys = keyring.getKeysForId(keyid, true);

            if (Array.isArray(keys) && keys.length) {
                return keys[0];
            }
        }

        return acc;
    }, undefined);

    return key;
}

export async function cloneKey(inputKey) {
    const key = await getKey(inputKey.toPacketlist().write());
    return key;
}

/**
 * Generate ECDHE key and secret from public key
 *
 * @param {Object<Options>}                              Public key Q, fingerprint and curve (name or OID)
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
export async function genPublicEphemeralKey({ Curve, Q, Fingerprint }) {
    if (Curve !== 'curve25519') {
        throw new Error('Only curve25519 supported');
    }

    const oid = new OID(hexToUint8Array('060A2B060104019755010501'));
    const { publicKey: V, sharedKey: S } = await genCurvePublicEphemeralKey(Q);
    const cipherAlgo = enums.read(enums.symmetric, enums.symmetric.aes128);

    const param = buildEcdhParam(
        enums.publicKey.ecdh,
        oid,
        new KDFParams({ cipher: enums.symmetric.aes128, hash: enums.hash.sha256 }),
        Fingerprint
    );

    const Z = await kdf(enums.hash.sha256, S, cipher[cipherAlgo].keySize, param, false, false);

    return { V, Z };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param {Object<Options>}        Private key d, public part of ECDHE V, Fingerprint and curve (name or OID)
 * @returns {Promise<Uint8Array>}  Generated ephemeral secret
 * @async
 */
export async function genPrivateEphemeralKey({ Curve, d, V, Fingerprint }) {
    if (Curve !== 'curve25519') {
        throw new Error('Only curve25519 supported');
    }

    const oid = new OID(hexToUint8Array('060A2B060104019755010501'));
    const { sharedKey: S } = await genCurvePrivateEphemeralKey(V, null, d);
    const cipherAlgo = enums.read(enums.symmetric, enums.symmetric.aes128);

    const param = buildEcdhParam(
        enums.publicKey.ecdh,
        oid,
        new KDFParams({ cipher: enums.symmetric.aes128, hash: enums.hash.sha256 }),
        Fingerprint
    );

    return kdf(enums.hash.sha256, S, cipher[cipherAlgo].keySize, param, false, false);
}
