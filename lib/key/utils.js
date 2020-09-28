import {
    generateKey as openpgpGenerateKey,
    reformatKey as openpgpReformatKey,
    crypto,
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
import { serverTime } from '../serverTime';

// returns promise for generated RSA public and encrypted private keys
export function generateKey({ passphrase, date = serverTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgpGenerateKey({ passphrase, date, ...rest });
}

export function generateSessionKey(algorithm) {
    return crypto.generateSessionKey(algorithm);
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
    const curveObj = new crypto.publicKey.elliptic.Curve(Curve);
    const oid = new OID(curveObj.oid);
    const { publicKey: V, sharedKey: S } = await crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(curveObj, Q);
    const cipherAlgo = enums.read(enums.symmetric, curveObj.cipher);

    const param = crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        enums.publicKey.ecdh,
        oid,
        new KDFParams({ cipher: curveObj.cipher, hash: curveObj.hash }),
        Fingerprint
    );

    const Z = await crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        crypto.cipher[cipherAlgo].keySize,
        param,
        false,
        false
    );

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
    const curveObj = new crypto.publicKey.elliptic.Curve(Curve);
    const oid = new OID(curveObj.oid);
    const { sharedKey: S } = await crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(curveObj, V, null, d);
    const cipherAlgo = enums.read(enums.symmetric, curveObj.cipher);

    const param = crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        enums.publicKey.ecdh,
        oid,
        new KDFParams({ cipher: curveObj.cipher, hash: curveObj.hash }),
        Fingerprint
    );

    return crypto.publicKey.elliptic.ecdh.kdf(curveObj.hash, S, crypto.cipher[cipherAlgo].keySize, param, false, false);
}
