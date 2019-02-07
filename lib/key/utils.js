import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';

// returns promise for generated RSA public and encrypted private keys
export const generateKey = (options) => {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    return openpgp.generateKey(options);
};
export const generateSessionKey = (algorithm) => openpgp.crypto.generateSessionKey(algorithm);

export function reformatKey(privKey, email = '', passphrase = '') {
    if (passphrase.length === 0) {
        return Promise.reject(new Error('Missing private key passcode'));
    }

    const user = {
        name: email,
        email
    };

    const options = {
        privateKey: privKey,
        userIds: [user],
        passphrase
    };

    return openpgp.reformatKey(options).then((reformattedKey) => reformattedKey.privateKeyArmored);
}

export async function getKeys(rawKeys = '') {
    const method = rawKeys instanceof Uint8Array ? 'read' : 'readArmored'; // openpgp.key.read or openpgp.key.readArmored
    const keys = await openpgp.key[method](rawKeys);

    if (!keys) {
        // keys is undefined in that case
        throw new Error('Cannot parse key(s)');
    }

    if (keys.err) {
        // openpgp.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }

    if (keys.keys.length < 1 || keys.keys[0] === undefined) {
        throw new Error('Invalid key(s)');
    }

    return keys.keys;
}

export async function isExpiredKey(key) {
    const time = await key.getExpirationTime('encrypt_sign');
    const timeServer = +serverTime();
    return !(key.getCreationTime() <= timeServer && timeServer < time) || key.revocationSignatures.length > 0;
}

export async function compressKey(armoredKey) {
    const [k] = await getKeys(armoredKey);
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
    const keyring = new openpgp.Keyring({
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
    const [key] = await getKeys(inputKey.toPacketlist().write());
    return key;
}

/**
 * Generate ECDHE key and secret from public key
 *
 * @param {Array<Options>}                              Public key Q, fingerprint and curve (name or OID)
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
export async function genPublicEphemeralKey(options) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(options.curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { V, S } = await openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(curveObj, options.Q);
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        openpgp.enums.publicKey.ecdh,
        oid,
        curveObj.cipher,
        curveObj.hash,
        options.fingerprint
    );

    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        openpgp.crypto.cipher[curveObj.cipher].keySize,
        param,
        curveObj,
        false
    );

    return {V, Z}
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param {Array<Options>}         Private key d, public part of ECDHE V, fingerprint and curve (name or OID)
 * @returns {Promise<Uint8Array>}  Generated ephemeral secret
 * @async
 */
export async function genPrivateEphemeralKey(options) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(options.curve);
    const oid = new openpgp.OID(curveObj.oid);
    const S = await openpgp.crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(curveObj, options.V, options.d);
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        openpgp.enums.publicKey.ecdh,
        oid,
        curveObj.cipher,
        curveObj.hash,
        options.fingerprint
    );

    return openpgp.crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        openpgp.crypto.cipher[curveObj.cipher].keySize,
        param,
        curveObj,
        false
    );
}
