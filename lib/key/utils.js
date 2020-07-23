import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';

// returns promise for generated RSA public and encrypted private keys
export function generateKey({ passphrase, date = serverTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgp.generateKey({ passphrase, date, ...rest });
}

export function generateSessionKey(algorithm) {
    return openpgp.crypto.generateSessionKey(algorithm);
}

export async function getPreferredAlgorithm(keys, date = serverTime()) {
    return openpgp.enums.read(openpgp.enums.symmetric, await openpgp.key.getPreferredAlgo('symmetric', keys, date));
}

export function reformatKey({ passphrase, date = serverTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgp.reformatKey({ passphrase, date, ...rest });
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
 * Generate a forwarding key for the final recipient, as well as the corresponding proxy factor.
 * The key in input must be a ECC primary key and must have at least one ECDH subkey using curve25519
 * @param {Key}               originalKey       ECC primary key of original recipient
 * @param {Array<Object>}     forwardingUserIds array of user IDs of forwarding key
 * @param {module:type/keyid} subkeyId          (optional) keyid of the ECDH subKey to use for the original recipient
 * @returns {Promise<Object>}                   The generated key object in the form:
 *          { proxyFactor, finalRecipientKey: { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String } }
 * @async
 * @static
 */
export async function generateForwardingMaterial(originalKey, forwardingUserIds, subKeyId = null) {
    const curveName = 'curve25519';

    let forwardingKey = await cloneKey(originalKey);
    // Generate new primary key params
    await forwardingKey.keyPacket.generate(null, forwardingKey.keyPacket.params[0]);
    forwardingKey.keyPacket.keyid = null;
    forwardingKey.keyPacket.fingerprint = null;

    // Setup subKey: find ECDH subkey to override
    const originalSubKey = await originalKey.getEncryptionKey(subKeyId);
    if (
        !originalSubKey ||
        originalSubKey.getAlgorithmInfo().algorithm !== 'ecdh' ||
        originalSubKey.getAlgorithmInfo().curve !== curveName
    ) {
        throw new Error('Could not find a suitable ECDH encryption key packet');
    }
    // Discard all other copied subkeys
    forwardingKey.subKeys = forwardingKey.subKeys.filter((subKey) =>
        subKey.getKeyId().equals(originalSubKey.getKeyId())
    );
    const forwardingSubKey = forwardingKey.subKeys[0];
    // Generate new subkey params
    await forwardingSubKey.keyPacket.generate(null, curveName);
    forwardingSubKey.keyPacket.keyid = null;
    forwardingSubKey.keyPacket.fingerprint = null;

    // Add KDF params for forwarding
    const { hash, cipher } = forwardingSubKey.keyPacket.params[2];
    forwardingSubKey.keyPacket.params[2] = new openpgp.KDFParams({
        version: 2,
        hash,
        cipher,
        flags: 0x3,
        replacementFingerprint: originalSubKey.keyPacket.getFingerprintBytes().subarray(0, 20),
        replacementKDFParams: new openpgp.KDFParams({ hash, cipher }).write()
    });

    // Update userIds and signatures
    forwardingKey = await openpgp.reformatKey({ privateKey: forwardingKey, userIds: forwardingUserIds });

    // Generate proxy factor k (server secret)
    const dB = originalSubKey.keyPacket.params[3].toBN();
    const dC = forwardingSubKey.keyPacket.params[3].toBN();
    const n = new openpgp.MPI(
        openpgp.util.hex_to_Uint8Array('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed')
    ).toBN();
    const proxyFactor = dC
        .invm(n)
        .mul(dB)
        .umod(n);

    return { proxyFactor, finalRecipientKey: forwardingKey };
}

/**
 * Generate ECDHE key and secret from public key
 *
 * @param {Object<Options>}                              Public key Q, fingerprint and curve (name or OID)
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
export async function genPublicEphemeralKey({ Curve, Q, Fingerprint }) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(Curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { publicKey: V, sharedKey: S } = await openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(
        curveObj,
        Q
    );
    const cipherAlgo = openpgp.enums.read(openpgp.enums.symmetric, curveObj.cipher);

    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        openpgp.enums.publicKey.ecdh,
        oid,
        new openpgp.KDFParams({ cipher: curveObj.cipher, hash: curveObj.hash }),
        Fingerprint
    );

    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        openpgp.crypto.cipher[cipherAlgo].keySize,
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
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(Curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { sharedKey: S } = await openpgp.crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(curveObj, V, null, d);
    const cipherAlgo = openpgp.enums.read(openpgp.enums.symmetric, curveObj.cipher);

    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
        openpgp.enums.publicKey.ecdh,
        oid,
        new openpgp.KDFParams({ cipher: curveObj.cipher, hash: curveObj.hash }),
        Fingerprint
    );

    return openpgp.crypto.publicKey.elliptic.ecdh.kdf(
        curveObj.hash,
        S,
        openpgp.crypto.cipher[cipherAlgo].keySize,
        param,
        false,
        false
    );
}
