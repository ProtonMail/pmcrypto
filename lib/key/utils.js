import { serverTime, binaryStringToArray } from '../utils';
import openpgpjs from '../openpgp';

// returns promise for generated RSA public and encrypted private keys
export const generateKey = (options) => {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    return openpgpjs.generateKey(options);
};
export const generateSessionKey = (algorithm) => openpgpjs.crypto.generateSessionKey(algorithm);


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

    return openpgpjs.reformatKey(options).then((reformattedKey) => reformattedKey.privateKeyArmored);
}

export function getKeys(rawKeys = '') {

    const keys = (rawKeys instanceof Uint8Array) ? openpgpjs.key.read(rawKeys) : openpgpjs.key.readArmored(rawKeys);

    if (keys === undefined) {
        throw new Error('Cannot parse key(s)');
    }
    if (keys.err) {
        // openpgpjs.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }
    if (keys.keys.length < 1 || keys.keys[0] === undefined) {
        throw new Error('Invalid key(s)');
    }

    return keys.keys;
}

export function isExpiredKey(key) {
    return key.getExpirationTime('encrypt_sign')
        .then((expirationTime) => !(key.getCreationTime() <= +serverTime() && +serverTime() < expirationTime) || key.revocationSignatures.length > 0);
}

export function compressKey(armoredKey) {
    const [ k ] = getKeys(armoredKey);
    const { users } = k;
    users.forEach(({ otherCertifications }) => otherCertifications.length = 0);
    return k.armor();
}

export function getFingerprint(key) {
    return key.getFingerprint();
}

export function getMatchingKey(signature, keys) {
    const keyring = new openpgpjs.Keyring({
        loadPublic: () => keys,
        loadPrivate: () => [],
        storePublic() {},
        storePrivate() {}
    });

    // eslint-disable-next-line new-cap
    const keyid = openpgpjs.util.Uint8Array_to_hex(binaryStringToArray(signature.keyid.toHex()));
    const [ key ] = keyring.getKeysForId(keyid, true) || [ null ];
    return key;
}

export function cloneKey(inputKey) {
    const [ key ] = getKeys(inputKey.toPacketlist().write());
    return key;
}
