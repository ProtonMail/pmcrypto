// returns promise for generated RSA public and encrypted private keys
const generateKey = (opt) => openpgp.generateKey(opt);
const generateSessionKey = (algorithm) => openpgp.crypto.generateSessionKey(algorithm);


function reformatKey(privKey, email = '', passphrase = '') {

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

function getKeys(rawKeys = '') {

    const keys = (rawKeys instanceof Uint8Array) ? openpgp.key.read(rawKeys) : openpgp.key.readArmored(rawKeys);

    if (keys === undefined) {
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

function isExpiredKey(key) {
    return key.getExpirationTime() !== null && key.getExpirationTime() < Date.now();
}

module.exports = {
    generateKey,
    generateSessionKey,
    reformatKey,
    getKeys,
    isExpiredKey
};