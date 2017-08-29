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

function getKeys(armoredKeys = '') {

    const keys = openpgp.key.readArmored(armoredKeys);

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

function pickPrivate(options) {

    if (options.privateKeys) {
        // Pick correct private key
        const encryptionKeyIds = options.message.getEncryptionKeyIds();
        if (!encryptionKeyIds.length) {
            throw new Error('No asymmetric session key packets found');
        }

        for (let i = 0; i < options.privateKeys.length; i++) {
            if (options.privateKeys[i].getKeyPacket(encryptionKeyIds) !== null) {
                options.privateKey = options.privateKeys[i];
                break;
            }
        }
    }

    delete options.privateKeys;

    return options;
}

module.exports = {
    pickPrivate,
    generateKey,
    generateSessionKey,
    reformatKey,
    getKeys
};