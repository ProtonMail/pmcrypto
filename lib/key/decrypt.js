const { getKeys, pickPrivate } = require('./utils');

function decryptPrivateKey(privKey, privKeyPassCode) {

    return Promise.resolve()
    .then(() => {

        if (privKey === undefined || privKey === '') {
            return Promise.reject(new Error('Missing private key'));
        }
        if (privKeyPassCode === undefined || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        const keys = getKeys(privKey);

        if (keys[0].decrypt(privKeyPassCode)) {
            return keys[0];
        }

        return Promise.reject(new Error('Private key decryption failed')); // Do NOT make this an Error object
    });
}

function decryptSessionKey(options) {

    return Promise.resolve()
    .then(() => {

        options = pickPrivate(options);

        try {
            return openpgp.decryptSessionKey(options)
            .then((result) => {

                // FIXME this should be in openpgp.js
                if (!result) {
                    return Promise.reject(new Error('Invalid session key for decryption'));
                }

                return result;
            })
            .catch((err) => {
                console.log(err);
                return Promise.reject(new Error('Session key decryption failed'));
            });
        } catch (err) {
            if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
                return Promise.reject(new Error('Incorrect message password')); // Bad password, reject without Error object
            }
            return Promise.reject(err);
        }
    });
}

return { decryptPrivateKey, decryptSessionKey };