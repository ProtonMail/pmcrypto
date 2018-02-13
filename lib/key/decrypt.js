const { getKeys } = require('./utils');

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

        return Promise.reject(new Error('Private key decryption failed'));
    });
}

function decryptSessionKey(options) {

    return Promise.resolve()
    .then(() => {

        try {
            return openpgp.decryptSessionKeys(options)
            .then((result) => {

                if (result.length > 1) {
                    return Promise.reject(new Error('Multiple decrypted session keys found'));
                }

                return result[0];
            })
            .catch((err) => {
                console.error(err);
                return Promise.reject(err);
            });
        } catch (err) {
            if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
                return Promise.reject(new Error('Incorrect message password'));
            }
            return Promise.reject(err);
        }
    });
}

module.exports = { decryptPrivateKey, decryptSessionKey };