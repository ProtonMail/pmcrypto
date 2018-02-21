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

            return Promise.reject(new Error('Private key decryption failed'));
        });
}

function decryptSessionKey(options) {

    return Promise.resolve()
        .then(() => {
            const optionsPrivate = pickPrivate(options);

            try {
                return openpgp.decryptSessionKey(optionsPrivate)
                    .then((result) => {

                        // FIXME this should be in openpgp.js
                        if (!result) {
                            return Promise.reject(new Error('Invalid session key for decryption'));
                        }

                        return result;
                    })
                    .catch((err) => {
                        console.error(err);
                        return Promise.reject(err);
                    });
            } catch (err) {
                if (err.message === 'CFB decrypt: invalid key' && optionsPrivate.passwords && optionsPrivate.passwords.length) {
                    return Promise.reject(new Error('Incorrect message password'));
                }
                return Promise.reject(err);
            }
        });
}

module.exports = { decryptPrivateKey, decryptSessionKey };
