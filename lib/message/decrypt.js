const { decode_utf8_base64, binaryStringToArray, arrayToBinaryString } = require('../utils');
const { pickPrivate } = require('../key/utils');
const { getEncMessageFromEmailPM, getEncRandomKeyFromEmailPM } = require('./compat');

function decryptMessage(options) {

    return Promise.resolve()
    .then(() => {

        options = pickPrivate(options);

        try {
            return openpgp.decrypt(options)
            .then(({ data, filename, signatures: sigs }) => {

                let verified = 0;
                let signatures = [];
                if (sigs) {
                    verified = 2;
                    for(let i = 0; i < sigs.length; i++) {
                        if (sigs[i].valid) {
                            verified = 1;
                            signatures.push(sigs[i].signature);
                        }
                    }
                }

                // Debugging
                if (process.env.NODE_ENV !== 'production') {
                    switch (verified) {
                        case 0:
                            console.log('No message signature present');
                            break;
                        case 1:
                            console.log('Verified message signature');
                            break;
                        case 2:
                            console.log('Message signature could not be verified');
                            break;
                        default:
                            return Promise.reject('Unknown verified value');
                    }
                }

                return { data, filename, verified, signatures };
            })
            .catch((err) => {
                console.log(err);
                return Promise.reject(new Error('Decryption failed'));
            });
        } catch (err) {
            if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
                return Promise.reject(new Error('Incorrect message password')); // Bad password, reject without Error object
            }
            return Promise.reject(err);
        }
    });
}

// Backwards-compatible decrypt message function
function decryptMessageLegacy(options) {

    return Promise.resolve()
    .then(() => {

        if (messageTime === undefined || messageTime === '') {
            throw new Error('Missing message time');
        }

        let oldEncMessage = getEncMessageFromEmailPM(options.message);
        const oldEncRandomKey = getEncRandomKeyFromEmailPM(options.message);

        // OpenPGP
        if (oldEncMessage === '' || oldEncRandomKey === '') return decryptMessage(options);

        // Old message encryption format
        const old_options = {
            privateKeys: options.privateKeys,
            message: oldEncRandomKey
        };

        return decryptMessage(old_options)
        .then(({ data }) => decode_utf8_base64(data))
        .then(binaryStringToArray)
        .then((randomKey) => {

            if (randomKey.length === 0) {
                return Promise.reject(new Error('Random key is empty'));
            }

            oldEncMessage = binaryStringToArray(decode_utf8_base64(oldEncMessage));

            let data;
            try {
                // cutoff time for enabling multilanguage support
                if (messageTime > 1399086120) {
                    data = decode_utf8_base64(arrayToBinaryString(openpgp.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true)));
                } else {
                    data = arrayToBinaryString(openpgp.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true));
                }
            } catch (err) {
                return Promise.reject(err);
            }
            return { data, signature: 0 };
        });
    });
}

module.exports = {
    decryptMessage,
    decryptMessageLegacy
}