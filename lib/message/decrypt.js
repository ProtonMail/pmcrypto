const { decode_utf8_base64, binaryStringToArray, arrayToBinaryString, serverTime } = require('../utils');
const { getMessage, handleVerificationResult } = require('../message/utils');
const { getEncMessageFromEmailPM, getEncRandomKeyFromEmailPM } = require('./compat');
const { VERIFICATION_STATUS: { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } } = require('../constants.js');

function decryptMessage(options) {
    const { publicKeys = [] } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return Promise.resolve()
    .then(() => {

        try {
            return openpgp.decrypt(options)
            .then((result) => handleVerificationResult(result, publicKeys, options.date))
            .then(({ data, filename, verified, signatures }) => {
                // Debugging
                if (process.env.NODE_ENV !== 'production') {
                    switch (verified) {
                        case NOT_SIGNED:
                            console.log('No message signature present');
                            break;
                        case SIGNED_AND_VALID:
                            console.log('Verified message signature');
                            break;
                        case SIGNED_AND_INVALID:
                            console.log('Message signature could not be verified');
                            break;
                        default:
                            return Promise.reject('Unknown verified value');
                    }
                }

                return { data, filename, verified, signatures };
            })
            .catch((err) => {
                console.error(err);
                return Promise.reject(err);
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
// 'message' option must be a string!
function decryptMessageLegacy(options) {

    return Promise.resolve()
    .then(() => {

        if (options.date === undefined || !(options.date instanceof Date)) {
            throw new Error('Missing message time');
        }

        let oldEncMessage = getEncMessageFromEmailPM(options.message);
        const oldEncRandomKey = getEncRandomKeyFromEmailPM(options.message);

        // OpenPGP
        if (oldEncMessage === '' || oldEncRandomKey === '') {
            // Convert message string to object
            options.message = getMessage(options.message);
            return decryptMessage(options);
        }

        // Old message encryption format
        const old_options = {
            privateKeys: options.privateKeys,
            message: getMessage(oldEncRandomKey)
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
                if (+options.date > 1399086120000) {
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
