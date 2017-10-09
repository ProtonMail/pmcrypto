function encryptMessage(options) {

    return openpgp.encrypt(options)
        .catch(function(err) {
            // Try without signing
            if (options.privateKeys && options.privateKeys.length) {
                options.privateKeys = [];
                return openpgp.encrypt(options);
            }
            return Promise.reject(err);
        });
}

module.exports = encryptMessage;