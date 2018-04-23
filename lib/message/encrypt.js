const { serverTime } = require('../utils');
function encryptMessage(options) {
    if (typeof options.data === 'string') {
        options.data = options.data.replace(/[ \t]*$/mg, '');
    }
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? openpgp.enums.compression.zlib : undefined;
    return openpgp.encrypt(options);
}

module.exports = encryptMessage;
