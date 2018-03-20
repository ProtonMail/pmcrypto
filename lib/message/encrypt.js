const { serverTime } = require('../utils');
function encryptMessage(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    return openpgp.encrypt(options);
}

module.exports = encryptMessage;
