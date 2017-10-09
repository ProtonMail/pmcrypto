const utils = require('./utils');
const keyUtils = require('./key/utils');
const decryptKey = require('./key/decrypt');
const encryptKey = require('./key/encrypt');
const decryptMessage = require('./message/decrypt');
const messageUtils = require('./message/utils');

function pmcrypto() {

    const config = { debug: true}

    return {
        config,

        generateKey: keyUtils.generateKey,
        getKeys: keyUtils.getKeys,

        reformatKey: keyUtils.reformatKey,
        generateSessionKey: keyUtils.generateSessionKey,

        encryptSessionKey: encryptKey.encryptSessionKey,
        decryptSessionKey: decryptKey.decryptSessionKey,
        encryptPrivateKey: encryptKey.encryptPrivateKey,
        decryptPrivateKey: decryptKey.decryptPrivateKey,

        getMessage: messageUtils.getMessage,
        getSignature: messageUtils.getSignature,
        signMessage: messageUtils.signMessage,
        splitMessage: messageUtils.splitMessage,
        verifyMessage: messageUtils.verifyMessage,
        getCleartextMessage: messageUtils.getCleartextMessage,

        encryptMessage: require('./message/encrypt'),
        decryptMessage: decryptMessage.decryptMessage,
        decryptMessageLegacy: decryptMessage.decryptMessageLegacy,

        encode_utf8: utils.encode_utf8,
        decode_utf8: utils.decode_utf8,
        encode_base64: utils.encode_base64,
        decode_base64: utils.decode_base64,
        encode_utf8_base64: utils.encode_utf8_base64,
        decode_utf8_base64: utils.decode_utf8_base64,
        getHashedPassword: utils.getHashedPassword,
        arrayToBinaryString: utils.arrayToBinaryString,
        binaryStringToArray: utils.binaryStringToArray,
        concatArrays: openpgp.util.concatUint8Array,

        keyInfo: require('./key/info'),
        keyCheck: require('./key/check')
    };
}

module.exports = pmcrypto();