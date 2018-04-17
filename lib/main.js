const utils = require('./utils');
const timing = require('./timing');
const keyUtils = require('./key/utils');
const decryptKey = require('./key/decrypt');
const encryptKey = require('./key/encrypt');
const decryptMessage = require('./message/decrypt');
const messageUtils = require('./message/utils');

function pmcrypto(performance) {

    const config = { debug: true }
    const perf = timing(performance);

    return {
        config,

        generateKey: keyUtils.generateKey,
        getKeys: keyUtils.getKeys,
        updateServerTime: utils.updateServerTime,

        reformatKey: keyUtils.reformatKey,
        generateSessionKey: keyUtils.generateSessionKey,
        isExpiredKey: keyUtils.isExpiredKey,

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
        createMessage: messageUtils.createMessage,

        encryptMessage: openpgp.encrypt,
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
        stripArmor: utils.stripArmor,

        keyInfo: require('./key/info'),
        keyCheck: require('./key/check')
    };
}

module.exports = pmcrypto;
