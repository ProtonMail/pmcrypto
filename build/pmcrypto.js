(function(){function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s}return e})()({1:[function(require,module,exports){
'use strict';

/**
 * @link https://github.com/vibornoff/asmcrypto.js/issues/121
 */
asmCrypto.random.skipSystemRNGWarning = true;
openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;
openpgp.initWorker({ path: 'openpgp.worker.min.js' });

window.pmcrypto = require('./index');

},{"./index":3}],2:[function(require,module,exports){
"use strict";

var constants = {
    VERIFICATION_STATUS: {
        NOT_SIGNED: 0,
        SIGNED_AND_VALID: 1,
        SIGNED_AND_INVALID: 2
    }
};

module.exports = constants;

},{}],3:[function(require,module,exports){
'use strict';

var utils = require('./utils');
var keyUtils = require('./key/utils');
var decryptKey = require('./key/decrypt');
var encryptKey = require('./key/encrypt');
var decryptMessage = require('./message/decrypt');
var messageUtils = require('./message/utils');

function pmcrypto() {

    var config = { debug: true };

    return {
        config: config,

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

module.exports = pmcrypto();

},{"./key/check":4,"./key/decrypt":5,"./key/encrypt":6,"./key/info":7,"./key/utils":8,"./message/decrypt":10,"./message/utils":11,"./utils":12}],4:[function(require,module,exports){
'use strict';

function keyCheck(info, email, expectEncrypted) {

    if (info.decrypted && expectEncrypted) {
        throw new Error('Expected encrypted key but got decrypted key');
    }

    if (info.version !== 4) {
        throw new Error('Key is not OpenPGP version 4');
    }

    if (email) {
        if (info.userIds.length !== 1) {
            throw new Error('Missing or too many UserID packets');
        }

        if (!new RegExp('<' + email + '>$').test(info.user.userId)) {
            throw new Error('UserID does not contain correct email address');
        }
    }

    if (info.bitSize && info.bitSize < 1024) {
        throw new Error('Key is less than 1024 bits');
    }

    if (isFinite(info.expires)) {
        throw new Error('Key will expire');
    }

    if (!info.encrypt) {
        throw new Error('Key cannot be used for encryption');
    }

    if (isFinite(info.encrypt.expires)) {
        throw new Error('Key will expire');
    }

    if (info.revocationSignatures.length) {
        throw new Error('Key is revoked');
    }

    if (!info.sign) {
        throw new Error('Key cannot be used for signing');
    }

    if (isFinite(info.sign.expires)) {
        throw new Error('Key will expire');
    }

    // Hash algorithms
    if (info.user.hash && info.user.hash.length) {
        if (info.user.hash[0] !== openpgp.enums.hash.sha256) {
            throw new Error('Preferred hash algorithm must be SHA256');
        }
    } else {
        throw new Error('Key missing preferred hash algorithms');
    }

    // Symmetric algorithms
    if (info.user.symmetric && info.user.symmetric.length) {
        if (info.user.symmetric[0] !== openpgp.enums.symmetric.aes256) {
            throw new Error('Preferred symmetric algorithm must be AES256');
        }
    } else {
        throw new Error('Key missing preferred symmetric algorithms');
    }

    // Compression algorithms
    if (info.user.compression && info.user.compression.length) {
        if (info.user.compression[0] !== openpgp.enums.compression.zlib) {
            throw new Error('Preferred compression algorithm must be zlib');
        }
    }

    return info;
}

module.exports = keyCheck;

},{}],5:[function(require,module,exports){
'use strict';

var _require = require('./utils'),
    getKeys = _require.getKeys;

function decryptPrivateKey(privKey, privKeyPassCode) {

    return Promise.resolve().then(function () {

        if (privKey === undefined || privKey === '') {
            return Promise.reject(new Error('Missing private key'));
        }
        if (privKeyPassCode === undefined || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        var keys = getKeys(privKey);
        return keys[0].decrypt(privKeyPassCode).then(function (success) {
            if (!success) {
                throw new Error('Private key decryption failed');
            }
            return keys[0];
        });
    });
}

function decryptSessionKey(options) {

    return Promise.resolve().then(function () {

        try {
            return openpgp.decryptSessionKeys(options).then(function (result) {

                if (result.length > 1) {
                    return Promise.reject(new Error('Multiple decrypted session keys found'));
                }

                return result[0];
            }).catch(function (err) {
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

module.exports = { decryptPrivateKey: decryptPrivateKey, decryptSessionKey: decryptSessionKey };

},{"./utils":8}],6:[function(require,module,exports){
'use strict';

function encryptPrivateKey(privKey, privKeyPassCode) {

    return Promise.resolve().then(function () {

        if (Object.prototype.toString.call(privKeyPassCode) !== '[object String]' || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        if (!{}.isPrototypeOf.call(openpgp.key.Key.prototype, privKey)) {
            return Promise.reject(new Error('Not a Key object'));
        }

        if (!privKey.isPrivate()) {
            return Promise.reject(new Error('Not a private key'));
        }

        if (privKey.primaryKey === null || privKey.subKeys === null || privKey.subKeys.length === 0) {
            return Promise.reject(new Error('Missing primary key or subkey'));
        }

        privKey.primaryKey.encrypt(privKeyPassCode);
        return privKey.subKeys[0].subKey.encrypt(privKeyPassCode).then(function () {
            return privKey.armor();
        });
    });
}

var encryptSessionKey = function encryptSessionKey(opt) {
    return openpgp.encryptSessionKey(opt);
};

module.exports = {
    encryptPrivateKey: encryptPrivateKey,
    encryptSessionKey: encryptSessionKey
};

},{}],7:[function(require,module,exports){
'use strict';

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var keyCheck = require('./check');

var _require = require('./utils'),
    getKeys = _require.getKeys;

var _require2 = require('../utils'),
    serverTime = _require2.serverTime;

function keyInfo(rawKey, email) {
    var _this = this;

    var expectEncrypted = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;
    var date = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : serverTime();


    return Promise.resolve(getKeys(rawKey)).then(function () {
        var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee3(keys) {
            var packetInfo, primaryUser, algoInfo, obj, encryptCheck;
            return regeneratorRuntime.wrap(function _callee3$(_context3) {
                while (1) {
                    switch (_context3.prev = _context3.next) {
                        case 0:
                            packetInfo = function () {
                                var _ref2 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(packet, key) {
                                    var i;
                                    return regeneratorRuntime.wrap(function _callee$(_context) {
                                        while (1) {
                                            switch (_context.prev = _context.next) {
                                                case 0:
                                                    if (packet) {
                                                        _context.next = 2;
                                                        break;
                                                    }

                                                    return _context.abrupt('return', null);

                                                case 2:
                                                    if (!key.subKeys) {
                                                        _context.next = 14;
                                                        break;
                                                    }

                                                    i = 0;

                                                case 4:
                                                    if (!(i < key.subKeys.length)) {
                                                        _context.next = 14;
                                                        break;
                                                    }

                                                    if (!(packet === key.subKeys[i].subKey)) {
                                                        _context.next = 11;
                                                        break;
                                                    }

                                                    _context.t0 = openpgp.enums.publicKey[packet.algorithm];
                                                    _context.next = 9;
                                                    return key.subKeys[i].getExpirationTime();

                                                case 9:
                                                    _context.t1 = _context.sent;
                                                    return _context.abrupt('return', {
                                                        algorithm: _context.t0,
                                                        expires: _context.t1
                                                    });

                                                case 11:
                                                    i++;
                                                    _context.next = 4;
                                                    break;

                                                case 14:
                                                    _context.t2 = openpgp.enums.publicKey[packet.algorithm];
                                                    _context.next = 17;
                                                    return key.getExpirationTime();

                                                case 17:
                                                    _context.t3 = _context.sent;
                                                    return _context.abrupt('return', {
                                                        algorithm: _context.t2,
                                                        expires: _context.t3
                                                    });

                                                case 19:
                                                case 'end':
                                                    return _context.stop();
                                            }
                                        }
                                    }, _callee, _this);
                                }));

                                return function packetInfo(_x4, _x5) {
                                    return _ref2.apply(this, arguments);
                                };
                            }();

                            primaryUser = function () {
                                var _ref3 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee2(key) {
                                    var primary, cert;
                                    return regeneratorRuntime.wrap(function _callee2$(_context2) {
                                        while (1) {
                                            switch (_context2.prev = _context2.next) {
                                                case 0:
                                                    _context2.next = 2;
                                                    return key.getPrimaryUser(date);

                                                case 2:
                                                    primary = _context2.sent;

                                                    if (primary) {
                                                        _context2.next = 5;
                                                        break;
                                                    }

                                                    return _context2.abrupt('return', null);

                                                case 5:
                                                    if (primary.user) {
                                                        _context2.next = 7;
                                                        break;
                                                    }

                                                    return _context2.abrupt('return', null);

                                                case 7:
                                                    if (primary.selfCertification) {
                                                        _context2.next = 9;
                                                        break;
                                                    }

                                                    return _context2.abrupt('return', null);

                                                case 9:
                                                    cert = primary.selfCertification;
                                                    return _context2.abrupt('return', {
                                                        userId: primary.user.userId.userid,
                                                        symmetric: cert.preferredSymmetricAlgorithms ? cert.preferredSymmetricAlgorithms : [],
                                                        hash: cert.preferredHashAlgorithms ? cert.preferredHashAlgorithms : [],
                                                        compression: cert.preferredCompressionAlgorithms ? cert.preferredCompressionAlgorithms : []
                                                    });

                                                case 11:
                                                case 'end':
                                                    return _context2.stop();
                                            }
                                        }
                                    }, _callee2, _this);
                                }));

                                return function primaryUser(_x6) {
                                    return _ref3.apply(this, arguments);
                                };
                            }();

                            algoInfo = keys[0].primaryKey.getAlgorithmInfo();
                            _context3.t0 = keys[0].primaryKey.version;
                            _context3.t1 = keys[0].toPublic().armor();
                            _context3.t2 = keys[0].primaryKey.getFingerprint();
                            _context3.t3 = keys[0].getUserIds();
                            _context3.next = 9;
                            return primaryUser(keys[0]);

                        case 9:
                            _context3.t4 = _context3.sent;
                            _context3.t5 = algoInfo.bits || null;
                            _context3.t6 = algoInfo.curve || null;
                            _context3.t7 = keys[0].primaryKey.created;
                            _context3.t8 = openpgp.enums.publicKey[algoInfo.algorithm];
                            _context3.t9 = algoInfo.algorithm;
                            _context3.next = 17;
                            return keys[0].getExpirationTime();

                        case 17:
                            _context3.t10 = _context3.sent;
                            _context3.t11 = packetInfo;
                            _context3.next = 21;
                            return keys[0].getEncryptionKeyPacket(undefined, date);

                        case 21:
                            _context3.t12 = _context3.sent;
                            _context3.t13 = keys[0];
                            _context3.next = 25;
                            return (0, _context3.t11)(_context3.t12, _context3.t13);

                        case 25:
                            _context3.t14 = _context3.sent;
                            _context3.t15 = packetInfo;
                            _context3.next = 29;
                            return keys[0].getSigningKeyPacket(undefined, date);

                        case 29:
                            _context3.t16 = _context3.sent;
                            _context3.t17 = keys[0];
                            _context3.next = 33;
                            return (0, _context3.t15)(_context3.t16, _context3.t17);

                        case 33:
                            _context3.t18 = _context3.sent;
                            _context3.t19 = keys[0].primaryKey.isDecrypted;
                            _context3.t20 = keys[0].revocationSignatures;
                            obj = {
                                version: _context3.t0,
                                publicKeyArmored: _context3.t1,
                                fingerprint: _context3.t2,
                                userIds: _context3.t3,
                                user: _context3.t4,
                                bitSize: _context3.t5,
                                curve: _context3.t6,
                                created: _context3.t7,
                                algorithm: _context3.t8,
                                algorithmName: _context3.t9,
                                expires: _context3.t10,
                                encrypt: _context3.t14,
                                sign: _context3.t18,
                                decrypted: _context3.t19,
                                revocationSignatures: _context3.t20,
                                validationError: null
                            };


                            try {
                                keyCheck(obj, email, expectEncrypted);
                            } catch (err) {
                                obj.validationError = err.message;
                            }

                            encryptCheck = obj.encrypt ? openpgp.encrypt({ data: 'test message', publicKeys: keys, date: date }) : Promise.resolve();
                            _context3.next = 41;
                            return encryptCheck;

                        case 41:
                            return _context3.abrupt('return', obj);

                        case 42:
                        case 'end':
                            return _context3.stop();
                    }
                }
            }, _callee3, _this);
        }));

        return function (_x3) {
            return _ref.apply(this, arguments);
        };
    }());
}

module.exports = keyInfo;

},{"../utils":12,"./check":4,"./utils":8}],8:[function(require,module,exports){
'use strict';

var _require = require('../utils'),
    serverTime = _require.serverTime;
// returns promise for generated RSA public and encrypted private keys


var generateKey = function generateKey(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    return openpgp.generateKey(options);
};
var generateSessionKey = function generateSessionKey(algorithm) {
    return openpgp.crypto.generateSessionKey(algorithm);
};

function reformatKey(privKey) {
    var email = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
    var passphrase = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : '';


    if (passphrase.length === 0) {
        return Promise.reject(new Error('Missing private key passcode'));
    }

    var user = {
        name: email,
        email: email
    };

    var options = {
        privateKey: privKey,
        userIds: [user],
        passphrase: passphrase
    };

    return openpgp.reformatKey(options).then(function (reformattedKey) {
        return reformattedKey.privateKeyArmored;
    });
}

function getKeys() {
    var rawKeys = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';


    var keys = rawKeys instanceof Uint8Array ? openpgp.key.read(rawKeys) : openpgp.key.readArmored(rawKeys);

    if (keys === undefined) {
        throw new Error('Cannot parse key(s)');
    }
    if (keys.err) {
        // openpgp.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }
    if (keys.keys.length < 1 || keys.keys[0] === undefined) {
        throw new Error('Invalid key(s)');
    }

    return keys.keys;
}

function isExpiredKey(key) {
    return key.getExpirationTime().then(function (expirationTime) {
        return !(key.primaryKey.created <= +serverTime() && +serverTime() < expirationTime);
    });
}

module.exports = {
    generateKey: generateKey,
    generateSessionKey: generateSessionKey,
    reformatKey: reformatKey,
    getKeys: getKeys,
    isExpiredKey: isExpiredKey
};

},{"../utils":12}],9:[function(require,module,exports){
'use strict';

// Deprecated, backwards compatibility
var protonmailCryptoHeaderMessage = '---BEGIN ENCRYPTED MESSAGE---';
var protonmailCryptoTailMessage = '---END ENCRYPTED MESSAGE---';
var protonmailCryptoHeaderRandomKey = '---BEGIN ENCRYPTED RANDOM KEY---';
var protonmailCryptoTailRandomKey = '---END ENCRYPTED RANDOM KEY---';

function getEncMessageFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        var begin = EmailPM.search(protonmailCryptoHeaderMessage) + protonmailCryptoHeaderMessage.length;
        var end = EmailPM.search(protonmailCryptoTailMessage);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}

function getEncRandomKeyFromEmailPM(EmailPM) {
    if (EmailPM !== undefined && typeof EmailPM.search === 'function') {
        var begin = EmailPM.search(protonmailCryptoHeaderRandomKey) + protonmailCryptoHeaderRandomKey.length;
        var end = EmailPM.search(protonmailCryptoTailRandomKey);
        if (begin === -1 || end === -1) return '';
        return EmailPM.substring(begin, end);
    }
    return '';
}

module.exports = {
    getEncMessageFromEmailPM: getEncMessageFromEmailPM,
    getEncRandomKeyFromEmailPM: getEncRandomKeyFromEmailPM
};

},{}],10:[function(require,module,exports){
(function (process){
'use strict';

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var _require = require('../utils'),
    decode_utf8_base64 = _require.decode_utf8_base64,
    binaryStringToArray = _require.binaryStringToArray,
    arrayToBinaryString = _require.arrayToBinaryString,
    serverTime = _require.serverTime;

var _require2 = require('../message/utils'),
    getMessage = _require2.getMessage,
    verifyExpirationTime = _require2.verifyExpirationTime,
    verifyInlineMessage = _require2.verifyInlineMessage;

var _require3 = require('./compat'),
    getEncMessageFromEmailPM = _require3.getEncMessageFromEmailPM,
    getEncRandomKeyFromEmailPM = _require3.getEncRandomKeyFromEmailPM;

var _require4 = require('../constants.js'),
    _require4$VERIFICATIO = _require4.VERIFICATION_STATUS,
    NOT_SIGNED = _require4$VERIFICATIO.NOT_SIGNED,
    SIGNED_AND_VALID = _require4$VERIFICATIO.SIGNED_AND_VALID,
    SIGNED_AND_INVALID = _require4$VERIFICATIO.SIGNED_AND_INVALID;

function decryptMessage(options) {
    var _this = this;

    var _options$verification = options.verificationTime,
        verificationTime = _options$verification === undefined ? false : _options$verification,
        _options$publicKeys = options.publicKeys,
        publicKeys = _options$publicKeys === undefined ? [] : _options$publicKeys,
        _options$isInline = options.isInline,
        isInline = _options$isInline === undefined ? false : _options$isInline;

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return Promise.resolve().then(function () {

        try {
            return openpgp.decrypt(options).then(function () {
                var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(_ref2) {
                    var data = _ref2.data,
                        filename = _ref2.filename,
                        sigs = _ref2.signatures;
                    var verified, signatures, i;
                    return regeneratorRuntime.wrap(function _callee$(_context) {
                        while (1) {
                            switch (_context.prev = _context.next) {
                                case 0:
                                    verified = NOT_SIGNED;
                                    signatures = [];

                                    if (!(sigs && sigs.length)) {
                                        _context.next = 17;
                                        break;
                                    }

                                    verified = SIGNED_AND_INVALID;
                                    i = 0;

                                case 5:
                                    if (!(i < sigs.length)) {
                                        _context.next = 17;
                                        break;
                                    }

                                    _context.t0 = sigs[i].valid;

                                    if (!_context.t0) {
                                        _context.next = 11;
                                        break;
                                    }

                                    _context.next = 10;
                                    return verifyExpirationTime(sigs[i], publicKeys, verificationTime);

                                case 10:
                                    _context.t0 = _context.sent;

                                case 11:
                                    sigs[i].valid = _context.t0;


                                    if (sigs[i].valid) {
                                        verified = SIGNED_AND_VALID;
                                    }
                                    if (sigs[i].valid || !options.publicKeys || !options.publicKeys.length) {
                                        signatures.push(sigs[i].signature);
                                    }

                                case 14:
                                    i++;
                                    _context.next = 5;
                                    break;

                                case 17:
                                    if (!(verified === SIGNED_AND_INVALID && isInline && options.publicKeys && options.publicKeys.length)) {
                                        _context.next = 19;
                                        break;
                                    }

                                    return _context.abrupt('return', verifyInlineMessage(sigs.map(function (_ref3) {
                                        var signature = _ref3.signature;
                                        return signature;
                                    }), publicKeys, data, options.date).then(function (_ref4) {
                                        var data = _ref4.data,
                                            signatures = _ref4.signatures,
                                            verified = _ref4.verified;
                                        return { data: data, signatures: signatures, verified: verified, filename: filename };
                                    }));

                                case 19:
                                    return _context.abrupt('return', { data: data, signatures: signatures, verified: verified, filename: filename });

                                case 20:
                                case 'end':
                                    return _context.stop();
                            }
                        }
                    }, _callee, _this);
                }));

                return function (_x) {
                    return _ref.apply(this, arguments);
                };
            }()).then(function (_ref5) {
                var data = _ref5.data,
                    signatures = _ref5.signatures,
                    verified = _ref5.verified,
                    filename = _ref5.filename;


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

                return { data: data, filename: filename, verified: verified, signatures: signatures };
            }).catch(function (err) {
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

    return Promise.resolve().then(function () {

        if (options.messageTime === undefined || options.messageTime === '') {
            throw new Error('Missing message time');
        }

        var oldEncMessage = getEncMessageFromEmailPM(options.message);
        var oldEncRandomKey = getEncRandomKeyFromEmailPM(options.message);

        // OpenPGP
        if (oldEncMessage === '' || oldEncRandomKey === '') {
            // Convert message string to object
            options.message = getMessage(options.message);
            return decryptMessage(options);
        }

        // Old message encryption format
        var old_options = {
            privateKeys: options.privateKeys,
            message: getMessage(oldEncRandomKey)
        };

        return decryptMessage(old_options).then(function (_ref6) {
            var data = _ref6.data;
            return decode_utf8_base64(data);
        }).then(binaryStringToArray).then(function (randomKey) {

            if (randomKey.length === 0) {
                return Promise.reject(new Error('Random key is empty'));
            }

            oldEncMessage = binaryStringToArray(decode_utf8_base64(oldEncMessage));

            var data = void 0;
            try {
                // cutoff time for enabling multilanguage support
                if (options.messageTime > 1399086120) {
                    data = decode_utf8_base64(arrayToBinaryString(openpgp.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true)));
                } else {
                    data = arrayToBinaryString(openpgp.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true));
                }
            } catch (err) {
                return Promise.reject(err);
            }
            return { data: data, signature: 0 };
        });
    });
}

module.exports = {
    decryptMessage: decryptMessage,
    decryptMessageLegacy: decryptMessageLegacy
};

}).call(this,require('_process'))
},{"../constants.js":2,"../message/utils":11,"../utils":12,"./compat":9,"_process":14}],11:[function(require,module,exports){
'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var verifyExpirationTime = function () {
    var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(_ref2, publicKeys, verificationTime) {
        var keyid = _ref2.keyid;
        var publickey, expirationTime;
        return regeneratorRuntime.wrap(function _callee$(_context) {
            while (1) {
                switch (_context.prev = _context.next) {
                    case 0:
                        if (verificationTime) {
                            _context.next = 2;
                            break;
                        }

                        return _context.abrupt('return', true);

                    case 2:
                        publickey = publicKeys.find(function (pk) {
                            return pk.primaryKey.keyid.bytes === keyid.bytes;
                        });

                        if (publickey) {
                            _context.next = 5;
                            break;
                        }

                        return _context.abrupt('return', false);

                    case 5:
                        _context.next = 7;
                        return publickey.getExpirationTime();

                    case 7:
                        expirationTime = _context.sent;
                        return _context.abrupt('return', expirationTime === null || +expirationTime > verificationTime * 1000);

                    case 9:
                    case 'end':
                        return _context.stop();
                }
            }
        }, _callee, this);
    }));

    return function verifyExpirationTime(_x, _x2, _x3) {
        return _ref.apply(this, arguments);
    };
}();

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var _require = require('../constants.js'),
    _require$VERIFICATION = _require.VERIFICATION_STATUS,
    NOT_SIGNED = _require$VERIFICATION.NOT_SIGNED,
    SIGNED_AND_VALID = _require$VERIFICATION.SIGNED_AND_VALID,
    SIGNED_AND_INVALID = _require$VERIFICATION.SIGNED_AND_INVALID;

var _require2 = require('../utils'),
    serverTime = _require2.serverTime,
    arrayToBinaryString = _require2.arrayToBinaryString;

function getMessage(message) {

    if (openpgp.message.Message.prototype.isPrototypeOf(message)) {
        return message;
    } else if (Uint8Array.prototype.isPrototypeOf(message)) {
        return openpgp.message.read(message);
    } else {
        return openpgp.message.readArmored(message.trim());
    }
}

function getSignature(signature) {

    if (openpgp.signature.Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    } else if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return openpgp.signature.read(signature);
    } else {
        return openpgp.signature.readArmored(signature.trim());
    }
}

function getCleartextMessage(message) {

    if (openpgp.cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    } else {
        return new openpgp.cleartext.CleartextMessage(message);
    }
}

function createMessage(source) {

    if (Uint8Array.prototype.isPrototypeOf(source)) {
        return openpgp.message.fromBinary(source);
    } else {
        return openpgp.message.fromText(source);
    }
}

function signMessage(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp.sign(options).catch(function (err) {
        console.error(err);
        return Promise.reject(err);
    });
}

function verifyMessage(options) {
    var _options$verification = options.verificationTime,
        verificationTime = _options$verification === undefined ? false : _options$verification,
        _options$publicKeys = options.publicKeys,
        publicKeys = _options$publicKeys === undefined ? [] : _options$publicKeys,
        _options$isInline = options.isInline,
        isInline = _options$isInline === undefined ? false : _options$isInline;

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp.verify(options).then(function (_ref3) {
        var data = _ref3.data,
            sigs = _ref3.signatures;

        var verified = NOT_SIGNED;
        var signatures = [];
        if (sigs && sigs.length) {
            verified = SIGNED_AND_INVALID;
            for (var i = 0; i < sigs.length; i++) {
                sigs[i].valid = sigs[i].valid && verifyExpirationTime(sigs[i], publicKeys, verificationTime);

                if (sigs[i].valid) {
                    verified = SIGNED_AND_VALID;
                }
                if (sigs[i].valid || !options.publicKeys || !options.publicKeys.length) {
                    signatures.push(sigs[i].signature);
                }
            }
        }
        if (verified === SIGNED_AND_INVALID && isInline && options.publicKeys && options.publicKeys.length) {
            return verifyInlineMessage(sigs.map(function (_ref4) {
                var signature = _ref4.signature;
                return signature;
            }), publicKeys, arrayToBinaryString(data), options.date);
        }
        return { data: data, verified: verified, signatures: signatures };
    }).catch(function (err) {
        console.error(err);
        return Promise.reject(err);
    });
}

function verifySignatures(signatures, publicKeys, cleartext, date) {
    return Promise.all(signatures.map(function (signature) {
        return verifyMessage({
            message: createMessage(cleartext),
            signature: signature,
            date: date,
            publicKeys: publicKeys
        }).then(function (_ref5) {
            var data = _ref5.data,
                verified = _ref5.verified,
                signatures = _ref5.signatures;
            return { data: arrayToBinaryString(data), verified: verified, signatures: signatures };
        });
    })).then(function (results) {
        var _results$filter = results.filter(function (_ref6) {
            var verified = _ref6.verified;
            return verified === SIGNED_AND_VALID;
        }),
            _results$filter2 = _slicedToArray(_results$filter, 1),
            _results$filter2$ = _results$filter2[0],
            verifiedResult = _results$filter2$ === undefined ? false : _results$filter2$;

        return verifiedResult || { data: cleartext, verified: SIGNED_AND_INVALID, signatures: [] };
    });
}

function verifyInlineMessage(signatures, publicKeys, cleartext, date) {
    return verifySignatures(signatures, publicKeys, cleartext, date).then(function (_ref7) {
        var data = _ref7.data,
            verified = _ref7.verified,
            sigs = _ref7.signatures;

        if (verified !== SIGNED_AND_INVALID) {
            return { data: data, verified: verified, signatures: sigs };
        }
        return verifySignatures(signatures, publicKeys, cleartext.replace(/[\xa0]/g, ' '), date);
    });
}

function splitMessage(message) {

    var msg = getMessage(message);

    var keyFilter = function keyFilter(packet) {
        return packet.tag !== openpgp.enums.packet.publicKeyEncryptedSessionKey && packet.tag !== openpgp.enums.packet.signature && packet.tag !== openpgp.enums.packet.symEncryptedSessionKey && packet.tag !== openpgp.enums.packet.compressed && packet.tag !== openpgp.enums.packet.literal && packet.tag !== openpgp.enums.packet.symmetricallyEncrypted && packet.tag !== openpgp.enums.packet.symEncryptedIntegrityProtected && packet.tag !== openpgp.enums.packet.symEncryptedAEADProtected;
    };

    var splitPackets = function splitPackets(packetList) {
        var packets = [];
        for (var i = 0; i < packetList.length; i++) {
            var newList = new openpgp.packet.List();
            newList.push(packetList[i]);
            packets.push(newList.write());
        }
        return packets;
    };

    var asymmetric = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey));
    var signature = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.signature));
    var symmetric = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.symEncryptedSessionKey));
    var compressed = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.compressed));
    var literal = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.literal));
    var encrypted = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.symmetricallyEncrypted, openpgp.enums.packet.symEncryptedIntegrityProtected, openpgp.enums.packet.symEncryptedAEADProtected));
    var other = splitPackets(msg.packets.filter(keyFilter));

    return {
        asymmetric: asymmetric,
        signature: signature,
        symmetric: symmetric,
        compressed: compressed,
        literal: literal,
        encrypted: encrypted,
        other: other
    };
}

module.exports = {
    signMessage: signMessage,
    verifyMessage: verifyMessage,
    verifyInlineMessage: verifyInlineMessage,
    splitMessage: splitMessage,
    getMessage: getMessage,
    verifyExpirationTime: verifyExpirationTime,
    getSignature: getSignature,
    getCleartextMessage: getCleartextMessage,
    createMessage: createMessage
};

},{"../constants.js":2,"../utils":12}],12:[function(require,module,exports){
'use strict';

// Load window.performance in the browser, perf_hooks in node, and fall back on Date
var _ref = require('perf_hooks') || { performance: window.performance },
    _ref$performance = _ref.performance,
    performance = _ref$performance === undefined ? Date : _ref$performance;

var noop = function noop() {};
var ifDefined = function ifDefined() {
    var cb = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : noop;
    return function (input) {
        if (input !== undefined) {
            return cb(input);
        }
    };
};

var encode_utf8 = ifDefined(function (input) {
    return unescape(encodeURIComponent(input));
});
var decode_utf8 = ifDefined(function (input) {
    return decodeURIComponent(escape(input));
});
var encode_base64 = ifDefined(function (input) {
    return btoa(input).trim();
});
var decode_base64 = ifDefined(function (input) {
    return atob(input.trim());
});
var encode_utf8_base64 = ifDefined(function (input) {
    return encode_base64(encode_utf8(input));
});
var decode_utf8_base64 = ifDefined(function (input) {
    return decode_utf8(decode_base64(input));
});

function binaryStringToArray(str) {
    var bytes = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

function arrayToBinaryString(arr) {
    var result = [];
    for (var i = 0; i < arr.length; i++) {
        result[i] = String.fromCharCode(arr[i]);
    }
    return result.join('');
}

function getHashedPassword(password) {
    return btoa(arrayToBinaryString(openpgp.crypto.hash.sha512(binaryStringToArray(password))));
}

function stripArmor(input) {
    return openpgp.armor.decode(input).data;
}

var lastServerTime = null;
var clientTime = null;

function serverTime() {
    if (lastServerTime !== null) {
        return new Date(+lastServerTime + (performance.now() - clientTime));
    }
    return new Date();
}

function updateServerTime(serverDate) {
    lastServerTime = serverDate;
    clientTime = performance.now();
}

module.exports = {
    encode_utf8: encode_utf8,
    decode_utf8: decode_utf8,
    encode_base64: encode_base64,
    decode_base64: decode_base64,
    encode_utf8_base64: encode_utf8_base64,
    decode_utf8_base64: decode_utf8_base64,
    binaryStringToArray: binaryStringToArray,
    arrayToBinaryString: arrayToBinaryString,
    getHashedPassword: getHashedPassword,
    stripArmor: stripArmor,
    updateServerTime: updateServerTime,
    serverTime: serverTime
};

},{"perf_hooks":13}],13:[function(require,module,exports){

},{}],14:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}]},{},[1]);
