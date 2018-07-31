'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var VERIFICATION_STATUS = {
    NOT_SIGNED: 0,
    SIGNED_AND_VALID: 1,
    SIGNED_AND_INVALID: 2
};

var SIGNATURE_TYPES = {
    BINARY: 0,
    CANONICAL_TEXT: 1
};
var TIME_OFFSET = 200; // ms

/* eslint-disable global-require */
openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;

/* START.NODE_ONLY */
global.btoa = require('btoa');
global.atob = require('atob');
global.Promise = require('es6-promise').Promise;
global.openpgp = require('openpgp');
/* END.NODE_ONLY */

var openpgpjs = openpgp;

// Load window.performance in the browser, perf_hooks in node, and fall back on Date
var getPerformance = function getPerformance() {
    /* START.NODE_ONLY */
    try {
        if (typeof require === 'undefined') {
            return;
        }
        // eslint-disable-next-line global-require
        var result = require('perf_hooks');
        if (result && result.performance) {
            return result.performance;
        }
    } catch (e) {}
    // no-op

    /* END.NODE_ONLY */
    if (window && window.performance) {
        return window.performance;
    }
    return Date;
};

var performance = getPerformance();

var noop = function noop() {};
var ifDefined = function ifDefined() {
    var cb = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : noop;
    return function (input) {
        if (input !== undefined) {
            return cb(input);
        }
    };
};

var encodeUtf8 = ifDefined(openpgpjs.util.encode_utf8);
var decodeUtf8 = ifDefined(openpgpjs.util.decode_utf8);
var encodeBase64 = ifDefined(function (input) {
    return btoa(input).trim();
});
var decodeBase64 = ifDefined(function (input) {
    return atob(input.trim());
});
var encodeUtf8Base64 = ifDefined(function (input) {
    return encodeBase64(encodeUtf8(input));
});
var decodeUtf8Base64 = ifDefined(function (input) {
    return decodeUtf8(decodeBase64(input));
});

var binaryStringToArray = openpgpjs.util.str_to_Uint8Array;
var arrayToBinaryString = openpgpjs.util.Uint8Array_to_str;

function getHashedPassword(password) {
    return btoa(arrayToBinaryString(openpgpjs.crypto.hash.sha512(binaryStringToArray(password))));
}

function stripArmor(input) {
    return openpgpjs.armor.decode(input).data;
}

var lastServerTime = null;
var clientTime = null;

function serverTime() {
    if (lastServerTime !== null) {
        var timeDiff = performance.now() - clientTime;
        /*
         * From the performance.now docs:
         * The timestamp is not actually high-resolution.
         * To mitigate security threats such as Spectre, browsers currently round the result to varying degrees.
         * (Firefox started rounding to 2 milliseconds in Firefox 59.)
         * Some browsers may also slightly randomize the timestamp.
         * The precision may improve again in future releases;
         * browser developers are still investigating these timing attacks and how best to mitigate them.
         */
        var safeTimeDiff = timeDiff < TIME_OFFSET ? 0 : timeDiff - TIME_OFFSET;
        return new Date(+lastServerTime + safeTimeDiff);
    }
    return new Date();
}

function updateServerTime(serverDate) {
    lastServerTime = serverDate;
    clientTime = performance.now();
}

function getMaxConcurrency() {
    var _ref = openpgpjs.getWorker() || {},
        _ref$workers = _ref.workers,
        workers = _ref$workers === undefined ? [null] : _ref$workers;

    return workers.length;
}

var asyncToGenerator = function (fn) {
  return function () {
    var gen = fn.apply(this, arguments);
    return new Promise(function (resolve, reject) {
      function step(key, arg) {
        try {
          var info = gen[key](arg);
          var value = info.value;
        } catch (error) {
          reject(error);
          return;
        }

        if (info.done) {
          resolve(value);
        } else {
          return Promise.resolve(value).then(function (value) {
            step("next", value);
          }, function (err) {
            step("throw", err);
          });
        }
      }

      return step("next");
    });
  };
};

var slicedToArray = function () {
  function sliceIterator(arr, i) {
    var _arr = [];
    var _n = true;
    var _d = false;
    var _e = undefined;

    try {
      for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) {
        _arr.push(_s.value);

        if (i && _arr.length === i) break;
      }
    } catch (err) {
      _d = true;
      _e = err;
    } finally {
      try {
        if (!_n && _i["return"]) _i["return"]();
      } finally {
        if (_d) throw _e;
      }
    }

    return _arr;
  }

  return function (arr, i) {
    if (Array.isArray(arr)) {
      return arr;
    } else if (Symbol.iterator in Object(arr)) {
      return sliceIterator(arr, i);
    } else {
      throw new TypeError("Invalid attempt to destructure non-iterable instance");
    }
  };
}();

// returns promise for generated RSA public and encrypted private keys
var generateKey = function generateKey(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    return openpgpjs.generateKey(options);
};
var generateSessionKey = function generateSessionKey(algorithm) {
    return openpgpjs.crypto.generateSessionKey(algorithm);
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

    return openpgpjs.reformatKey(options).then(function (reformattedKey) {
        return reformattedKey.privateKeyArmored;
    });
}

function getKeys() {
    var rawKeys = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';


    var keys = rawKeys instanceof Uint8Array ? openpgpjs.key.read(rawKeys) : openpgpjs.key.readArmored(rawKeys);

    if (keys === undefined) {
        throw new Error('Cannot parse key(s)');
    }
    if (keys.err) {
        // openpgpjs.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }
    if (keys.keys.length < 1 || keys.keys[0] === undefined) {
        throw new Error('Invalid key(s)');
    }

    return keys.keys;
}

function isExpiredKey(key) {
    return key.getExpirationTime('encrypt_sign').then(function (expirationTime) {
        return !(key.getCreationTime() <= +serverTime() && +serverTime() < expirationTime) || key.revocationSignatures.length > 0;
    });
}

function compressKey(armoredKey) {
    var _getKeys = getKeys(armoredKey),
        _getKeys2 = slicedToArray(_getKeys, 1),
        k = _getKeys2[0];

    var users = k.users;

    users.forEach(function (_ref) {
        var otherCertifications = _ref.otherCertifications;
        return otherCertifications.length = 0;
    });
    return k.armor();
}

function getFingerprint(key) {
    return key.getFingerprint();
}

function getMatchingKey(signature, keys) {
    var keyring = new openpgpjs.Keyring({
        loadPublic: function loadPublic() {
            return keys;
        },
        loadPrivate: function loadPrivate() {
            return [];
        },
        storePublic: function storePublic() {},
        storePrivate: function storePrivate() {}
    });

    // eslint-disable-next-line new-cap
    var keyid = openpgpjs.util.Uint8Array_to_hex(binaryStringToArray(signature.keyid.toHex()));

    var _ref2 = keyring.getKeysForId(keyid, true) || [null],
        _ref3 = slicedToArray(_ref2, 1),
        key = _ref3[0];

    return key;
}

function cloneKey(inputKey) {
    var _getKeys3 = getKeys(inputKey.toPacketlist().write()),
        _getKeys4 = slicedToArray(_getKeys3, 1),
        key = _getKeys4[0];

    return key;
}

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
            return openpgpjs.decryptSessionKeys(options).then(function (result) {

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

function encryptPrivateKey(inputKey, privKeyPassCode) {

    return Promise.resolve(cloneKey(inputKey)).then(function (privKey) {

        if (Object.prototype.toString.call(privKeyPassCode) !== '[object String]' || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        if (!{}.isPrototypeOf.call(openpgpjs.key.Key.prototype, privKey)) {
            return Promise.reject(new Error('Not a Key object'));
        }

        if (!privKey.isPrivate()) {
            return Promise.reject(new Error('Not a private key'));
        }

        if (privKey.keyPacket === null || privKey.subKeys === null || privKey.subKeys.length === 0) {
            return Promise.reject(new Error('Missing primary key or subkey'));
        }

        return privKey.encrypt(privKeyPassCode).then(function () {
            return privKey.armor();
        });
    });
}

var encryptSessionKey = function encryptSessionKey(opt) {
    return openpgpjs.encryptSessionKey(opt);
};

/* eslint-disable no-prototype-builtins */

var NOT_SIGNED = VERIFICATION_STATUS.NOT_SIGNED,
    SIGNED_AND_VALID = VERIFICATION_STATUS.SIGNED_AND_VALID,
    SIGNED_AND_INVALID = VERIFICATION_STATUS.SIGNED_AND_INVALID;
var CANONICAL_TEXT = SIGNATURE_TYPES.CANONICAL_TEXT;


function getMessage(message) {

    if (openpgpjs.message.Message.prototype.isPrototypeOf(message)) {
        return message;
    } else if (Uint8Array.prototype.isPrototypeOf(message)) {
        return openpgpjs.message.read(message);
    } else {
        return openpgpjs.message.readArmored(message.trim());
    }
}

function getSignature(signature) {

    if (openpgpjs.signature.Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    } else if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return openpgpjs.signature.read(signature);
    }
    return openpgpjs.signature.readArmored(signature.trim());
}

function getCleartextMessage(message) {

    if (openpgpjs.cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    } else {
        return new openpgpjs.cleartext.CleartextMessage(message);
    }
}

function createMessage(source) {

    if (Uint8Array.prototype.isPrototypeOf(source)) {
        return openpgpjs.message.fromBinary(source);
    } else {
        return openpgpjs.message.fromText(source);
    }
}

function signMessage(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgpjs.sign(options).catch(function (err) {
        console.error(err);
        return Promise.reject(err);
    });
}

function isCanonicalTextSignature(_ref) {
    var packets = _ref.packets;

    return Object.values(packets).some(function (_ref2) {
        var _ref2$signatureType = _ref2.signatureType,
            signatureType = _ref2$signatureType === undefined ? false : _ref2$signatureType;
        return signatureType === CANONICAL_TEXT;
    });
}

var handleVerificationResult = function () {
    var _ref3 = asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(_ref4, publicKeys, date) {
        var data = _ref4.data,
            _ref4$filename = _ref4.filename,
            filename = _ref4$filename === undefined ? 'msg.txt' : _ref4$filename,
            sigs = _ref4.signatures;
        var verified, signatures, i, verifiableSigs, text, textMessage, verificationPromises, verificationResults;
        return regeneratorRuntime.wrap(function _callee$(_context) {
            while (1) {
                switch (_context.prev = _context.next) {
                    case 0:
                        verified = NOT_SIGNED;
                        signatures = [];

                        if (sigs && sigs.length) {
                            verified = SIGNED_AND_INVALID;
                            for (i = 0; i < sigs.length; i++) {
                                if (sigs[i].valid) {
                                    verified = SIGNED_AND_VALID;
                                }
                                if (sigs[i].valid || !publicKeys.length) {
                                    signatures.push(sigs[i].signature);
                                }
                            }
                        }

                        if (!(verified === SIGNED_AND_INVALID)) {
                            _context.next = 12;
                            break;
                        }

                        // enter extended text mode: some mail clients change spaces into nonbreaking spaces, we'll try to verify by normalizing this too.
                        verifiableSigs = sigs.filter(function (_ref5) {
                            var valid = _ref5.valid;
                            return valid !== null;
                        }).map(function (_ref6) {
                            var signature = _ref6.signature;
                            return signature;
                        }).filter(isCanonicalTextSignature);
                        text = typeof data === 'string' ? data : arrayToBinaryString(data);
                        textMessage = createMessage(text.replace(/[\xa0]/g, ' '));
                        verificationPromises = verifiableSigs.map(function (signature) {
                            return openpgpjs.verify({
                                message: textMessage,
                                publicKeys: publicKeys,
                                signature: signature,
                                date: date
                            }).then(function (_ref7) {
                                var data = _ref7.data,
                                    signatures = _ref7.signatures;
                                return {
                                    data: data,
                                    signatures: signatures.map(function (_ref8) {
                                        var signature = _ref8.signature;
                                        return signature;
                                    }),
                                    verified: signatures[0].valid ? SIGNED_AND_VALID : SIGNED_AND_INVALID
                                };
                            });
                        });
                        _context.next = 10;
                        return Promise.all(verificationPromises);

                    case 10:
                        verificationResults = _context.sent;
                        return _context.abrupt('return', verificationResults.filter(function (_ref9) {
                            var verified = _ref9.verified;
                            return verified === SIGNED_AND_VALID;
                        }).reduceRight(function (acc, result) {
                            if (acc.verified !== SIGNED_AND_VALID) {
                                acc.verified = result.verified;
                                acc.data = arrayToBinaryString(result.data);
                            }
                            acc.signatures = acc.signatures.concat(result.signature);
                            return acc;
                        }, { data: data, verified: verified, filename: filename, signatures: signatures }));

                    case 12:
                        return _context.abrupt('return', { data: data, verified: verified, filename: filename, signatures: signatures });

                    case 13:
                    case 'end':
                        return _context.stop();
                }
            }
        }, _callee, this);
    }));

    return function handleVerificationResult(_x, _x2, _x3) {
        return _ref3.apply(this, arguments);
    };
}();

function verifyMessage(options) {
    var _options$publicKeys = options.publicKeys,
        publicKeys = _options$publicKeys === undefined ? [] : _options$publicKeys;

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgpjs.verify(options).then(function (result) {
        return handleVerificationResult(result, publicKeys, options.date);
    }).then(function (_ref10) {
        var data = _ref10.data,
            verified = _ref10.verified,
            signatures = _ref10.signatures;
        return { data: data, verified: verified, signatures: signatures };
    }).catch(function (err) {
        console.error(err);
        return Promise.reject(err);
    });
}

function splitMessage(message) {

    var msg = getMessage(message);

    var keyFilter = function keyFilter(packet) {
        return packet.tag !== openpgpjs.enums.packet.publicKeyEncryptedSessionKey && packet.tag !== openpgpjs.enums.packet.signature && packet.tag !== openpgpjs.enums.packet.symEncryptedSessionKey && packet.tag !== openpgpjs.enums.packet.compressed && packet.tag !== openpgpjs.enums.packet.literal && packet.tag !== openpgpjs.enums.packet.symmetricallyEncrypted && packet.tag !== openpgpjs.enums.packet.symEncryptedIntegrityProtected && packet.tag !== openpgpjs.enums.packet.symEncryptedAEADProtected;
    };

    var splitPackets = function splitPackets(packetList) {
        var packets = [];
        for (var i = 0; i < packetList.length; i++) {
            var newList = new openpgpjs.packet.List();
            newList.push(packetList[i]);
            packets.push(newList.write());
        }
        return packets;
    };

    var asymmetric = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.publicKeyEncryptedSessionKey));
    var signature = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.signature));
    var symmetric = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.symEncryptedSessionKey));
    var compressed = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.compressed));
    var literal = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.literal));
    var encrypted = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.symmetricallyEncrypted, openpgpjs.enums.packet.symEncryptedIntegrityProtected, openpgpjs.enums.packet.symEncryptedAEADProtected));
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

function decryptMessage(options) {
    var _options$publicKeys = options.publicKeys,
        publicKeys = _options$publicKeys === undefined ? [] : _options$publicKeys;

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return Promise.resolve().then(function () {

        try {
            return openpgpjs.decrypt(options).then(function (result) {
                return handleVerificationResult(result, publicKeys, options.date);
            }).then(function (_ref) {
                var data = _ref.data,
                    filename = _ref.filename,
                    verified = _ref.verified,
                    signatures = _ref.signatures;

                return {
                    data: data, filename: filename, verified: verified, signatures: signatures
                };
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

        if (options.date === undefined || !(options.date instanceof Date)) {
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
        var oldOptions = {
            privateKeys: options.privateKeys,
            message: getMessage(oldEncRandomKey)
        };

        return decryptMessage(oldOptions).then(function (_ref2) {
            var data = _ref2.data;
            return decodeUtf8Base64(data);
        }).then(binaryStringToArray).then(function (randomKey) {

            if (randomKey.length === 0) {
                return Promise.reject(new Error('Random key is empty'));
            }

            oldEncMessage = binaryStringToArray(decodeUtf8Base64(oldEncMessage));

            var data = void 0;
            try {
                // cutoff time for enabling multilanguage support
                if (+options.date > 1399086120000) {
                    data = decodeUtf8Base64(arrayToBinaryString(openpgpjs.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true)));
                } else {
                    data = arrayToBinaryString(openpgpjs.crypto.cfb.decrypt('aes256', randomKey, oldEncMessage, true));
                }
            } catch (err) {
                return Promise.reject(err);
            }
            return { data: data, signature: 0 };
        });
    });
}

function encryptMessage(options) {
    if (typeof options.data === 'string') {
        options.data = options.data.replace(/[ \t]*$/mg, '');
    }
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? openpgpjs.enums.compression.zlib : undefined;
    return openpgpjs.encrypt(options);
}

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
        if (info.user.hash[0] !== openpgpjs.enums.hash.sha256) {
            throw new Error('Preferred hash algorithm must be SHA256');
        }
    } else {
        throw new Error('Key missing preferred hash algorithms');
    }

    // Symmetric algorithms
    if (info.user.symmetric && info.user.symmetric.length) {
        if (info.user.symmetric[0] !== openpgpjs.enums.symmetric.aes256) {
            throw new Error('Preferred symmetric algorithm must be AES256');
        }
    } else {
        throw new Error('Key missing preferred symmetric algorithms');
    }

    // Compression algorithms
    if (info.user.compression && info.user.compression.length) {
        if (info.user.compression[0] !== openpgpjs.enums.compression.zlib) {
            throw new Error('Preferred compression algorithm must be zlib');
        }
    }

    return info;
}

var _this = undefined;

var packetInfo = function () {
    var _ref = asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(packet, key) {
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

                        _context.t0 = openpgpjs.enums.publicKey[packet.algorithm];
                        _context.next = 9;
                        return key.subKeys[i].getExpirationTime('encrypt_sign');

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
                        _context.t2 = openpgpjs.enums.publicKey[packet.algorithm];
                        _context.next = 17;
                        return key.getExpirationTime('encrypt_sign');

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

    return function packetInfo(_x, _x2) {
        return _ref.apply(this, arguments);
    };
}();

var primaryUser = function () {
    var _ref2 = asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee2(key, date) {
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

    return function primaryUser(_x3, _x4) {
        return _ref2.apply(this, arguments);
    };
}();

var info = (function () {
    var _ref3 = asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee3(rawKey, email) {
        var expectEncrypted = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;
        var date = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : serverTime();
        var keys, algoInfo, obj, encryptCheck;
        return regeneratorRuntime.wrap(function _callee3$(_context3) {
            while (1) {
                switch (_context3.prev = _context3.next) {
                    case 0:
                        _context3.next = 2;
                        return getKeys(rawKey);

                    case 2:
                        keys = _context3.sent;
                        algoInfo = keys[0].getAlgorithmInfo();
                        _context3.t0 = keys[0].primaryKey.version;
                        _context3.t1 = keys[0].toPublic().armor();
                        _context3.t2 = keys[0].getFingerprint();
                        _context3.t3 = keys[0].getUserIds();
                        _context3.next = 10;
                        return primaryUser(keys[0], date);

                    case 10:
                        _context3.t4 = _context3.sent;
                        _context3.t5 = algoInfo.bits || null;
                        _context3.t6 = algoInfo.curve || null;
                        _context3.t7 = keys[0].getCreationTime();
                        _context3.t8 = openpgpjs.enums.publicKey[algoInfo.algorithm];
                        _context3.t9 = algoInfo.algorithm;
                        _context3.next = 18;
                        return keys[0].getExpirationTime('encrypt_sign').catch(function () {
                            return null;
                        });

                    case 18:
                        _context3.t10 = _context3.sent;
                        _context3.t11 = packetInfo;
                        _context3.next = 22;
                        return keys[0].getEncryptionKey(undefined, date);

                    case 22:
                        _context3.t12 = _context3.sent;
                        _context3.t13 = keys[0];
                        _context3.next = 26;
                        return (0, _context3.t11)(_context3.t12, _context3.t13);

                    case 26:
                        _context3.t14 = _context3.sent;
                        _context3.t15 = packetInfo;
                        _context3.next = 30;
                        return keys[0].getSigningKey(undefined, date);

                    case 30:
                        _context3.t16 = _context3.sent;
                        _context3.t17 = keys[0];
                        _context3.next = 34;
                        return (0, _context3.t15)(_context3.t16, _context3.t17);

                    case 34:
                        _context3.t18 = _context3.sent;
                        _context3.t19 = keys[0].isDecrypted();
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

                        encryptCheck = obj.encrypt ? openpgpjs.encrypt({ data: 'test message', publicKeys: keys, date: date }) : Promise.resolve();
                        _context3.next = 42;
                        return encryptCheck;

                    case 42:
                        return _context3.abrupt('return', obj);

                    case 43:
                    case 'end':
                        return _context3.stop();
                }
            }
        }, _callee3, this);
    }));

    function keyInfo(_x5, _x6) {
        return _ref3.apply(this, arguments);
    }

    return keyInfo;
})();

/* eslint-disable camelcase */

var config = { debug: true };
var concatArrays = openpgpjs.util.concatUint8Array;
var encode_utf8 = encodeUtf8;
var decode_utf8 = decodeUtf8;
var encode_base64 = encodeBase64;
var decode_base64 = decodeBase64;
var encode_utf8_base64 = encodeUtf8Base64;
var decode_utf8_base64 = decodeUtf8Base64;

var pmcrypto = /*#__PURE__*/Object.freeze({
    config: config,
    cloneKey: cloneKey,
    generateKey: generateKey,
    getKeys: getKeys,
    updateServerTime: updateServerTime,
    getMaxConcurrency: getMaxConcurrency,
    reformatKey: reformatKey,
    generateSessionKey: generateSessionKey,
    isExpiredKey: isExpiredKey,
    encryptSessionKey: encryptSessionKey,
    decryptSessionKey: decryptSessionKey,
    encryptPrivateKey: encryptPrivateKey,
    decryptPrivateKey: decryptPrivateKey,
    compressKey: compressKey,
    getMessage: getMessage,
    getSignature: getSignature,
    signMessage: signMessage,
    splitMessage: splitMessage,
    verifyMessage: verifyMessage,
    getCleartextMessage: getCleartextMessage,
    createMessage: createMessage,
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    decryptMessageLegacy: decryptMessageLegacy,
    encodeUtf8: encodeUtf8,
    encode_utf8: encode_utf8,
    decodeUtf8: decodeUtf8,
    decode_utf8: decode_utf8,
    encodeBase64: encodeBase64,
    encode_base64: encode_base64,
    decodeBase64: decodeBase64,
    decode_base64: decode_base64,
    encodeUtf8Base64: encodeUtf8Base64,
    encode_utf8_base64: encode_utf8_base64,
    decodeUtf8Base64: decodeUtf8Base64,
    decode_utf8_base64: decode_utf8_base64,
    getHashedPassword: getHashedPassword,
    arrayToBinaryString: arrayToBinaryString,
    binaryStringToArray: binaryStringToArray,
    concatArrays: concatArrays,
    stripArmor: stripArmor,
    keyInfo: info,
    keyCheck: keyCheck,
    getFingerprint: getFingerprint,
    getMatchingKey: getMatchingKey
});

exports.default = pmcrypto;
exports.config = config;
exports.cloneKey = cloneKey;
exports.generateKey = generateKey;
exports.getKeys = getKeys;
exports.updateServerTime = updateServerTime;
exports.getMaxConcurrency = getMaxConcurrency;
exports.reformatKey = reformatKey;
exports.generateSessionKey = generateSessionKey;
exports.isExpiredKey = isExpiredKey;
exports.encryptSessionKey = encryptSessionKey;
exports.decryptSessionKey = decryptSessionKey;
exports.encryptPrivateKey = encryptPrivateKey;
exports.decryptPrivateKey = decryptPrivateKey;
exports.compressKey = compressKey;
exports.getMessage = getMessage;
exports.getSignature = getSignature;
exports.signMessage = signMessage;
exports.splitMessage = splitMessage;
exports.verifyMessage = verifyMessage;
exports.getCleartextMessage = getCleartextMessage;
exports.createMessage = createMessage;
exports.encryptMessage = encryptMessage;
exports.decryptMessage = decryptMessage;
exports.decryptMessageLegacy = decryptMessageLegacy;
exports.encodeUtf8 = encodeUtf8;
exports.encode_utf8 = encode_utf8;
exports.decodeUtf8 = decodeUtf8;
exports.decode_utf8 = decode_utf8;
exports.encodeBase64 = encodeBase64;
exports.encode_base64 = encode_base64;
exports.decodeBase64 = decodeBase64;
exports.decode_base64 = decode_base64;
exports.encodeUtf8Base64 = encodeUtf8Base64;
exports.encode_utf8_base64 = encode_utf8_base64;
exports.decodeUtf8Base64 = decodeUtf8Base64;
exports.decode_utf8_base64 = decode_utf8_base64;
exports.getHashedPassword = getHashedPassword;
exports.arrayToBinaryString = arrayToBinaryString;
exports.binaryStringToArray = binaryStringToArray;
exports.concatArrays = concatArrays;
exports.stripArmor = stripArmor;
exports.keyInfo = info;
exports.keyCheck = keyCheck;
exports.getFingerprint = getFingerprint;
exports.getMatchingKey = getMatchingKey;
