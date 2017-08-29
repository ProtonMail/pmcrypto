(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;
openpgp.initWorker({ path: 'openpgp.worker.min.js' });

window.pmcrypto = require('./index');

},{"./index":2}],2:[function(require,module,exports){
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

},{"./key/check":3,"./key/decrypt":4,"./key/encrypt":5,"./key/info":6,"./key/utils":7,"./message/decrypt":9,"./message/encrypt":10,"./message/utils":11,"./utils":12}],3:[function(require,module,exports){
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

    if (info.bitSize < 1024) {
        throw new Error('Key is less than 1024 bits');
    }

    if (info.expires) {
        throw new Error('Key will expire');
    }

    if (!info.encrypt) {
        throw new Error('Key cannot be used for encryption');
    }

    if (info.encrypt.expires) {
        throw new Error('Key will expire');
    }

    if (info.revocationSignature !== null) {
        throw new Error('Key is revoked');
    }

    if (!info.sign) {
        throw new Error('Key cannot be used for signing');
    }

    if (info.sign.expires) {
        throw new Error('Key will expire');
    }

    // Algorithm check for RSA
    if (info.algorithm !== openpgp.enums.publicKey.rsa_encrypt_sign && info.algorithm !== openpgp.enums.publicKey.rsa_sign || info.encrypt.algorithm !== openpgp.enums.publicKey.rsa_encrypt_sign && info.encrypt.algorithm !== openpgp.enums.publicKey.rsa_encrypt || info.sign.algorithm !== openpgp.enums.publicKey.rsa_encrypt_sign && info.sign.algorithm !== openpgp.enums.publicKey.rsa_sign) {
        throw new Error('Key asymmetric algorithms must be RSA');
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

},{}],4:[function(require,module,exports){
'use strict';

var _require = require('./utils'),
    getKeys = _require.getKeys,
    pickPrivate = _require.pickPrivate;

function decryptPrivateKey(privKey, privKeyPassCode) {

    return Promise.resolve().then(function () {

        if (privKey === undefined || privKey === '') {
            return Promise.reject(new Error('Missing private key'));
        }
        if (privKeyPassCode === undefined || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        var keys = getKeys(privKey);

        if (keys[0].decrypt(privKeyPassCode)) {
            return keys[0];
        }

        return Promise.reject(new Error('Private key decryption failed')); // Do NOT make this an Error object
    });
}

function decryptSessionKey(options) {

    return Promise.resolve().then(function () {

        options = pickPrivate(options);

        try {
            return openpgp.decryptSessionKey(options).then(function (result) {

                // FIXME this should be in openpgp.js
                if (!result) {
                    return Promise.reject(new Error('Invalid session key for decryption'));
                }

                return result;
            }).catch(function (err) {
                console.log(err);
                return Promise.reject(new Error('Session key decryption failed'));
            });
        } catch (err) {
            if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
                return Promise.reject(new Error('Incorrect message password')); // Bad password, reject without Error object
            }
            return Promise.reject(err);
        }
    });
}

module.exports = { decryptPrivateKey: decryptPrivateKey, decryptSessionKey: decryptSessionKey };

},{"./utils":7}],5:[function(require,module,exports){
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
        privKey.subKeys[0].subKey.encrypt(privKeyPassCode);
        return privKey.armor();
    });
}

var encryptSessionKey = function encryptSessionKey(opt) {
    return openpgp.encryptSessionKey(opt);
};

module.exports = {
    encryptPrivateKey: encryptPrivateKey,
    encryptSessionKey: encryptSessionKey
};

},{}],6:[function(require,module,exports){
'use strict';

var keyCheck = require('./check');
var encryptMessage = require('../message/encrypt');

var _require = require('./utils'),
    getKeys = _require.getKeys;

function keyInfo(privKey, email) {
    var expectEncrypted = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;


    return Promise.resolve().then(function () {

        var packetInfo = function packetInfo(packet, key) {
            if (!packet) {
                return null;
            }

            if (key.subKeys) {
                for (var i = 0; i < key.subKeys.length; i++) {
                    if (packet === key.subKeys[i].subKey) {
                        return {
                            algorithm: openpgp.enums.publicKey[packet.algorithm],
                            expires: key.subKeys[i].getExpirationTime()
                        };
                    }
                }
            }

            // Packet must be primary key
            return {
                algorithm: openpgp.enums.publicKey[packet.algorithm],
                expires: key.getExpirationTime()
            };
        };

        var primaryUser = function primaryUser(key) {

            var primary = key.getPrimaryUser();
            if (!primary) {
                return null;
            }

            if (!primary.user) {
                return null;
            }

            if (!primary.selfCertificate) {
                return null;
            }

            var cert = primary.selfCertificate;

            return {
                userId: primary.user.userId.userid,
                symmetric: cert.preferredSymmetricAlgorithms ? cert.preferredSymmetricAlgorithms : [],
                hash: cert.preferredHashAlgorithms ? cert.preferredHashAlgorithms : [],
                compression: cert.preferredCompressionAlgorithms ? cert.preferredCompressionAlgorithms : []
            };
        };

        var keys = getKeys(privKey);

        var obj = {
            version: keys[0].primaryKey.version,
            publicKeyArmored: keys[0].toPublic().armor(),
            fingerprint: keys[0].primaryKey.getFingerprint(),
            userIds: keys[0].getUserIds(),
            user: primaryUser(keys[0]),
            bitSize: keys[0].primaryKey.getBitSize(),
            created: keys[0].primaryKey.created,
            algorithm: openpgp.enums.publicKey[keys[0].primaryKey.algorithm],
            expires: keys[0].getExpirationTime(),
            encrypt: packetInfo(keys[0].getEncryptionKeyPacket(), keys[0]),
            sign: packetInfo(keys[0].getSigningKeyPacket(), keys[0]),
            decrypted: keys[0].primaryKey.isDecrypted, // null if public key
            revocationSignature: keys[0].revocationSignature,
            validationError: null
        };

        try {
            keyCheck(obj, email, expectEncrypted);
        } catch (err) {
            obj.validationError = err.message;
        }

        return encryptMessage({ data: 'test message', publicKeys: keys }).then(function () {
            return obj;
        });
    });
}

module.exports = keyInfo;

},{"../message/encrypt":10,"./check":3,"./utils":7}],7:[function(require,module,exports){
'use strict';

// returns promise for generated RSA public and encrypted private keys
var generateKey = function generateKey(opt) {
    return openpgp.generateKey(opt);
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
    var armoredKeys = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';


    var keys = openpgp.key.readArmored(armoredKeys);

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

function pickPrivate(options) {

    if (options.privateKeys) {
        // Pick correct private key
        var encryptionKeyIds = options.message.getEncryptionKeyIds();
        if (!encryptionKeyIds.length) {
            throw new Error('No asymmetric session key packets found');
        }

        for (var i = 0; i < options.privateKeys.length; i++) {
            if (options.privateKeys[i].getKeyPacket(encryptionKeyIds) !== null) {
                options.privateKey = options.privateKeys[i];
                break;
            }
        }
    }

    delete options.privateKeys;

    return options;
}

module.exports = {
    pickPrivate: pickPrivate,
    generateKey: generateKey,
    generateSessionKey: generateSessionKey,
    reformatKey: reformatKey,
    getKeys: getKeys
};

},{}],8:[function(require,module,exports){
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

},{}],9:[function(require,module,exports){
(function (process){
'use strict';

var _require = require('../utils'),
    decode_utf8_base64 = _require.decode_utf8_base64,
    binaryStringToArray = _require.binaryStringToArray,
    arrayToBinaryString = _require.arrayToBinaryString;

var _require2 = require('../key/utils'),
    pickPrivate = _require2.pickPrivate;

var _require3 = require('./compat'),
    getEncMessageFromEmailPM = _require3.getEncMessageFromEmailPM,
    getEncRandomKeyFromEmailPM = _require3.getEncRandomKeyFromEmailPM;

function decryptMessage(options) {

    return Promise.resolve().then(function () {

        options = pickPrivate(options);

        try {
            return openpgp.decrypt(options).then(function (_ref) {
                var data = _ref.data,
                    filename = _ref.filename,
                    sigs = _ref.signatures;


                var verified = 0;
                var signatures = [];
                if (sigs) {
                    verified = 2;
                    for (var i = 0; i < sigs.length; i++) {
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

                return { data: data, filename: filename, verified: verified, signatures: signatures };
            }).catch(function (err) {
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

    return Promise.resolve().then(function () {

        if (options.messageTime === undefined || options.messageTime === '') {
            throw new Error('Missing message time');
        }

        var oldEncMessage = getEncMessageFromEmailPM(options.message);
        var oldEncRandomKey = getEncRandomKeyFromEmailPM(options.message);

        // OpenPGP
        if (oldEncMessage === '' || oldEncRandomKey === '') return decryptMessage(options);

        // Old message encryption format
        var old_options = {
            privateKeys: options.privateKeys,
            message: oldEncRandomKey
        };

        return decryptMessage(old_options).then(function (_ref2) {
            var data = _ref2.data;
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
},{"../key/utils":7,"../utils":12,"./compat":8,"_process":13}],10:[function(require,module,exports){
"use strict";

function encryptMessage(options) {

    return openpgp.encrypt(options).catch(function (err) {
        // Try without signing
        if (options.privateKeys && options.privateKeys.length) {
            options.privateKeys = [];
            return openpgp.encrypt(options);
        }
        return Promise.reject(err);
    });
}

module.exports = encryptMessage;

},{}],11:[function(require,module,exports){
'use strict';

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

function signMessage(options) {

    return openpgp.sign(options).catch(function (err) {
        console.log(err);
        return Promise.reject(new Error('Message signing failed'));
    });
}

function verifyMessage(options) {

    return openpgp.verify(options).catch(function (err) {
        console.log(err);
        return Promise.reject(new Error('Message verification failed'));
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
    splitMessage: splitMessage,
    getMessage: getMessage,
    getSignature: getSignature
};

},{}],12:[function(require,module,exports){
'use strict';

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

module.exports = {
    encode_utf8: encode_utf8,
    decode_utf8: decode_utf8,
    encode_base64: encode_base64,
    decode_base64: decode_base64,
    encode_utf8_base64: encode_utf8_base64,
    decode_utf8_base64: decode_utf8_base64,
    binaryStringToArray: binaryStringToArray,
    arrayToBinaryString: arrayToBinaryString,
    getHashedPassword: getHashedPassword
};

},{}],13:[function(require,module,exports){
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
