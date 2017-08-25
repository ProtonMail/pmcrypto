'use strict';

/*
 * Be VERY careful about changing this file. It is used in both the browser JS package and in the node.js encryption server
 * Just because your changes work in the browser does not mean they work in the encryption server!
 */

if (typeof module !== 'undefined' && module.exports) {
    // node.js
    /* eslint { "no-global-assign": "off", "import/no-extraneous-dependencies": "off", "import/no-unresolved": "off", "global-require" : "off" } */
    btoa = require('btoa');
    atob = require('atob');
    Promise = require('es6-promise').Promise;
    openpgp = require('openpgp');
} else {
    // Browser
    openpgp.config.integrity_protect = true;
    openpgp.initWorker({ path: 'openpgp.worker.min.js' });
}

openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;

var pmcrypto = function pmcrypto() {

    var config = {
        debug: true

        // Deprecated, backwards compatibility
    };var protonmailCryptoHeaderMessage = '---BEGIN ENCRYPTED MESSAGE---';
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

    // Current
    function encode_utf8(data) {
        if (data !== undefined) return unescape(encodeURIComponent(data));
    }

    function decode_utf8(data) {
        if (data !== undefined) return decodeURIComponent(escape(data));
    }

    function encode_base64(data) {
        if (data !== undefined) return btoa(data).trim();
    }

    function decode_base64(data) {
        if (data !== undefined) return atob(data.trim());
    }

    function encode_utf8_base64(data) {
        if (data !== undefined) return encode_base64(encode_utf8(data));
    }

    function decode_utf8_base64(data) {
        if (data !== undefined) return decode_utf8(decode_base64(data));
    }

    function generateKey(options) {

        return openpgp.generateKey(options);
    }

    function generateSessionKey(algorithm) {
        return openpgp.crypto.generateSessionKey(algorithm);
    }

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

    function encryptSessionKey(options) {

        return openpgp.encryptSessionKey(options);
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

    // Backwards-compatible decrypt message function
    function decryptMessageLegacy(options) {

        return Promise.resolve().then(function () {

            if (messageTime === undefined || messageTime === '') {
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

            return decryptMessage(old_options).then(function (_ref) {
                var data = _ref.data;
                return decode_utf8_base64(data);
            }).then(binaryStringToArray).then(function (randomKey) {

                if (randomKey.length === 0) {
                    return Promise.reject(new Error('Random key is empty'));
                }

                oldEncMessage = binaryStringToArray(decode_utf8_base64(oldEncMessage));

                var data = void 0;
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
                return { data: data, signature: 0 };
            });
        });
    }

    function decryptMessage(options) {

        return Promise.resolve().then(function () {

            options = pickPrivate(options);

            try {
                return openpgp.decrypt(options).then(function (_ref2) {
                    var data = _ref2.data,
                        filename = _ref2.filename,
                        sigs = _ref2.signatures;


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
                    if (config.debug) {
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

    function getHashedPassword(password) {
        return btoa(arrayToBinaryString(openpgp.crypto.hash.sha512(binaryStringToArray(password))));
    }

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

    return {
        // config
        config: config,

        // returns promise for generated RSA public and encrypted private keys
        generateKey: generateKey,

        // Get keys
        getKeys: getKeys,

        // Private key
        encryptPrivateKey: encryptPrivateKey,
        decryptPrivateKey: decryptPrivateKey,

        // Get message/signature
        getMessage: getMessage,
        getSignature: getSignature,

        // returns a promise, reject with Error
        encryptMessage: encryptMessage,
        decryptMessage: decryptMessage,
        decryptMessageLegacy: decryptMessageLegacy, // Backwards compatibility wrapper
        signMessage: signMessage,
        verifyMessage: verifyMessage,

        // Split existing encrypted message by packet type
        splitMessage: splitMessage,

        // Session key generation
        generateSessionKey: generateSessionKey,

        // Session key manipulation
        encryptSessionKey: encryptSessionKey,
        decryptSessionKey: decryptSessionKey,

        // Reformat key
        reformatKey: reformatKey,

        // Login page
        getHashedPassword: getHashedPassword,

        // Javascript string to/from base64-encoded and/or UTF8
        encode_utf8: encode_utf8,
        decode_utf8: decode_utf8,
        encode_base64: encode_base64,
        decode_base64: decode_base64,
        encode_utf8_base64: encode_utf8_base64,
        decode_utf8_base64: decode_utf8_base64,

        // Typed array/binary string conversions
        arrayToBinaryString: arrayToBinaryString,
        binaryStringToArray: binaryStringToArray,
        concatArrays: openpgp.util.concatUint8Array,

        // Dump key information
        keyInfo: keyInfo,
        keyCheck: keyCheck
    };
}();

// node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = pmcrypto;
}