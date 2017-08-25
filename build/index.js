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

    /*
     * The safari tab seems to crash sometimes when using a webworker. This is a bug that was filed to Apple.
     * But until Apple fixes this bug we can turn off the webworker to prevent this from happening.
     * As soon as Apple fixes their bug we should use the webworker again, as it can causes the browser to hang
     * when the user has a lot of addresses/public keys.
     */
    var browsers = ['Safari', 'Mobile Safari'];
    if (!_.contains(browsers, $.ua.browser.name)) {
        openpgp.initWorker({ path: 'openpgp.worker.min.js' });
    }
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

    // Backwards-compatible decrypt RSA message function
    function decryptMessageRSA(encMessage, privKey, messageTime, pubKeys) {
        return new Promise(function (resolve, reject) {

            if (encMessage === undefined || encMessage === '') {
                return reject(new Error('Missing encrypted message'));
            }
            if (privKey === undefined || privKey === '') {
                return reject(new Error('Missing private key'));
            }
            if (messageTime === undefined || messageTime === '') {
                return reject(new Error('Missing message time'));
            }

            var oldEncMessage = getEncMessageFromEmailPM(encMessage);
            var oldEncRandomKey = getEncRandomKeyFromEmailPM(encMessage);

            // OpenPGP
            if (oldEncMessage === '' || oldEncRandomKey === '') return resolve(decryptMessage(encMessage, privKey, false, null, pubKeys));

            // Old message encryption format
            resolve(decryptMessage(oldEncRandomKey, privKey, false).then(function (_ref) {
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
            }));
        });
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

    function generateKeysRSA() {
        var email = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
        var passphrase = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
        var numBits = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 2048;


        if (passphrase.length === 0) {
            return Promise.reject('Missing private key passcode');
        }

        var user = {
            name: email,
            email: email
        };

        return openpgp.generateKey({
            numBits: numBits,
            userIds: [user],
            passphrase: passphrase
        });
    }

    function generateKeyAES() {
        return openpgp.crypto.generateSessionKey('aes256');
    }

    function reformatKey(privKey) {
        var email = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
        var passphrase = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : '';


        if (passphrase.length === 0) {
            return Promise.reject('Missing private key passcode');
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

        var keys = void 0;
        try {
            keys = openpgp.key.readArmored(armoredKeys);
        } catch (err) {
            return err;
        }

        if (keys === undefined) {
            return new Error('Cannot parse key(s)');
        }
        if (keys.err) {
            // openpgp.key.readArmored returns error arrays.
            return new Error(keys.err[0].message);
        }
        if (keys.keys.length < 1 || keys.keys[0] === undefined) {
            return new Error('Invalid key(s)');
        }

        return keys.keys;
    }

    // privKeys is optional - will also sign the message
    function encryptMessage() {
        var message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
        var pubKeys = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
        var passwords = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : [];
        var privKeys = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : [];

        return new Promise(function (resolve, reject) {
            if (message === undefined) {
                return reject(new Error('Missing data'));
            }
            if (pubKeys === undefined && passwords === undefined) {
                return reject(new Error('Missing key'));
            }

            var options = {
                data: message,
                armor: true
            };

            if (pubKeys && pubKeys.length) {
                var keys = getKeys(pubKeys);
                if (keys instanceof Error) return reject(keys);
                options.publicKeys = keys;
            }

            if (passwords) {
                if (!(passwords instanceof Array)) {
                    options.passwords = [passwords];
                } else {
                    options.passwords = passwords;
                }
            }

            if (privKeys) {
                options.privateKeys = privKeys[0];
            }

            openpgp.encrypt(options).then(function (ciphertext) {
                resolve(ciphertext.data);
            }).catch(function (err) {
                if (privKeys) {
                    options.privateKeys = [];
                }
                openpgp.encrypt(options).then(function (ciphertext) {
                    resolve(ciphertext.data);
                });
            });
        });
    }

    // when attachment signing is implemented, use the privKeys parameter
    function encryptFile(data, pubKeys, passwords, filename, privKeys) {
        return new Promise(function (resolve, reject) {
            if (data === undefined) {
                return reject(new Error('Missing data'));
            }
            if (pubKeys === undefined && passwords === undefined) {
                return reject(new Error('Missing key'));
            }

            var options = {
                filename: filename,
                data: data,
                armor: false
            };

            if (pubKeys && pubKeys.length) {
                var keys = getKeys(pubKeys);
                if (keys instanceof Error) return reject(keys);
                options.publicKeys = keys;
            }

            if (passwords) {
                if (!(passwords instanceof Array)) {
                    options.passwords = [passwords];
                } else {
                    options.passwords = passwords;
                }
            }

            if (privKeys) {
                // Sign with primary (first) key in array
                options.privateKeys = privKeys[0];
            }

            openpgp.encrypt(options).then(function (ciphertext) {
                resolve(splitFile(ciphertext.message));
            }).catch(function (err) {
                if (privKeys) {
                    options.privateKeys = [];
                }
                openpgp.encrypt(options).then(function (ciphertext) {
                    resolve(splitFile(ciphertext.message));
                });
            });
        });
    }

    function encryptSessionKey(sessionKey, algo, pubKeys, passwords) {

        return new Promise(function (resolve, reject) {
            if (sessionKey === undefined) {
                return reject(new Error('Missing session key'));
            }
            if (algo === undefined) {
                return reject(new Error('Missing session key algorithm'));
            }
            if (pubKeys === undefined && passwords === undefined) {
                return reject(new Error('Missing key'));
            }
            if (sessionKey.length !== 32) {
                return reject(new Error('Invalid session key length'));
            }

            var options = {
                data: sessionKey,
                algorithm: algo
            };

            if (pubKeys && pubKeys.length) {
                var keys = getKeys(pubKeys);
                if (keys instanceof Error) return reject(keys);
                options.publicKeys = keys;
            }

            if (passwords) {
                if (!(passwords instanceof Array)) {
                    options.passwords = [passwords];
                } else {
                    options.passwords = passwords;
                }
            }
            openpgp.encryptSessionKey(options).then(function (result) {
                resolve(result.message.packets.write());
            });
        });
    }

    // public keys optional, for verifying signature
    // returns an object { message, signature }
    function decryptMessage(encMessage, privKey, binary, sessionKeyAlgorithm, publicKeys) {
        return new Promise(function (resolve, reject) {

            if (encMessage === undefined || encMessage === '') {
                return reject(new Error('Missing encrypted message'));
            }
            if (privKey === undefined || privKey === '') {
                return reject(new Error('Missing private key'));
            }
            var message = void 0;
            if ({}.isPrototypeOf.call(Uint8Array.prototype, encMessage)) {
                message = openpgp.message.read(encMessage);
            } else {
                message = openpgp.message.readArmored(encMessage.trim());
            }

            var privateKey = privKey;
            if (Array.isArray(privateKey)) {
                // Pick correct key
                if (privKey.length === 0) {
                    return reject(new Error('Empty key array'));
                }

                var encryptionKeyIds = message.getEncryptionKeyIds();
                if (!encryptionKeyIds.length) {
                    return reject(new Error('Nothing to decrypt'));
                }

                var privateKeyPacket = null;
                for (var i = 0; i < privateKey.length; i++) {
                    privateKeyPacket = privKey[i].getKeyPacket(encryptionKeyIds);
                    if (privateKeyPacket !== null) {
                        privateKey = privKey[i];
                        break;
                    }
                }
                if (privateKeyPacket == null) {
                    return reject(new Error('No appropriate private key found.'));
                }
            }

            var options = {
                message: message
            };

            if (publicKeys) {
                var keys = getKeys(publicKeys);
                if (keys instanceof Error) return reject(keys);
                options.publicKeys = keys;
            }

            if ({}.isPrototypeOf.call(Uint8Array.prototype, privateKey)) {
                options.sessionKey = { data: privateKey, algorithm: sessionKeyAlgorithm };
            } else if (typeof privateKey === 'string' || privateKey instanceof String) {
                options.password = privateKey;
            } else {
                options.privateKey = privateKey;
            }

            if (binary) {
                options.format = 'binary';
            }

            var sig = void 0;

            try {
                openpgp.decrypt(options).then(function (decrypted) {
                    // for now, log signature info in console - later integrate with front end
                    if (binary) {
                        if (decrypted.signatures == null || decrypted.signatures[0] == null) {
                            if (config.debug) {
                                console.log('No attachment signature present');
                            }
                            sig = 0;
                        } else if (decrypted.signatures[0].valid) {
                            if (config.debug) {
                                console.log('Verified attachment signature');
                            }
                            sig = 1;
                        } else {
                            if (config.debug) {
                                console.log('Attachment signature could not be verified');
                            }
                            sig = 2;
                        }
                        resolve({ data: decrypted.data, filename: decrypted.filename, signature: sig });
                    } else {
                        if (decrypted.signatures == null || decrypted.signatures[0] == null) {
                            if (config.debug) {
                                console.log('No message signature present');
                            }
                            sig = 0;
                        } else if (decrypted.signatures[0].valid) {
                            if (config.debug) {
                                console.log('Verified message signature');
                            }
                            sig = 1;
                        } else {
                            if (config.debug) {
                                console.log('Message signature could not be verified');
                            }
                            sig = 2;
                        }
                        resolve({ data: decrypted.data, signature: sig });
                    }
                }).catch(function (err) {
                    return reject(err);
                });
            } catch (err) {
                if (err.message === 'CFB decrypt: invalid key') {
                    return reject(err.message); // Bad password, reject without Error object
                }
                reject(err);
            }
        });
    }

    function decryptSessionKey(encMessage, key) {

        return new Promise(function (resolve, reject) {
            if (encMessage === undefined || encMessage === '') {
                return reject(new Error('Missing encrypted message'));
            }
            if (key === undefined || key === '') {
                return reject(new Error('Missing password'));
            }

            var message = void 0;
            if ({}.isPrototypeOf.call(Uint8Array.prototype, encMessage)) {
                message = openpgp.message.read(encMessage);
            } else {
                message = openpgp.message.readArmored(encMessage.trim());
            }

            var privateKey = key;
            if (Array.isArray(privateKey)) {
                // Pick correct key
                if (key.length === 0) {
                    reject(new Error('Empty key array'));
                }

                var encryptionKeyIds = message.getEncryptionKeyIds();
                if (!encryptionKeyIds.length) {
                    reject(new Error('Nothing to decrypt'));
                }
                var privateKeyPacket = null;
                for (var i = 0; i < privateKey.length; i++) {
                    privateKeyPacket = privateKey[i].getKeyPacket(encryptionKeyIds);
                    if (privateKeyPacket !== null) {
                        privateKey = privateKey[i];
                        break;
                    }
                }
                if (privateKeyPacket == null) {
                    reject(new Error('No appropriate private key found.'));
                }
            }

            var options = {
                message: message
            };

            if (typeof privateKey === 'string' || privateKey instanceof String) {
                options.password = privateKey;
            } else {
                options.privateKey = privateKey;
            }

            try {
                openpgp.decryptSessionKey(options).then(function (result) {
                    var data = result.data;
                    if (data === undefined) {
                        // unencrypted attachment?
                        return reject(new Error('Undefined session key'));
                    } else if (data.length !== 32) {
                        return reject(new Error('Invalid session key length'));
                    }
                    resolve({ key: data, algo: result.algorithm });
                }, function (err) {
                    reject(err);
                });
            } catch (err) {
                if (err.message === 'CFB decrypt: invalid key') {
                    return reject(err.message); // Bad password, reject without Error object
                }
                reject(err);
            }
        });
    }

    function encryptPrivateKey(privKey, privKeyPassCode) {

        return new Promise(function (resolve, reject) {

            if (Object.prototype.toString.call(privKeyPassCode) !== '[object String]' || privKeyPassCode === '') {
                return reject(new Error('Missing private key passcode'));
            }

            if (!{}.isPrototypeOf.call(openpgp.key.Key.prototype, privKey)) {
                return reject(new Error('Not a Key object'));
            }

            if (!privKey.isPrivate()) {
                return reject(new Error('Not a private key'));
            }

            if (privKey.primaryKey === null || privKey.subKeys === null || privKey.subKeys.length === 0) {
                return reject(new Error('Missing primary key or subkey'));
            }

            privKey.primaryKey.encrypt(privKeyPassCode);
            privKey.subKeys[0].subKey.encrypt(privKeyPassCode);
            resolve(privKey.armor());
        });
    }

    function decryptPrivateKey(privKey, privKeyPassCode) {

        return new Promise(function (resolve, reject) {
            if (privKey === undefined || privKey === '') {
                return reject(new Error('Missing private key'));
            }
            if (privKeyPassCode === undefined || privKeyPassCode === '') {
                return reject(new Error('Missing private key passcode'));
            }

            var keys = getKeys(privKey);
            if (keys instanceof Error) return reject(keys);

            if (keys[0].decrypt(privKeyPassCode)) {
                resolve(keys[0]);
            } else reject('Private key decryption failed'); // Do NOT make this an Error object
        });
    }

    function signMessage(privKeys) {
        var message = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';

        return new Promise(function (resolve, reject) {

            if (privKeys === undefined || privKeys.length < 1) {
                return reject(new Error('Missing private keys'));
            }

            var options = {
                data: message,
                privateKeys: privKeys,
                armor: true
            };

            openpgp.sign(options).then(function (signedMsg) {
                resolve(signedMsg.data);
            }).catch(function (err) {
                reject('Message signing failed');
            });
        });
    }

    function verifyMessage(pubKeys, signedMessage) {
        return new Promise(function (resolve, reject) {
            if (!signedMessage) {
                return reject(new Error('Missing signed message'));
            }

            if (pubKeys === undefined || pubKeys.length < 1) {
                return reject(new Error('Missing public keys'));
            }

            var message = openpgp.cleartext.readArmored(signedMessage.trim());
            if (message instanceof Error) return reject(message);

            var options = {
                message: message,
                publicKeys: pubKeys
            };

            openpgp.verify(options).then(function (signedMsg) {
                resolve(signedMsg);
            }).catch(function (err) {
                reject('Message verification failed');
            });
        });
    }

    function getHashedPassword(password) {
        return btoa(arrayToBinaryString(window.openpgp.crypto.hash.sha512(binaryStringToArray(password))));
    }

    function splitFile(encMessage) {

        return new Promise(function (resolve, reject) {

            var msg = void 0;
            if (openpgp.message.Message.prototype.isPrototypeOf(encMessage)) {
                msg = encMessage;
            } else if (Uint8Array.prototype.isPrototypeOf(encMessage)) {
                msg = openpgp.message.read(encMessage);
            } else {
                msg = openpgp.message.readArmored(encMessage.trim());
            }

            var keyFilter = function keyFilter(packet) {
                return packet.tag !== openpgp.enums.packet.symmetricallyEncrypted && packet.tag !== openpgp.enums.packet.symEncryptedIntegrityProtected;
            };

            var nonData = msg.packets.filter(keyFilter);
            var data = msg.packets.filterByTag(openpgp.enums.packet.symmetricallyEncrypted, openpgp.enums.packet.symEncryptedIntegrityProtected);

            if (nonData.length === 0) {
                return reject(new Error('No non-data packets found'));
            }
            if (data.length === 0) {
                return reject(new Error('No data packets found'));
            }

            resolve({
                keys: nonData.write(),
                data: data.write()
            });
        });
    }

    function keyInfo(privKey, email) {
        var expectEncrypted = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;


        return new Promise(function (resolve, reject) {

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
            if (keys instanceof Error) return reject(keys);

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

            encryptMessage('test message', privKey).then(function () {
                resolve(obj);
            }, function (err) {
                reject(err);
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
        generateKeysRSA: generateKeysRSA,

        // returns a promise, reject with Error
        encryptMessage: encryptMessage,
        decryptMessage: decryptMessage,
        decryptMessageRSA: decryptMessageRSA, // Backwards compatibility wrapper
        signMessage: signMessage,
        verifyMessage: verifyMessage,

        // AES session key generation
        generateKeyAES: generateKeyAES,

        // Get keys
        getKeys: getKeys,

        // Encrypted attachments syntactic sugar
        encryptFile: encryptFile,

        // Private key
        encryptPrivateKey: encryptPrivateKey,
        decryptPrivateKey: decryptPrivateKey,

        // Reformat key
        reformatKey: reformatKey,

        // Session key manipulation
        encryptSessionKey: encryptSessionKey,
        decryptSessionKey: decryptSessionKey,

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

        // Split existing encrypted file into data and non-data parts
        splitFile: splitFile,

        // Dump key information
        keyInfo: keyInfo,
        keyCheck: keyCheck
    };
}();

// node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = pmcrypto;
}