function encryptPrivateKey(privKey, privKeyPassCode) {

    return Promise.resolve()
    .then(() => {

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


return encryptPrivateKey;