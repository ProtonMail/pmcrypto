import { openpgp } from '../openpgp';
import { getKeys } from './utils';

export async function decryptPrivateKey(privKey, privKeyPassCode) {
    if (privKey === undefined || privKey === '') {
        return Promise.reject(new Error('Missing private key'));
    }

    if (privKeyPassCode === undefined || privKeyPassCode === '') {
        return Promise.reject(new Error('Missing private key passcode'));
    }

    const [key] = await getKeys(privKey);
    const success = await key.decrypt(privKeyPassCode);

    if (!success) {
        throw new Error('Private key decryption failed');
    }

    return key;
}

export async function decryptSessionKey(options) {
    try {
        const result = await openpgp.decryptSessionKeys(options);

        if (result.length > 1) {
            return Promise.reject(new Error('Multiple decrypted session keys found'));
        }

        return result[0];
    } catch (err) {
        if (err.message === 'CFB decrypt: invalid key' && options.passwords && options.passwords.length) {
            return Promise.reject(new Error('Incorrect message password'));
        }

        return Promise.reject(err);
    }
}
