import { decryptKey, decryptSessionKeys } from '../openpgp';
import { getKey } from './utils';

export async function decryptPrivateKey(privKey, privKeyPassCode) {
    if (privKey === undefined || privKey === '') {
        return Promise.reject(new Error('Missing private key'));
    }

    if (privKeyPassCode === undefined || privKeyPassCode === '') {
        return Promise.reject(new Error('Missing private key passcode'));
    }

    const key = await getKey(privKey);
    const decryptedKey = await decryptKey({ privateKey: key, passphrase: privKeyPassCode });
    return decryptedKey;
}

export async function decryptSessionKey(options) {
    try {
        const result = await decryptSessionKeys(options);

        if (result.length > 1) {
            throw new Error('Multiple decrypted session keys found');
        }

        return result[0];
    } catch (err) {
        return Promise.reject(err);
    }
}
