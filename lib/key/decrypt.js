import { decryptKey, decryptSessionKeys } from '../openpgp';
import { getKey } from './utils';


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
