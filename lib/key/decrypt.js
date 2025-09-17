import { decryptSessionKeys } from '../openpgp';

export async function decryptSessionKey(options) {
    const result = await decryptSessionKeys(options);

    if (result.length > 1) {
        throw new Error('Multiple decrypted session keys found');
    }

    return result[0];
}
