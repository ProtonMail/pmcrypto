import type { MaybeStream } from '../pmcrypto';
import md5 from './_md5';

export const SHA256 = async (data: Uint8Array) => {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(digest);
};

export const SHA512 = async (data: Uint8Array) => {
    const digest = await crypto.subtle.digest('SHA-512', data);
    return new Uint8Array(digest);
};

/**
 * MD5 is an unsafe hash function. It should normally not be used.
 * It's exposed because it's required for old auth versions.
 * @see openpgp.crypto.hash.md5
 */
export const unsafeMD5 = (data: Uint8Array) => md5(data);

/**
 * SHA1 is an unsafe hash function. It should not be used for cryptographic purposes.
 * DO NOT USE in contexts where collision resistance is important
 * @see openpgp.crypto.hash.sha1
 */
export async function unsafeSHA1(data: MaybeStream<Uint8Array>) {
    if (data instanceof Uint8Array) {
        const digest = await crypto.subtle.digest('SHA-1', data);
        return new Uint8Array(digest);
    }

    const { sha1 } = await import('@openpgp/noble-hashes/sha1');
    const hashInstance = sha1.create();
    const inputReader = data.getReader(); // AsyncInterator is still not widely supported
    // eslint-disable-next-line no-constant-condition
    while (true) {
        const { done, value } = await inputReader.read();
        if (done) {
            return hashInstance.digest();
        }
        hashInstance.update(value);
    }
}
