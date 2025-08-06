import type { MaybeWebStream } from '../pmcrypto';

export const SHA256 = async (data: Uint8Array<ArrayBuffer>) => {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(digest);
};

export const SHA512 = async (data: Uint8Array<ArrayBuffer>) => {
    const digest = await crypto.subtle.digest('SHA-512', data);
    return new Uint8Array(digest);
};

/**
 * MD5 is an unsafe hash function. It should normally not be used.
 * It's exposed because it's required for old auth versions.
 */
export const unsafeMD5 = async (data: Uint8Array<ArrayBuffer>) => import('./_md5').then(({ md5 }) => md5(data) as Uint8Array<ArrayBuffer>);

/**
 * SHA1 is an unsafe hash function. It should not be used for cryptographic purposes.
 * DO NOT USE in contexts where collision resistance is important
 * @see openpgp.crypto.hash.sha1
 */
export async function unsafeSHA1(data: MaybeWebStream<Uint8Array<ArrayBuffer>>) {
    if (data instanceof Uint8Array) {
        const digest = await crypto.subtle.digest('SHA-1', data);
        return new Uint8Array(digest);
    }

    const { sha1 } = await import('@noble/hashes/sha1');
    const hashInstance = sha1.create();
    const inputReader = data.getReader(); // AsyncInterator is still not widely supported
    // eslint-disable-next-line no-constant-condition
    while (true) {
        const { done, value } = await inputReader.read();
        if (done) {
            return hashInstance.digest() as Uint8Array<ArrayBuffer>;
        }
        hashInstance.update(value);
    }
}
