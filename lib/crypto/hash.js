/* global crypto */
import md5 from './_md5';

export const SHA256 = async (args) => {
    const digest = await crypto.subtle.digest('SHA-256', args);
    return new Uint8Array(digest);
};

export const SHA512 = async (args) => {
    const digest = await crypto.subtle.digest('SHA-512', args);
    return new Uint8Array(digest);
};

/**
 * MD5 is an unsafe hash function. It should normally not be used.
 * It's exposed because it's required for old auth versions.
 * @see openpgp.crypto.hash.md5
 */
export const unsafeMD5 = (args) => md5(args);

/**
 * SHA1 is an unsafe hash function. It should not be used for cryptographic purposes.
 * DO NOT USE in contexts where collision resistance is important
 * @see openpgp.crypto.hash.sha1
 */
export const unsafeSHA1 = async (args) => {
    const digest = await crypto.subtle.digest('SHA-1', args);
    return new Uint8Array(digest);
};
