/* global crypto */

const SYMMETRIC_KEY_SIZES = {
    aes128: 16,
    aes192: 24,
    aes256: 32
};

export function getSymmetricKeySize(algoName) {
    if (!SYMMETRIC_KEY_SIZES[algoName]) {
        throw new Error('Unsupported symmetric algorithm');
    }

    return SYMMETRIC_KEY_SIZES[algoName];
}

export const getRandomBytes = async (length) => {
    return crypto.getRandomValues(new Uint8Array(length));
};
