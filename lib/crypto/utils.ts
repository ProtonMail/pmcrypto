import type { enums } from '../openpgp';
const SYMMETRIC_KEY_SIZES: { [label: string]: number } = {
    aes128: 16,
    aes192: 24,
    aes256: 32
};

export function getSymmetricKeySize(algoName: enums.symmetricNames) {
    if (!SYMMETRIC_KEY_SIZES[algoName]) {
        throw new Error('Unsupported symmetric algorithm');
    }

    return SYMMETRIC_KEY_SIZES[algoName];
}

export const getRandomBytes = (length: number) => {
    return crypto.getRandomValues(new Uint8Array(length));
};
