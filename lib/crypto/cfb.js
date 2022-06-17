import { AES_CFB } from '@openpgp/asmcrypto.js/dist_es8/aes/cfb';

export const AES256 = {
    blockSize: 16,
    decrypt: (message, key, iv) => AES_CFB.decrypt(message, key, iv)
};
