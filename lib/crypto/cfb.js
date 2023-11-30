// This is only used in `decryptLegacy`
import { AES_CFB } from '@openpgp/asmcrypto.js/aes/cfb';

export const AES256 = {
    blockSize: 16,
    decrypt: (message, key, iv) => AES_CFB.decrypt(message, key, iv)
};
