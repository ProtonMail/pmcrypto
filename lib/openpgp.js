import { config } from 'openpgp';

export const setConfig = () => {
    config.s2kIterationCountByte = 96;
    /**
     * This option is needed because we have some old messages from 2015-2016
     * that were encrypted using non-encryption RSA keys, due to an openpgpjs bug.
     * Some time after implementing symmetric re-encryption we should be able to disable this
     */
    config.allowInsecureDecryptionWithSigningKeys = true;
};
