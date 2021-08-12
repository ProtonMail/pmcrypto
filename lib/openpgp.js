import { config } from 'openpgp';

export const setConfig = () => {
    config.s2k_iteration_count_byte = 96;
    /**
     * This option is needed because we have some old messages from 2015-2016
     * that were encrypted using non-encryption RSA keys, due to an openpgpjs bug.
     * Some time after implementing symmetric re-encryption we should be able to disable this
     */
    config.allow_insecure_decryption_with_signing_keys = true;
};
