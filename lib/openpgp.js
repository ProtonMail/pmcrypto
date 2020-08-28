let instance; // eslint-disable-line import/no-mutable-exports

export { instance as openpgp };

export const setInstance = (value) => {
    instance = value;
};

export const setConfig = (openpgp) => {
    openpgp.config.s2k_iteration_count_byte = 96;
    /**
     * This option is needed because we have some old messages from 2015-2016
     * that were encrypted using non-encryption RSA keys, due to an openpgpjs bug.
     * Some time after implementing symmetric re-encryption we should be able to disable this
     */
    openpgp.config.allow_insecure_decryption_with_signing_keys = true;
};
