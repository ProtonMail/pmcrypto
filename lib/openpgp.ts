import { config } from 'openpgp/lightweight';

export const setConfig = () => {
    config.s2kIterationCountByte = 255;
    /**
     * This option is needed because we have some old messages from 2015-2016
     * that were encrypted using non-encryption RSA keys, due to an openpgpjs bug.
     * Some time after implementing symmetric re-encryption we should be able to disable this
     */
    config.allowInsecureDecryptionWithSigningKeys = true;

    /**
     * This is necessary as we used to reformat keys on import, without setting the new binding signature creation time
     * to match the key creation time.
     */
    config.allowInsecureVerificationWithReformattedKeys = true;

    // these minimum key settings apply to already imported (private) keys as well, so we cannot be too strict.
    // to enforce stricter checks e.g. on new key imports, `checkKeyStrength` should be called.
    config.rejectPublicKeyAlgorithms = new Set();
    config.rejectCurves = new Set();
    config.minRSABits = 1023;

    config.checkEdDSAFaultySignatures = false; // let each web-client enable the check
};

export * from 'openpgp/lightweight';
