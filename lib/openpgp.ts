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

    // we want to avoid generating SEIPDv2 messages until support is rolled out to other platforms,
    // in case e.g. some users have already imported v4 keys with SEIPDv2 feature flags.
    config.ignoreSEIPDv2FeatureFlag = true;

    // We still allow parsing of v5 keys and signatures so that we can log usage of the former through
    // `checkKeyCompatibility` errors: v5 entities were allowed in pmcrypto v7, so they might have been
    // uploaded as e.g. contact keys.
    config.enableParsingV5Entities = true;

    // Opt-in setting for now to avoid disruptions if too grammar is too strict.
    config.enforceGrammar = false;
};

export * from 'openpgp/lightweight';
