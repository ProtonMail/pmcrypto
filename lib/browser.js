/**
 * @link https://github.com/vibornoff/asmcrypto.js/issues/121
 */
asmCrypto.random.skipSystemRNGWarning = true;

const { hardwareConcurrency = 1 } = window.navigator || {};
openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;
openpgp.initWorker({ path: 'openpgp.worker.min.js', n: hardwareConcurrency });

window.pmcrypto = require('./index');
