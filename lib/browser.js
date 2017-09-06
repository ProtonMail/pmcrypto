/**
 * @link https://github.com/vibornoff/asmcrypto.js/issues/121
 */
asmCrypto.random.skipSystemRNGWarning = true;
openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;
openpgp.initWorker({ path: 'openpgp.worker.min.js' });

window.pmcrypto = require('./index');