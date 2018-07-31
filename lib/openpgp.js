/* eslint-disable global-require */
openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;

/* START.NODE_ONLY */
global.btoa = require('btoa');
global.atob = require('atob');
global.Promise = require('es6-promise').Promise;
global.openpgp = require('openpgp');
/* END.NODE_ONLY */

/* START.BROWSER_ONLY */
/**
 * @link https://github.com/vibornoff/asmcrypto.js/issues/121
 */
asmCrypto.random.skipSystemRNGWarning = true;

const { hardwareConcurrency = 1 } = window.navigator || {};
openpgp.initWorker({ path: 'openpgp.worker.min.js', n: hardwareConcurrency });
/* END.BROWSER_ONLY */
const openpgpjs = openpgp;

export default openpgpjs;
