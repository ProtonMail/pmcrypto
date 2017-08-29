openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;
openpgp.initWorker({ path: 'openpgp.worker.min.js' });

window.pmcrypto = require('./index');