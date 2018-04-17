global.btoa = require('btoa');
global.atob = require('atob');
global.openpgp = require('openpgp');

openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;

module.exports = require('../lib/main')(window.performance);
