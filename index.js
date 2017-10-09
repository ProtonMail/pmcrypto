const btoa = require('btoa');
const atob = require('atob');
const Promise = require('es6-promise').Promise;
const openpgp = require('openpgp');

openpgp.config.integrity_protect = true;
openpgp.config.use_native = true;
module.exports = require('./lib/index');