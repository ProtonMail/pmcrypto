global.btoa = require('btoa');
global.atob = require('btoa');

require = require('esm')(module); // eslint-disable-line no-global-assign

module.exports = require('./pmcrypto.js');
