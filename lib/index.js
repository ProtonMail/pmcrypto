require = require('esm')(module);

global.btoa = require('btoa');
global.atob = require('btoa');

module.exports = require('./pmcrypto.js');
