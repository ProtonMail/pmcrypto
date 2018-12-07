import { init } from '../lib/pmcrypto';

init({
    openpgp: require('openpgp'),
    atob: require('atob'),
    btoa: require('btoa')
});
