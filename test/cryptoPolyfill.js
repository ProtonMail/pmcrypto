const { Crypto } = require('@peculiar/webcrypto');

global.crypto = new Crypto();
global.navigator = { userAgent: 'Node.js' };
