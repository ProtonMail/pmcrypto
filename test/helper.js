const openpgp = require('openpgp');

export const init = () => {
    global.openpgp = openpgp;
};
