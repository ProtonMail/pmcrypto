/**
 * Load window.performance in the browser, perf_hooks in node, and fall back on Date
 */
const requirePerfHooks = () => {
    try {
        const result = require('perf_hooks');
        if (result && result.performance) {
            return result;
        }
    } catch (e) {
        
    }
};
const { performance = Date } = requirePerfHooks() || window || {};

/**
 * Noop
 * @return {void}
 */
const noop = () => {};

/**
 * If defined
 * @param {cb = () => void} cb
 * @return {(input) => any}
 */
const ifDefined = (cb = noop) => (input) => {
    if (input !== undefined) {
        return cb(input);
    }
};

const encode_utf8 = ifDefined((input) => unescape(encodeURIComponent(input)));
const decode_utf8 = ifDefined((input) => decodeURIComponent(escape(input)));
const encode_base64 = ifDefined((input) => btoa(input).trim());
const decode_base64 = ifDefined((input) => atob(input.trim()));
const encode_utf8_base64 = ifDefined((input) => encode_base64(encode_utf8(input)));
const decode_utf8_base64 = ifDefined((input) => decode_utf8(decode_base64(input)));

/**
 * Binary string to array
 *
 * A unicode string may need to be encoded with `encode_utf8` to keep all the
 * information of the string
 * @param {string} str
 * @return {Uint8Array}
 */
function binaryStringToArray(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

/**
 * Array to binary string
 *
 * A unicode string may need to be decoded with `decode_utf8`
 * @param {array} arr
 * @return {string}
 */
function arrayToBinaryString(arr) {
    const result = [];
    for (let i = 0; i < arr.length; i++) {
        result[i] = String.fromCharCode(arr[i]);
    }
    return result.join('');
}

/**
 * Get sha512 hashed password in base 64
 * @param {string} password Password to hash
 * @return {string} Hashed password
 */
function getHashedPassword(password) {
    return btoa(arrayToBinaryString(openpgp.crypto.hash.sha512(binaryStringToArray(password))));
}

function stripArmor(input) {
    return openpgp.armor.decode(input).data;
}

let lastServerTime = null;
let clientTime = null;

function serverTime() {
    if (lastServerTime !== null) {
        return new Date(+lastServerTime + (performance.now() - clientTime));
    }
    return new Date();
}

function updateServerTime(serverDate) {
    lastServerTime = serverDate;
    clientTime = performance.now();
}

module.exports = {
    encode_utf8,
    decode_utf8,
    encode_base64,
    decode_base64,
    encode_utf8_base64,
    decode_utf8_base64,
    binaryStringToArray,
    arrayToBinaryString,
    getHashedPassword,
    stripArmor,
    updateServerTime,
    serverTime
};
