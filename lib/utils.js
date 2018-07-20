import { TIME_OFFSET } from './constants';
// Load window.performance in the browser, perf_hooks in node, and fall back on Date
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

const noop = () => {};
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


function binaryStringToArray(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

function arrayToBinaryString(arr) {
    const result = [];
    for (let i = 0; i < arr.length; i++) {
        result[i] = String.fromCharCode(arr[i]);
    }
    return result.join('');
}

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
        const timeDiff = performance.now() - clientTime;
        /*
         * From the performance.now docs:
         * The timestamp is not actually high-resolution.
         * To mitigate security threats such as Spectre, browsers currently round the result to varying degrees.
         * (Firefox started rounding to 2 milliseconds in Firefox 59.)
         * Some browsers may also slightly randomize the timestamp.
         * The precision may improve again in future releases;
         * browser developers are still investigating these timing attacks and how best to mitigate them.
         */
        const safeTimeDiff = timeDiff < TIME_OFFSET ? 0 : timeDiff - TIME_OFFSET;
        return new Date(+lastServerTime + safeTimeDiff);
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
