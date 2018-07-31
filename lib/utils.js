import { TIME_OFFSET } from './constants';
import openpgpjs from './openpgp';

// Load window.performance in the browser, perf_hooks in node, and fall back on Date
const getPerformance = () => {
    /* START.NODE_ONLY */
    try {
        if (typeof require === 'undefined') {
            return;
        }
        // eslint-disable-next-line global-require
        const result = require('perf_hooks');
        if (result && result.performance) {
            return result.performance;
        }
    } catch (e) {
        // no-op
    }
    /* END.NODE_ONLY */
    if (window && window.performance) {
        return window.performance;
    }
    return Date;
};

const performance = getPerformance();

const noop = () => {};
export const ifDefined = (cb = noop) => (input) => {
    if (input !== undefined) {
        return cb(input);
    }
};

export const encodeUtf8 = ifDefined(openpgpjs.util.encode_utf8);
export const decodeUtf8 = ifDefined(openpgpjs.util.decode_utf8);
export const encodeBase64 = ifDefined((input) => btoa(input).trim());
export const decodeBase64 = ifDefined((input) => atob(input.trim()));
export const encodeUtf8Base64 = ifDefined((input) => encodeBase64(encodeUtf8(input)));
export const decodeUtf8Base64 = ifDefined((input) => decodeUtf8(decodeBase64(input)));

export const binaryStringToArray = openpgpjs.util.str_to_Uint8Array;
export const arrayToBinaryString = openpgpjs.util.Uint8Array_to_str;

export function getHashedPassword(password) {
    return btoa(arrayToBinaryString(openpgpjs.crypto.hash.sha512(binaryStringToArray(password))));
}

export function stripArmor(input) {
    return openpgpjs.armor.decode(input).data;
}

let lastServerTime = null;
let clientTime = null;

export function serverTime() {
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

export function updateServerTime(serverDate) {
    lastServerTime = serverDate;
    clientTime = performance.now();
}

export function getMaxConcurrency() {
    const { workers = [ null ] } = openpgpjs.getWorker() || {};
    return workers.length;
}
