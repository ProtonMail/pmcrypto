import openpgpjs from './openpgp';

const noop = () => {};
export const ifDefined = (cb = noop) => (input) => {
    if (input !== undefined) {
        return cb(input);
    }
};

export const encodeUtf8 = ifDefined((input) => unescape(encodeURIComponent(input)));
export const decodeUtf8 = ifDefined((input) => decodeURIComponent(escape(input)));
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

export function serverTime() {
    return lastServerTime || new Date();
}

export function updateServerTime(serverDate) {
    lastServerTime = serverDate;
}

export function getMaxConcurrency() {
    const { workers = [null] } = openpgpjs.getWorker() || {};
    return workers.length;
}
