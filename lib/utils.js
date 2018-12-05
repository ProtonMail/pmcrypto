const btoa = (window || global).btoa || require('btoa');
const atob = (window || global).atob || require('atob');

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

export const binaryStringToArray = (args) => openpgp.util.str_to_Uint8Array(args);
export const arrayToBinaryString = (args) => openpgp.util.Uint8Array_to_str(args);
export const concatArrays = (args) => openpgp.util.concatUint8Array(args);

export function getHashedPassword(password) {
    return btoa(arrayToBinaryString(openpgp.crypto.hash.sha512(binaryStringToArray(password))));
}

export function stripArmor(input) {
    return openpgp.armor.decode(input).data;
}

let lastServerTime = null;

export function serverTime() {
    return lastServerTime || new Date();
}

export function updateServerTime(serverDate) {
    lastServerTime = serverDate;
}

export function getMaxConcurrency() {
    const { workers = [null] } = openpgp.getWorker() || {};
    return workers.length;
}
