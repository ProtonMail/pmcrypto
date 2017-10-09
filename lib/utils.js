const noop = () => {};
const ifDefined = (cb = noop) => (input) => {
    if (input !== undefined) {
        return cb(input);
    }
}

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

module.exports = {
    encode_utf8,
    decode_utf8,
    encode_base64,
    decode_base64,
    encode_utf8_base64,
    decode_utf8_base64,
    binaryStringToArray,
    arrayToBinaryString,
    getHashedPassword
};