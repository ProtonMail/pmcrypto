// Most of these util functions are copied as-is from https://github.com/openpgpjs/openpgpjs/blob/v5.0.0/src/util.js
// @ts-ignore missing TS defs
import { concatUint8Array, transform } from '@openpgp/web-stream-tools';

import type { MaybeStream, WebStream } from './pmcrypto';

const localAtob = typeof atob === 'undefined' ? (str: string) => Buffer.from(str, 'base64').toString('binary') : atob;
const localBtoa = typeof btoa === 'undefined' ? (str: string) => Buffer.from(str, 'binary').toString('base64') : btoa;

const ifDefined = <T, R>(cb: (input: T) => R) => <U extends T | undefined>(input: U) => {
    return (input !== undefined ? cb(input as T) : undefined) as U extends T ? R : undefined;
};
export const encodeUtf8 = ifDefined((input: string) => unescape(encodeURIComponent(input)));
export const decodeUtf8 = ifDefined((input: string) => decodeURIComponent(escape(input)));
export const encodeBase64 = ifDefined((input: string) => localBtoa(input).trim());
export const decodeBase64 = ifDefined((input: string) => localAtob(input.trim()));
export const encodeUtf8Base64 = ifDefined((input: string) => encodeBase64(encodeUtf8(input)));
export const decodeUtf8Base64 = ifDefined((input: string) => decodeUtf8(decodeBase64(input)));

export function concatArrays(arrays: Uint8Array[]): Uint8Array {
    return concatUint8Array(arrays);
}

const isString = (data: any):  data is string | String => {
    return typeof data === 'string' || data instanceof String;
};

/**
 * Convert a hex string to an array of 8-bit integers
 * @param hex  A hex string to convert
 * @returns An array of 8-bit integers
 */
export const hexToUint8Array = (hex: string) => {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < hex.length >> 1; k++) {
        result[k] = parseInt(hex.substr(k << 1, 2), 16);
    }
    return result;
};

/**
 * Convert a string to an array of 8-bit integers
 * @param str String to convert
 * @returns An array of 8-bit integers
 */
export const binaryStringToArray = (str: string) => {
    if (!isString(str)) {
        throw new Error('binaryStringToArray: Data must be in the form of a string');
    }

    const result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        result[i] = str.charCodeAt(i);
    }
    return result;
};

/**
 * Encode an array of 8-bit integers as a string
 * @param bytes data to encode
 * @return string-encoded bytes
 */
export const arrayToBinaryString = (bytes: Uint8Array) => {
    const result = [];
    const bs = 1 << 14;
    const j = bytes.length;

    for (let i = 0; i < j; i += bs) {
        // @ts-ignore Uint8Array treated as number[]
        result.push(String.fromCharCode.apply(String, bytes.subarray(i, i + bs < j ? i + bs : j)));
    }
    return result.join('');
};

/**
 * Convert an array of 8-bit integers to a hex string
 * @param bytes Array of 8-bit integers to convert
 * @returns Hexadecimal representation of the array
 */
export const arrayToHexString = (bytes: Uint8Array) => {
    const r = [];
    const e = bytes.length;
    let c = 0;
    let h;
    while (c < e) {
        h = bytes[c++].toString(16);
        while (h.length < 2) {
            h = '0' + h;
        }
        r.push('' + h);
    }
    return r.join('');
};

/**
 * Convert a native javascript string to a Uint8Array of utf8 bytes
 * @param str - The string to convert
 * @returns A valid squence of utf8 bytes.
 */
export function stringToUtf8Array(str: string): Uint8Array;
export function stringToUtf8Array(str: WebStream<string>): WebStream<Uint8Array>;
export function stringToUtf8Array(str: MaybeStream<string>): MaybeStream<Uint8Array> {
    const encoder = new TextEncoder();
    return transform(str, (value: string) => encoder.encode(value));
}

/**
 * Convert a Uint8Array of utf8 bytes to a native javascript string
 * @param utf8 - A valid squence of utf8 bytes
 * @returns A native javascript string.
 */
export function utf8ArrayToString(utf8: Uint8Array): string;
export function utf8ArrayToString(utf8: WebStream<Uint8Array>): WebStream<string>;
export function utf8ArrayToString(utf8: MaybeStream<Uint8Array>): MaybeStream<string> {
    const decoder = new TextDecoder();
    function process(value: Uint8Array, lastChunk = false) {
        return decoder.decode(value, { stream: !lastChunk });
    }
    return transform(utf8, process, () => process(new Uint8Array(), true));
}

/* eslint-disable camelcase */
export const encode_utf8 = encodeUtf8;
export const decode_utf8 = decodeUtf8;
export const encode_base64 = encodeBase64;
export const decode_base64 = decodeBase64;
export const encode_utf8_base64 = encodeUtf8Base64;
export const decode_utf8_base64 = decodeUtf8Base64;
