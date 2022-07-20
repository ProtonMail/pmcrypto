// Most of these util functions are copied as-is from https://github.com/openpgpjs/openpgpjs/blob/v5.0.0/src/util.js
import type { MaybeStream, WebStream } from './pmcrypto';

const ifDefined = <T, R>(cb: (input: T) => R) => <U extends T | undefined>(input: U) => {
    return (input !== undefined ? cb(input as T) : undefined) as U extends T ? R : undefined;
};
export const encodeUtf8 = ifDefined((input: string) => unescape(encodeURIComponent(input)));
export const decodeUtf8 = ifDefined((input: string) => decodeURIComponent(escape(input)));
export const encodeBase64 = ifDefined((input: string) => btoa(input).trim());
export const decodeBase64 = ifDefined((input: string) => atob(input.trim()));
export const encodeUtf8Base64 = ifDefined((input: string) => encodeBase64(encodeUtf8(input)));
export const decodeUtf8Base64 = ifDefined((input: string) => decodeUtf8(decodeBase64(input)));

/**
 * Concatenate (flatten) Uint8Arrays
 * @param arrays - Uint8Arrays to concatenate
 * @returns concatenated array
 */
export function concatArrays(arrays: Uint8Array[]): Uint8Array {
    if (arrays.length === 1) return arrays[0];

    let totalLength = 0;
    for (let i = 0; i < arrays.length; i++) {
        if (!(arrays[i] instanceof Uint8Array)) {
            throw new Error('concatArrays: Data must be in the form of a Uint8Array');
        }

        totalLength += arrays[i].length;
    }

    const result = new Uint8Array(totalLength);
    let pos = 0;
    arrays.forEach((element) => {
        result.set(element, pos);
        pos += element.length;
    });

    return result;
}

const isString = (data: any): data is string | String => {
    return typeof data === 'string' || data instanceof String;
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
 * Convert a hex string to an array of 8-bit integers
 * @param hex  A hex string to convert
 * @returns An array of 8-bit integers
 */
export const hexStringToArray = (hex: string) => {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < result.length; k++) {
        const i = k << 1;
        result[k] = parseInt(hex.substring(i, i + 2), 16);
    }
    return result;
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

    if (isString(str)) return encoder.encode(str);
    const reader = str.getReader();
    const transformedStream: WebStream<Uint8Array> = new ReadableStream<Uint8Array>({
        async pull(controller) {
            const { value, done } = await reader.read();

            if (done) {
                controller.close();
            } else {
                controller.enqueue(encoder.encode(value));
            }
        },
        cancel() {
            reader.cancel();
        }
    });

    return transformedStream;
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

    if (utf8 instanceof Uint8Array) return decoder.decode(utf8);

    const reader = utf8.getReader();
    const transformedStream: WebStream<string> = new ReadableStream<string>({
        async pull(controller) {
            const { value, done } = await reader.read();

            if (done) {
                controller.enqueue(
                    decoder.decode(new Uint8Array(), { stream: false }) // flush any remaining partial char
                );
                controller.close();
            } else {
                controller.enqueue(
                    decoder.decode(value, { stream: true }) // handle chars spread across chunks
                );
            }
        },
        cancel() {
            reader.cancel();
        }
    });

    return transformedStream;
}
