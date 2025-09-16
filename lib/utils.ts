// Most of these util functions are copied as-is from https://github.com/openpgpjs/openpgpjs/blob/v5.0.0/src/util.js
import type { MaybeWebStream, WebStream } from './pmcrypto';

export type MaybeArray<T> = T | Array<T>;

/**
 * Concatenate (flatten) Uint8Arrays
 * @param arrays - Uint8Arrays to concatenate
 * @returns concatenated array
 */
export function concatArrays(arrays: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
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

const isString = (data: unknown): data is string => {
    return typeof data === 'string' || data instanceof String;
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
export const arrayToHexString = (bytes: Uint8Array<ArrayBuffer>) => {
    const hexAlphabet = '0123456789abcdef';
    let s = '';
    bytes.forEach((v) => { s += hexAlphabet[v >> 4] + hexAlphabet[v & 15]; });
    return s;
};

/**
 * Convert a native javascript string to a Uint8Array of utf8 bytes
 * @param str - The string to convert
 * @returns A valid squence of utf8 bytes.
 */
export function stringToUtf8Array(str: string): Uint8Array<ArrayBuffer>;
export function stringToUtf8Array(str: WebStream<string>): WebStream<Uint8Array<ArrayBuffer>>;
export function stringToUtf8Array(str: MaybeWebStream<string>): MaybeWebStream<Uint8Array<ArrayBuffer>> {
    const encoder = new TextEncoder();

    if (isString(str)) return encoder.encode(str);
    const reader = str.getReader();
    const transformedStream: WebStream<Uint8Array<ArrayBuffer>> = new ReadableStream<Uint8Array<ArrayBuffer>>({
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
export function utf8ArrayToString(utf8: Uint8Array<ArrayBuffer>): string;
export function utf8ArrayToString(utf8: WebStream<Uint8Array<ArrayBuffer>>): WebStream<string>;
export function utf8ArrayToString(utf8: MaybeWebStream<Uint8Array<ArrayBuffer>>): MaybeWebStream<string> {
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

/**
 * Normalise date to compare it to other OpenPGP timestamps
 * @param time - date to normalise
 * @returns date with reduced precision (seconds)
 */
export const normalizeDate = (time: Date) => new Date(Math.floor(+time / 1000) * 1000);
