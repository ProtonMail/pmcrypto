/* eslint-disable no-prototype-builtins */
import { serverTime } from '../utils';
import { createMessage } from './utils';
import openpgpjs from '../openpgp';

export default function encryptMessage(options) {
    if (typeof options.data === 'string') {
        options.message = createMessage(options.data.replace(/[ \t]*$/gm, ''));
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? openpgpjs.enums.compression.zlib : undefined;

    return openpgpjs.encrypt(options);
}
