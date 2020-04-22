/* eslint-disable no-prototype-builtins */
import { encrypt, util, enums } from 'openpgp';
import { serverTime } from '../serverTime';
import { createMessage } from './utils';

export default function encryptMessage(options) {
    if (typeof options.data === 'string') {
        options.message = createMessage(util.removeTrailingSpaces(options.data), options.filename);
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data, options.filename);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? enums.compression.zlib : undefined;

    return encrypt(options);
}
