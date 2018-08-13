import { serverTime } from '../utils';
import openpgpjs from '../openpgp';

export default function encryptMessage(options) {
    if (typeof options.data === 'string') {
        options.data = options.data.replace(/[ \t]*$/mg, '');
    }
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? openpgpjs.enums.compression.zlib : undefined;
    return openpgpjs.encrypt(options);
}
