/* eslint-disable no-prototype-builtins */
import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';
import { createMessage } from './utils';

export default async function encryptMessage(options) {
    if (typeof options.data === 'string') {
        options.message = createMessage(openpgp.util.removeTrailingSpaces(options.data), options.filename);
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data, options.filename);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? openpgp.enums.compression.zlib : undefined;

    if (options.detached) {
        // Create detached signature of message
        const signature = await options.message.signDetached(options.privateKeys);

        // Encrypt message without signing it (thus no need to change .detached)
        options.privateKeys = [];
        const ciphertext = await openpgp.encrypt(options);

        // Encrypt signature and add it to the final package
        options.message = createMessage(signature.packets.write(), options.filename);
        const encSignature = await openpgp.encrypt(options);
        ciphertext.encSignature = encSignature.data;

        // Add plain signature for backward compatibility
        ciphertext.signature = signature.armor();

        return ciphertext;
    } else {
        return openpgp.encrypt(options);
    }
}
