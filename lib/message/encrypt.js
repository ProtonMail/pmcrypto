/* eslint-disable no-prototype-builtins */
import { encrypt, util, enums } from 'openpgp';
import { serverTime } from '../serverTime';
import { createMessage } from './utils';

export default async function encryptMessage({ armor = true, ...options }) {
    if (typeof options.data === 'string') {
        options.message = createMessage(util.removeTrailingSpaces(options.data), options.filename);
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data, options.filename);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? enums.compression.zlib : undefined;

    options.armor = armor;

    if (options.detached) {
        const result = {};

        // Create detached signature of message
        const signature = await options.message.signDetached(options.privateKeys);

        // Encrypt message without signing it
        options.privateKeys = [];
        options.returnSessionKey = true;
        const result = await openpgp.encrypt(options);

        // Encrypt signature and add it to the final result
        options.message = createMessage(signature.packets.write());
        options.sessionKey = result.sessionKey;
        const encryptedSignature = await openpgp.encrypt(options);
        result.encryptedSignature = options.armor ? encryptedSignature.data : encryptedSignature.message;

        // Add plain signature for backward compatibility
        result.signature = options.armor ? signature.armor() : signature;

        return result;
    }
    return { data: await encrypt({ armor, ...options }) };
}
