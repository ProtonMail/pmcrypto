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

    if (options.detached) {
        const result = {};

        // Create detached signature of message
        const signature = await options.message.signDetached(options.privateKeys);

        // Encrypt message without signing it
        result.data = await encrypt({
            ...options,
            detached: false,
            privateKeys: [],
            armor
        });

        // Encrypt signature and add it to the final result
        result.encryptedSignature = await encrypt({
            ...options,
            detached: false,
            message: createMessage(signature.packets.write()),
            privateKeys: [],
            armor
        });

        // Add plain signature for backward compatibility
        result.signature = armor ? signature.armor() : signature;

        return result;
    }
    return { data: await encrypt({ armor, ...options }) };
}
