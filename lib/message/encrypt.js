/* eslint-disable no-prototype-builtins */
import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';
import { createMessage } from './utils';

export default async function encryptMessage({ armor = true, ...options }) {
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

        // Encrypt message without signing it
        const result = await openpgp.encrypt({
            ...options,
            privateKeys: [],
            armor
        });

        // Encrypt signature and add it to the final result
        const encryptedSignature = await openpgp.encrypt({
            ...options,
            message: createMessage(signature.packets.write()),
            privateKeys: [],
            armor
        });
        result.encryptedSignature = armor ? encryptedSignature.data : encryptedSignature.message;

        // Add plain signature for backward compatibility
        result.signature = armor ? signature.armor() : signature;

        return result;
    }
    return openpgp.encrypt({ armor, ...options });
}
