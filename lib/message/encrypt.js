/* eslint-disable no-prototype-builtins */
import { encrypt, enums, generateSessionKey } from 'openpgp';
import { serverTime } from '../serverTime';
import { removeTrailingSpaces } from '../utils';
import { createMessage } from './utils';

export default async function encryptMessage({ armor = true, ...options }) {
    if (typeof options.data === 'string') {
        options.message = createMessage(removeTrailingSpaces(options.data), options.filename);
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data, options.filename);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    options.compression = options.compression ? enums.compression.zlib : undefined;

    options.armor = armor;
    const result = {};

    if (!options.sessionKey) {
        options.sessionKey = await generateSessionKey(options);
    }
    if (options.returnSessionKey) {
        result.sessionKey = options.sessionKey;
    }
    if (options.detached) {
        // Create detached signature of message
        const signature = await options.message.signDetached(options.privateKeys);
        options.detached = false;
        options.privateKeys = [];

        // Encrypt signature and add it to the final result
        result.encryptedSignature = await encrypt({
            ...options,
            message: createMessage(signature.packets.write())
        });

        // Add plain signature for backward compatibility
        result.signature = armor ? signature.armor() : signature;
    }

    const encrypted = await encrypt(options);
    if (options.armor) {
        result.data = encrypted;
    } else {
        result.message = encrypted;
    }

    return result;
}
