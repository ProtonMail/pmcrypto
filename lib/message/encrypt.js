/* eslint-disable no-prototype-builtins */
import { createMessage as openpgpCreateMessage, generateSessionKey, encrypt, sign } from 'openpgp';
import { serverTime } from '../serverTime';
import { createMessage } from './utils';
import { removeTrailingSpaces } from '../utils';

export default async function encryptMessage({ armor = true, detached = false, ...options }) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;
    if (typeof options.format === 'undefined') {
        options.format = armor ? 'armored' : 'object';
    }

    if (typeof options.data === 'string') {
        options.message = await openpgpCreateMessage({
            text: removeTrailingSpaces(options.data),
            filename: options.filename
        });
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = await openpgpCreateMessage({ binary: options.data, filename: options.filename });
    }

    delete options.data;

    if (options.returnSessionKey) {
        options.sessionKey = await generateSessionKey({ encryptionKeys: options.encryptionKeys });
    }
    delete options.returnSessionKey;

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    if (detached) {
        const signOptions = {
            message: options.message,
            signingKeys: options.signingKeys,
            date: options.date,
            format: 'object',
            detached: true
        };

        // Create detached signature of message
        const signature = await sign(signOptions);

        // Encrypt message without signing it
        options.signingKeys = [];
        const result = {
            message: await encrypt(options)
        };
        if (options.sessionKey) {
            result.sessionKey = options.sessionKey;
        }

        // Encrypt signature and add it to the final result
        options.message = await createMessage(signature.write());
        options.sessionKey = result.sessionKey;
        const encryptedSignature = await encrypt(options);
        result.encryptedSignature = encryptedSignature;

        // Add plain signature for backward compatibility
        result.signature = signature;
        result.sessionKey = options.sessionKey;

        return result;
    }

    const result = {
        message: await encrypt(options)
    };

    if (options.sessionKey) {
        result.sessionKey = options.sessionKey;
    }
    return result;
}
