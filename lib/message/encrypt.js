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

    options.armor = armor;

    if (options.detached) {
        // Create detached signature of message
        const { signature } = await openpgp.sign({ ...options, armor: false, streaming: false });

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
    return openpgp.encrypt(options);
}
