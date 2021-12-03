import { generateSessionKey, encrypt, sign, createMessage } from 'openpgp';
import { readToEnd, pipe, transformPair } from '@openpgp/web-stream-tools';
import { serverTime } from '../serverTime';

export default async function encryptMessage({
    returnSessionKey,
    date = serverTime(),
    armor = true,
    detached = false,
    ...options
}) {
    const sanitizedOptions = { ...options, date };

    if (!options.format) {
        sanitizedOptions.format = armor ? 'armored' : 'object'; // TODO change, remove `armor` param?
    }

    if (!options.sessionKey) {
        sanitizedOptions.sessionKey = await generateSessionKey({
            encryptionKeys: sanitizedOptions.encryptionKeys,
            date: sanitizedOptions.date,
            encryptionUserIDs: sanitizedOptions.encryptionUserIDs,
            config: sanitizedOptions.config
        });
    }

    const result = {};
    if (returnSessionKey) {
        result.sessionKey = sanitizedOptions.sessionKey;
    }

    if (detached) {
        // Add cleartext signature for backward compatibility
        const { message } = sanitizedOptions;
        if (message.fromStream) {
            // TODO clone input stream -- sanitizedOptions.message.fromStream ? await readMessage({ clone(<input data>) }) : sanitizedOptions.message;
            throw new Error('Encrypting and detached-signing a message created from a stream is not supported yet');
        }
        const signature = await sign({
            message,
            signingKeys: sanitizedOptions.signingKeys,
            signingKeyIDs: sanitizedOptions.signingKeyIDs,
            signingUserIDs: sanitizedOptions.signingUserIDs,
            date: sanitizedOptions.date,
            config: sanitizedOptions.config,
            format: 'object',
            detached: true
        });
        result.signature = armor ? signature.armor() : signature;
        if (message.fromStream) {
            result.signature = await readToEnd(
                transformPair(message.packets.write(), async (readable, writable) => {
                    await Promise.all([pipe(result.signature, writable), readToEnd(readable).catch(() => {})]);
                })
            );
        }
        // Encrypt signature
        result.encryptedSignature = await encrypt({
            ...sanitizedOptions,
            // TODO clone if streaming signature
            message: await createMessage({ binary: signature.packets.write() })
        });
    }

    const encrypted = await encrypt({
        ...sanitizedOptions,
        // Encrypt message without signing it if we store a separate detached signature
        signingKeys: detached ? [] : sanitizedOptions.signingKeys
    });

    if (armor) {
        result.data = encrypted;
    } else {
        result.message = encrypted;
    }

    return result;
}
