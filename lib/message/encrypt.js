import { isStream, passiveClone, clone } from '@openpgp/web-stream-tools';
import { generateSessionKey, encrypt, sign, createMessage, armor as openpgp_armor, enums } from '../openpgp';
import { serverTime } from '../serverTime';
import { removeTrailingSpaces } from './utils';

export default async function encryptMessage({
    textData,
    binaryData,
    returnSessionKey,
    stripTrailingSpaces,
    date = serverTime(),
    armor = true,
    detached = false,
    ...options
}) {
    const sanitizedOptions = { ...options, date };
    const dataType = binaryData ? 'binary' : 'text';
    const data = binaryData || (stripTrailingSpaces ? removeTrailingSpaces(textData) : textData); // throw if streamed text and stripTrailingSpaces enabled

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
        if (!armor && isStream(data)) {
            throw new Error('Unsupported detached signature when streaming data and requesting non-armored result');
        }

        const detachedSignatureBinary = await sign({
            message: await createMessage({
                [dataType]: isStream(data) ? passiveClone(data) : data
            }),
            signingKeys: sanitizedOptions.signingKeys,
            signingKeyIDs: sanitizedOptions.signingKeyIDs,
            signingUserIDs: sanitizedOptions.signingUserIDs,
            date: sanitizedOptions.date,
            config: sanitizedOptions.config,
            format: 'binary',
            detached: true
        });

        result.encryptedSignature = await encrypt({
            ...sanitizedOptions,
            message: await createMessage({ binary: clone(detachedSignatureBinary) }) // clone is very cheap for non-stream binary data (it just returns a subarray)
        });

        result.signature = armor
            ? openpgp_armor(enums.armor.signature, detachedSignatureBinary)
            : detachedSignatureBinary;
    }

    const encrypted = await encrypt({
        ...sanitizedOptions,
        message: await createMessage({ [dataType]: data }),
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
