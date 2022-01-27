import { isStream, passiveClone, clone } from '@openpgp/web-stream-tools';
import { generateSessionKey, encrypt, sign, createMessage, armor as openpgp_armor, enums } from '../openpgp';
import { serverTime } from '../serverTime';
import { removeTrailingSpaces } from './utils';

/**
 * Clone the data if it is streamed
 * @param {any | ReadableStream<any>} data - data to clone, if streamed
 * @param {Boolean} passive - whether to return a passive clone
 * @returns clone of data stream, or data
 */
const cloneIfStream = (data, passive = false) => {
    if (!isStream(data)) return data;
    return passive ? passiveClone(data) : clone(data);
};

const createMessageFromPassiveStreamClone = ({ text, binary, date = serverTime(), ...options }) => {
    const dataType = binary ? 'binary' : 'text';
    const data = binary || text;
    return createMessage({
        [dataType]: cloneIfStream(data, true),
        date,
        ...options
    })
}

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
            message: await createMessageFromPassiveStreamClone({ [dataType]: data }),
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
            message: await createMessage({ binary: cloneIfStream(detachedSignatureBinary) })
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
