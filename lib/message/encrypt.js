import { isStream, passiveClone, clone } from '@openpgp/web-stream-tools';
import { generateSessionKey, encrypt, sign, createMessage, armor as openpgp_armor, enums } from '../openpgp';
import { serverTime } from '../serverTime';
import { removeTrailingSpaces } from './utils';
import { getNotationForContext } from './context';

export default async function encryptMessage({
    textData,
    binaryData,
    stripTrailingSpaces,
    signatureContext,
    format = 'armored',
    date = serverTime(),
    detached = false,
    ...options
}) {
    if (signatureContext && (options.signingKeys === undefined || options.signingKeys.length === 0)) {
        // sanity check to catch mistakes in case library users wrongly consider the `context` to be
        // applied into e.g. the AEAD associated data
        throw new Error('Unexpected `signatureContext` input without any `signingKeys` provided');
    }

    const sanitizedOptions = {
        ...options,
        signatureNotations: signatureContext ?
            getNotationForContext(signatureContext.value, signatureContext.critical) :
            undefined,
        date,
        format
    };
    const dataType = binaryData ? 'binary' : 'text';
    const data = binaryData || (stripTrailingSpaces ? removeTrailingSpaces(textData) : textData); // throw if streamed text and stripTrailingSpaces enabled

    if (!options.sessionKey) {
        sanitizedOptions.sessionKey = await generateSessionKey({
            encryptionKeys: sanitizedOptions.encryptionKeys,
            date: sanitizedOptions.date,
            encryptionUserIDs: sanitizedOptions.encryptionUserIDs,
            config: sanitizedOptions.config
        });
    }

    const result = {};

    if (detached) {
        if (format === 'object') {
            // Supporting streamed data with object output is complicated, and right now we do not have a use case for that.
            // If an object is needed from non-streamed input, the caller should just request armor/binary output and then parse the result.
            throw new Error('Unsupported detached signature when requesting "object" result');
        }

        const detachedSignatureBinary = await sign({
            message: await createMessage({
                [dataType]: isStream(data) ? passiveClone(data) : data,
                date
            }),
            signingKeys: sanitizedOptions.signingKeys,
            signingKeyIDs: sanitizedOptions.signingKeyIDs,
            signingUserIDs: sanitizedOptions.signingUserIDs,
            signatureNotations: sanitizedOptions.signatureNotations,
            date: sanitizedOptions.date,
            config: sanitizedOptions.config,
            format: 'binary',
            detached: true
        });

        result.encryptedSignature = await encrypt({
            ...sanitizedOptions,
            signingKeys: [],
            message: await createMessage({ binary: clone(detachedSignatureBinary), date }) // clone is very cheap for non-stream binary data (it just returns a subarray)
        });

        result.signature = format === 'armored'
            ? openpgp_armor(enums.armor.signature, detachedSignatureBinary)
            : detachedSignatureBinary;
    }

    result.message = await encrypt({
        ...sanitizedOptions,
        message: await createMessage({ [dataType]: data, date }),
        // Encrypt message without signing it if we store a separate detached signature
        signingKeys: detached ? [] : sanitizedOptions.signingKeys
    });

    return result;
}
