import { createMessage, sign } from '../openpgp';
import { serverTime } from '../serverTime';
import { getNotationForContext } from './context';
import { removeTrailingSpaces } from './utils';

/**
 * Get a signed message from the given data.
 * Either `textData` or `binaryData` must be specified.
 * @param {Object} options - input for openpgp.sign
 * @param {String|ReadableStream<String>} textData - text data to sign
 * @param {Uint8Array|ReadableStream<Uint8Array>} binaryData - binary data to sign
 * @param {Boolean} stripTrailingSpaces - whether trailing spaces should be removed from `textData`
 * @returns Promise<{Message|Signature|MaybeStream<String>|MaybeStream<Uint8Array>}> signed message object, signature object, or corresponding serialised data
 * @throws on signing error
 */
export default async function signMessage({
    textData,
    binaryData,
    stripTrailingSpaces,
    context,
    date = serverTime(),
    format = 'armored',
    ...options
}) {
    const dataType = binaryData ? 'binary' : 'text';
    const data = binaryData || (stripTrailingSpaces ? removeTrailingSpaces(textData) : textData); // throw if streamed text and stripTrailingSpaces enabled
    const sanitizedOptions = {
        ...options,
        date,
        format,
        message: await createMessage({ [dataType]: data, date }),
        signatureNotations: context ? getNotationForContext(context.value, context.critical) : undefined
    };

    return sign(sanitizedOptions).catch((err) => {
        console.error(err);
        return Promise.reject(err);
    });
}
