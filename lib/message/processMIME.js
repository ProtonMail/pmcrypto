import { getSignature, verifyMessage, removeTrailingSpaces } from './utils';
import { VERIFICATION_STATUS, MAX_ENC_HEADER_LENGTH } from '../constants';
import { serverTime } from '../serverTime';
import { parseMail } from './parseMail';

const verifySignature = async ({ verificationKeys = [], date = serverTime() }, data) => {
    const { headers } = await parseMail(data.split(/\r?\n\s*\r?\n/g)[0] + '\n\n');
    const contentType = headers['content-type'] || '';
    const [baseContentType] = contentType.split(';');
    if (baseContentType.toLowerCase() !== 'multipart/signed') {
        return { subdata: data, verified: 0, signatures: [] };
    }
    const [, rawboundary] = /boundary\s*=\s*([^;]*)\s*(;|$)/gi.exec(contentType) || [];
    if (!rawboundary) {
        return { subdata: data, verified: 0, signatures: [] };
    }
    const boundary = rawboundary[0] === '"' ? JSON.parse(rawboundary) || rawboundary : rawboundary;
    const [mainPart] = data.split(`\n--${boundary}--\n`);
    const parts = mainPart.split(`\n--${boundary}\n`);
    if (parts.length < 3) {
        return { subdata: data, verified: 0, signatures: [] };
    }
    const { attachments: [sigAttachment = {}] = [] } = await parseMail(parts[2].trim());

    const { contentType: sigAttachmentContentType = '', content: sigAttachmentContent = '' } = sigAttachment;
    if (sigAttachmentContentType.toLowerCase() !== 'application/pgp-signature') {
        return { subdata: data, verified: 0, signatures: [] };
    }
    const sigData = sigAttachmentContent.toString();

    const signature = await getSignature(sigData);
    const body = parts[1];

    const {
        data: subdata,
        verified,
        signatures
    } = await verifyMessage({
        // The body is to be treated as CleartextMessage, see https://github.com/openpgpjs/openpgpjs/pull/1265#issue-830304843
        textData: removeTrailingSpaces(body),
        verificationKeys,
        date,
        signature
    });

    return { subdata, verified, signatures };
};

/**
 * This function parses MIME format into attachments, content, encryptedSubject. The attachment automatically
 * inherit the verified status from the message verified status, as they are included in the body. For more
 * information see: https://tools.ietf.org/html/rfc2045, https://tools.ietf.org/html/rfc2046 and
 * https://tools.ietf.org/html/rfc2387.
 * @param {Object} options
 * @param {String} [options.headerFilename] - The file name a memoryhole header should have
 * @param {String} [options.sender] - the address of the sender of this message
 * @param {String} [content] - mail content to parse
 * @param {VERIFICATION_STATUS} [verified]
 * @param {Signature[]} [signatures]
 * @returns {Promise<{
 *      body: String,
 *      attachments: Object[],
 *      verified: VERIFICATION_STATUS,
 *      encryptedSubject: String,
 *      mimetype: 'text/html' | 'text/plain' | undefined,
 *      signatures: Signature[]
 * }>}
 */
const parse = async (
    { headerFilename = 'Encrypted Headers.txt', sender = '' },
    content = '',
    verified = VERIFICATION_STATUS.NOT_VERIFIED,
    signatures = []
) => {
    const data = await parseMail(content);
    // cf. https://github.com/autocrypt/memoryhole subject can be in the MIME headers
    const { attachments = [], text = '', html = '', subject: mimeSubject = '' } = data;

    const result = await Promise.all(
        attachments.map(async (att) => {
            const { headers } = await parseMail(att.content);
            // cf. https://github.com/autocrypt/memoryhole
            if (
                att.fileName ||
                att.contentType !== 'text/rfc822-headers' ||
                att.content.length > MAX_ENC_HEADER_LENGTH
            ) {
                return;
            }
            // probably some encrypted headers, not sure about the subjects yet. We don't want to attach them on reply
            // the headers for this current message shouldn't be carried over to the next message.
            att.generatedFileName = `${headerFilename}.txt`;
            att.contentDisposition = 'attachment';
            // check for subject headers and from headers to match the current message with the right sender.
            if (!headers.subject || !headers.from) {
                return;
            }
            const from = headers.from.split('<').pop().replace('>', '').trim().toLowerCase();
            if (from !== sender.toLowerCase()) {
                return;
            }
            // found the encrypted subject:
            return headers.subject;
        })
    );

    const [encryptedSubject = mimeSubject] = result.filter((i) => i);

    if (html) {
        return {
            body: html,
            attachments,
            verified,
            encryptedSubject,
            mimetype: 'text/html',
            signatures
        };
    }
    if (text) {
        return {
            body: text,
            attachments,
            verified,
            encryptedSubject,
            mimetype: 'text/plain',
            signatures
        };
    }
    if (attachments.length) {
        return {
            body: '',
            attachments,
            verified,
            encryptedSubject,
            mimetype: undefined,
            signatures
        };
    }
    throw new Error('No body or attachments found in the mime message');
};

/**
 * Process the mime structure in the right attachment.
 * @param {Object} options - options for signature verification and MIME processing
 * @param {String} options.data - MIME data to process
 * @param {PublicKey[]} [options.verificationKeys]
 * @param {Date} [options.date] - to use for signature verification, instead of the server time
 * @param {String} [options.headerFilename] - the file name a memoryhole header should have
 * @param {String} [options.sender] - the address of the sender of this message
 * @return {Promise<{
 *      body: String,
 *      attachments: Object[],
 *      verified: VERIFICATION_STATUS,
 *      encryptedSubject: String,
 *      mimetype: 'text/html' | 'text/plain' | undefined,
 *      signatures: Signature[]
 * }>}
 */
export default async function processMIME({ data, ...options}) {
    const { subdata, verified, signatures } = await verifySignature(options, data);

    return parse(options, subdata, verified, signatures);
}
