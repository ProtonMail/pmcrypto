import { getSignature, verifyMessage, createCleartextMessage } from './utils';
import { VERIFICATION_STATUS, MAX_ENC_HEADER_LENGTH } from '../constants';

/**
 * Parse a mail into an object format, splitting, headers, html, text/plain and attachments. The result is defined
 * by the MailParser. This function wraps the mailparser to make it a promise.
 * @param data
 * @return {Promise}
 */
export const parseMail = (data) => {
    return new Promise((resolve, reject) => {
        import('./mailparser')
            .then(({ default: MailParser }) => {
                const mailparser = new MailParser({ defaultCharset: 'UTF-8' });
                mailparser.on('end', resolve);
                mailparser.write(data);
                mailparser.end();
            })
            .catch(reject);
    });
};

const verifySignature = async ({ publicKeys = [], date }, data) => {
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

    const { data: subdata, verified, signatures } = await verifyMessage({
        message: createCleartextMessage(body),
        publicKeys,
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
 * @param headerFilename The file name a memoryhole header should have
 * @param sender the address of the sender of this message
 * @param content
 * @param verified
 * @returns {Promise.<*>}
 */
const parse = async (
    { headerFilename = 'Encrypted Headers.txt', sender = null },
    content = '',
    verified = VERIFICATION_STATUS.NOT_VERIFIED,
    signatures
) => {
    const data = await parseMail(content);
    // cf. https://github.com/autocrypt/memoryhole subject can be in the MIME headers
    const { attachments = [], text = '', html = '', subject: mimeSubject = false } = data;

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
            const from = headers.from
                .split('<')
                .pop()
                .replace('>', '')
                .trim()
                .toLowerCase();
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
            attachments,
            verified,
            encryptedSubject,
            signatures
        };
    }
    throw new Error('No body or attachments found in the mime message');
};

/**
 * Process the mime structure in the right attachment.
 * @param options
 * @param data
 * @return {Promise<*>}
 */
export default async function processMIME(options, data) {
    const { subdata, verified, signatures } = await verifySignature(options, data);

    return parse(options, subdata, verified, signatures);
}
