/// <reference path="./verify.d.ts" />

import { removeTrailingSpaces } from './utils';
import { verifyMessage } from './verify';
import { VERIFICATION_STATUS, MAX_ENC_HEADER_LENGTH } from '../constants';
import { serverTime } from '../serverTime';
import { parseMail, generateFileName } from './parseMail';
import { readSignature, PublicKey, MaybeArray, Signature as OpenPGPSignature } from '../openpgp';
import { arrayToHexString, utf8ArrayToString } from '../utils';

import type { Attachment } from './parseMail';

export interface MIMEAttachment extends Attachment {
    /**
     * `content-id` header value if present, otherwise a unique random value
     */
    contentId: string;
    /**
     * Original attachment file name, properly cleaned, or generated file name with extention based on MIME type.
     * Multiple attachments from the same message will always have different filenames (a counter value is appended to identical names)
     */
    fileName: string;
}

type VerifySignatureOptions = Pick<ProcessMIMEOptions, 'verificationKeys' | 'date'>;
const verifySignature = async (
    { verificationKeys = [], date = serverTime() }: VerifySignatureOptions,
    data: string
) => {
    const { headers } = await parseMail(data.split(/\r?\n\s*\r?\n/g)[0] + '\n\n');
    const [contentType] = headers['content-type'] || [''];
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
    const { attachments: [sigAttachment] = [] } = await parseMail(parts[2].trim());

    const { contentType: sigAttachmentContentType = '', content: sigAttachmentContent = new Uint8Array() } = sigAttachment || {};
    if (sigAttachmentContentType.toLowerCase() !== 'application/pgp-signature') {
        return { subdata: data, verified: 0, signatures: [] };
    }
    const sigData = utf8ArrayToString(sigAttachmentContent);

    const signature = await readSignature({ armoredSignature: sigData });
    const body = parts[1];

    const {
        data: subdata,
        verified,
        signatures
    } = await verifyMessage({
        // The body is to be treated as CleartextMessage, see https://github.com/openpgpjs/openpgpjs/pull/1265#issue-830304843
        textData: removeTrailingSpaces(body).replaceAll('\n', '\r\n'),
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
 * @param options
 * @param options.headerFilename - The file name a memoryhole header should have
 * @param options.sender - the address of the sender of this message
 * @param content - mail content to parse
 * @param verified
 * @param signatures
 */
const parse = async (
    { headerFilename = 'Encrypted Headers.txt', sender = '' },
    mailContent = '',
    verified = VERIFICATION_STATUS.NOT_SIGNED,
    signatures: OpenPGPSignature[] = []
): Promise<ProcessMIMEResult> => {
    // cf. https://github.com/autocrypt/memoryhole subject can be in the MIME headers
    const { attachments: parsedAttachments = [], body: { text = '', html = '' }, subject: mimeSubject = '' } = await parseMail(mailContent);

    // normalise attachments and look for encrypted subject
    let encryptedSubjectHeader;
    const attachments: MIMEAttachment[] = [];
    const fileNameCounter: { [key: string]: number } = {}; // track duplicate file names
    for (const parsedAttachment of parsedAttachments) {
        let generatedFileName = generateFileName(parsedAttachment.fileName, parsedAttachment.contentType);
        // rename attachments with the same name
        if (fileNameCounter[generatedFileName]) {
            generatedFileName = `${generatedFileName} (${fileNameCounter[generatedFileName]++})`;
        } else {
            fileNameCounter[generatedFileName] = 1;
        }

        const attachment = {
            ...parsedAttachment,
            fileName: generatedFileName,
            contentId: parsedAttachment.contentId || `<${arrayToHexString(crypto.getRandomValues(new Uint8Array(16)))}@pmcrypto>`
        };
        attachments.push(attachment);

        // cf. https://github.com/autocrypt/memoryhole
        if (
            parsedAttachment.fileName ||
            parsedAttachment.contentType !== 'text/rfc822-headers' ||
            parsedAttachment.content.length > MAX_ENC_HEADER_LENGTH
        ) {
            continue;
        }
        // probably some encrypted headers, not sure about the subjects yet. We don't want to attach them on reply
        // the headers for this current message shouldn't be carried over to the next message.
        attachment.fileName = `${headerFilename}.txt`;
        attachment.contentDisposition = 'attachment';
        const { from, subject: attachmentSubject } = await parseMail(utf8ArrayToString(parsedAttachment.content));
        // check for subject headers and from headers to match the current message with the right sender.
        if (!attachmentSubject || !from) {
            continue;
        }
        const fromEmail = from
            .split('<')
            .pop()
            ?.replace('>', '')
            .trim()
            .toLowerCase() || '';
        if (fromEmail !== sender.toLowerCase()) {
            continue;
        }
        // found the encrypted subject:
        encryptedSubjectHeader = encryptedSubjectHeader || attachmentSubject;
    }

    const encryptedSubject = encryptedSubjectHeader || mimeSubject;

    if (html) {
        return {
            body: html,
            attachments,
            verified,
            encryptedSubject,
            mimeType: 'text/html',
            signatures
        };
    }
    if (text) {
        return {
            body: text,
            attachments,
            verified,
            encryptedSubject,
            mimeType: 'text/plain',
            signatures
        };
    }
    if (attachments.length) {
        return {
            body: '',
            attachments,
            verified,
            encryptedSubject,
            mimeType: undefined,
            signatures
        };
    }
    throw new Error('No body or attachments found in the mime message');
};

export interface ProcessMIMEOptions {
    data: string,
    verificationKeys?: MaybeArray<PublicKey>,
    date?: Date,
    headerFilename?: string;
    sender?: string;
}

export interface ProcessMIMEResult {
    body: string,
    attachments: MIMEAttachment[],
    verified: VERIFICATION_STATUS,
    encryptedSubject: string,
    mimeType?: 'text/html' | 'text/plain',
    signatures: OpenPGPSignature[]
}
/**
 * Process the mime structure in the right attachment.
 * @param options - options for signature verification and MIME processing
 * @param options.data - MIME data to process
 * @param options.verificationKeys
 * @param options.date - to use for signature verification, instead of the server time
 * @param options.headerFilename - the file name a memoryhole header should have
 * @param options.sender - the address of the sender of this message
 */
export default async function processMIME({ data, ...options }: ProcessMIMEOptions): Promise<ProcessMIMEResult> {
    const { subdata, verified, signatures } = await verifySignature(options, data);

    return parse(options, subdata, verified, signatures);
}
