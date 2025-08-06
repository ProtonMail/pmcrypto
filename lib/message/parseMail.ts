// NB: using `export type` is important to ensure we do not import the library unless parseMail (below) is called
export type { Attachment } from 'jsmimeparser';

/**
 * Parse a mail into an object format, splitting, headers, html, text/plain and attachments.
 * As jsmime is not a small library, we only want to import it if it's actually used.
 */
export const parseMail = (mail: string | Uint8Array<ArrayBuffer>) => import('jsmimeparser').then(({ parseMail: jsmimeParseEmail }) => jsmimeParseEmail(mail));

// Mapping between mime types to the corresponding extensions.
// This is only used if the parsed attachment does not include a filename.
// For size reasons, we only support a small subset of mime types, that includes primarily standard types
// and in particular those types for which the web apps display a custom file icon.
const mimeExtensions: { [type: string]: string } = {
    'application/octet-stream': 'bin',
    'application/x-rar-compressed': 'rar',
    'application/x-zip-compressed': 'zip',
    'application/zip': 'zip',
    'application/x-7z-compressed': '7z',
    'application/x-arj': 'arj',
    'application/x-debian-package': 'deb',
    'application/x-redhat-package-manager': 'rpm',
    'application/x-rpm': 'rpm',
    'application/vnd.rar': 'rar',
    'application/gzip': 'gz',
    'application/x-gzip': 'gz',
    'application/x-compress': 'z',
    'application/vnd.apple.installer+xml': 'pkg',
    'application/msword': 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
    'application/vnd.ms-powerpoint': 'ppt',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/vnd.oasis.opendocument.spreadsheet': 'ods',
    'application/vnd.oasis.opendocument.presentation': 'odp',
    'application/xliff+xml': 'xlf',
    'application/xml': 'xml',
    'text/html': 'html',
    'application/xhtml+xml': 'xhtml',
    'application/pgp-keys': 'asc',
    'application/rtf': 'rtf',
    'application/x-tex': 'tex',
    'application/vnd.oasis.opendocument.text': 'odt',
    'application/vnd.wordperfect': 'wpd',
    'application/vnd.ms-fontobject': 'eot',
    'application/font-sfnt': 'ttf',
    'application/vnd.oasis.opendocument.formula-template': 'odft',

    'application/x-bzip': 'bz',
    'application/x-bzip2': 'bzip2',
    'application/epub+zip': 'epub',
    'application/javascript': 'js',
    'application/json': 'json',
    'application/pdf': 'pdf',
    'application/pgp-encrypted': 'pgp',
    'application/pgp-signature': 'asc',
    'application/pkcs7-mime': 'p7m',
    'application/pkcs7-signature': 'p7s',
    'audio/aac': 'aac',
    'audio/midi': 'midi',
    'audio/x-midi': 'midi',
    'audio/ogg': 'oga',
    'audio/mp3': 'mp3',
    'audio/mp4': 'm4a',
    'audio/mpeg': 'mpga',
    'font/otf': 'otf',
    'font/ttf': 'ttf',
    'font/woff': 'woff',
    'font/woff2': 'woff2',
    'image/avif': 'avif',
    'image/bmp': 'bmp',
    'image/jpeg': 'jpeg',
    'image/png': 'png',
    'image/svg+xml': 'svg',
    'image/tiff': 'tif',
    'message/rfc822': 'eml',
    'text/calendar': 'ics',
    'text/css': 'css',
    'text/csv': 'csv',
    'text/markdown': 'md',
    'text/plain': 'txt',
    'text/richtext': 'rtx',
    'text/vcard': 'vcard',
    'text/xml': 'xml',
    'text/yaml': 'yaml',
    'video/x-msvideo': 'avi',
    'video/mp4': 'mp4',
    'video/mpeg': 'mpeg',
    'video/quicktime': 'mov',
    'video/webm': 'webm',
    'video/ogg': 'ogv'
};

/**
 * Normalise parsed filename if present, otherwise generate a new one, trying to infer the file extension based
 * on the provided content type.
 */
export const generateFileName = (parsedFileName?: string, contentType?: string) => {
    // The (old) MailParser used to return a generatedFileName, see https://github.com/nodemailer/mailparser/issues/238
    // now we generate it here instead, using a similar but simplified function  (e.g. we support fewer default extensions).

    const defaultExt = !parsedFileName && contentType ? mimeExtensions[contentType] : '';
    const fileName = parsedFileName || (defaultExt ? `attachment.${defaultExt}` : 'attachment');

    // remove path if it is included in the filename
    return fileName.split(/[/\\]+/).pop()?.replace(/^\.+/, '') || 'attachment';
};
