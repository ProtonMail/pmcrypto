import {
    DecryptOptions,
    DecryptMessageResult as openpgp_DecryptMessageResult,
    Message,
    Key,
    Signature,
    SignOptions,
    EncryptOptions,
    VerifyOptions,
    VerifyMessageResult as openpgp_VerifyMessageResult,
    reformatKey,
    generateKey,
    PrivateKey,
    PublicKey,
    SessionKey,
    EncryptSessionKeyOptions,
    decryptSessionKeys as openpgp_decryptSessionKeys,
    WebStream,
    CleartextMessage,
    KeyOptions as GenerateKeyOptions,
    UserID,
    PartialConfig
} from 'openpgp/lightweight';

type MaybeArray<T> = T | T[];

export function init(): void;

export enum VERIFICATION_STATUS {
    NOT_SIGNED = 0,
    SIGNED_AND_VALID = 1,
    SIGNED_AND_INVALID = 2
}

export enum SIGNATURE_TYPES {
    BINARY = 0,
    CANONICAL_TEXT = 1
}

export type OpenPGPKey = Key;
export type OpenPGPMessage = Message<Uint8Array | string>; // TODO missing streaming support
export type OpenPGPSignature = Signature;

export { generateKey, reformatKey };
export type { PrivateKey, PublicKey, GenerateKeyOptions, Key, SessionKey };

export interface ReformatKeyOptions {
    privateKey: PrivateKey;
    userIDs?: MaybeArray<UserID>;
    passphrase?: string;
    keyExpirationTime?: number;
    date?: Date,
    format?: GenerateKeyOptions['format'],
    config?: PartialConfig
}

export interface DecryptLegacyOptions extends Omit<DecryptOptions, 'message'> {
    message: string;
    messageDate: Date;
}

export interface DecryptMimeOptions extends DecryptLegacyOptions {
    headerFilename?: string;
    sender?: string;
}

export function encryptPrivateKey(key: OpenPGPKey, password: string): Promise<string>;
export function decryptPrivateKey(serialisedKey: string | Uint8Array, password: string): Promise<PrivateKey>;

export function encodeUtf8(str: string): string;
export function encodeUtf8(str: undefined): undefined;

export function decodeUtf8(str: string): string;
export function decodeUtf8(str: undefined): undefined;

export function encodeBase64(str: string): string;
export function encodeBase64(str: undefined): undefined;

export function decodeBase64(str: string): string;
export function decodeBase64(str: undefined): undefined;

export function encodeUtf8Base64(str: string): string;
export function encodeUtf8Base64(str: undefined): string;

export function decodeUtf8Base64(str: string): string;
export function decodeUtf8Base64(str: undefined): undefined;

export function stringToUtf8Array(str: string): Uint8Array;
export function utf8ArrayToString(bytes: Uint8Array): string;

export function binaryStringToArray(str: string): Uint8Array;

export function arrayToBinaryString(bytes: Uint8Array): string;

export function arrayToHexString(bytes: Uint8Array): string;

export function concatArrays(data: Uint8Array[]): Uint8Array;

export function getKeys(serializedKeys: string | Uint8Array): Promise<OpenPGPKey[]>;
export function getKey(serializedKey: string | Uint8Array): Promise<OpenPGPKey>;

export function getFingerprint(key: OpenPGPKey): string;

export function isExpiredKey(key: OpenPGPKey, date?: Date): Promise<boolean>;
export function isRevokedKey(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function generateSessionKey(algoName: 'aes128' | 'aes192' | 'aes256'): Promise<Uint8Array>;
export function generateSessionKeyFromKeyPreferences(publicKeys: OpenPGPKey | OpenPGPKey[]): Promise<SessionKey>;

export interface EncryptSessionKeyOptionsPmcrypto extends EncryptSessionKeyOptions {}
export function encryptSessionKey<F extends EncryptSessionKeyOptionsPmcrypto['format'] = 'armored'>(
    options: EncryptSessionKeyOptionsPmcrypto & { format?: F }
): Promise<
    F extends 'armored' ? string :
    F extends 'binary' ? Uint8Array :
    F extends 'object' ? OpenPGPMessage :
    never
>;

export type DecryptSessionKeyOptionsPmcrypto = Parameters<typeof openpgp_decryptSessionKeys>[0];
// This differs from `openpgp.decryptSessionKeys` in the return type
export function decryptSessionKey(options: DecryptSessionKeyOptionsPmcrypto): Promise<SessionKey | undefined>;

export interface DecryptOptionsPmcrypto<T extends MaybeStream<Data>> extends DecryptOptions {
    message: Message<T>;
    encryptedSignature?: Message<MaybeStream<Data>>;
}

export interface DecryptResultPmcrypto<T extends openpgp_DecryptMessageResult['data'] = MaybeStream<Data>> {
    data: T;
    signatures: T extends WebStream<Data> ? Promise<OpenPGPSignature[]> : OpenPGPSignature[];
    filename: string;
    verified: T extends WebStream<Data> ? Promise<VERIFICATION_STATUS> : VERIFICATION_STATUS;
    errors?: T extends WebStream<Data> ? Promise<Error[]> : Error[];
}

export function decryptMessage<T extends MaybeStream<Data>, F extends DecryptOptions['format'] = 'utf8'>(
    options: DecryptOptionsPmcrypto<T> & { format?: F }
): Promise<
    F extends 'utf8' ?
        T extends WebStream<Data> ?
            DecryptResultPmcrypto<WebStream<string>> :
            DecryptResultPmcrypto<string> :
    F extends 'binary' ?
        T extends WebStream<Data> ?
            DecryptResultPmcrypto<WebStream<Uint8Array>> :
            DecryptResultPmcrypto<Uint8Array> :
    never
>;

export function decryptMessageLegacy<
    T extends MaybeStream<Data> = MaybeStream<Data>,
    F extends DecryptLegacyOptions['format'] = 'utf8'
>(options: DecryptLegacyOptions & { format?: F }): Promise<
    // output type cannot be statically determined:
    // string for legacy messages, but either string or Uint8Array output for non-legacy ones (depending on options.format)
    F extends 'utf8' ?
        T extends WebStream<Data> ?
            DecryptResultPmcrypto<WebStream<string>> :
            DecryptResultPmcrypto<string> :
    F extends 'binary' ?
        T extends WebStream<Data> ?
            DecryptResultPmcrypto<WebStream<Uint8Array | string>> :
            DecryptResultPmcrypto<Uint8Array | string> :
    never
>;

export function decryptMIMEMessage(options: DecryptMimeOptions): Promise<{
    getBody: () => Promise<{ body: string; mimetype: string } | undefined>;
    getAttachments: () => Promise<any>;
    getEncryptedSubject: () => Promise<string>;
    verify: () => Promise<number>;
    errors: () => Promise<Error[] | undefined>;
    signatures: OpenPGPSignature[];
}>;

export type MaybeStream<T extends Uint8Array | string> = T | WebStream<T>;
export type Data = string | Uint8Array;
export { WebStream };

export interface EncryptOptionsPmcrypto<T extends MaybeStream<Data>> extends Omit<EncryptOptions, 'message'> {
    textData?: T extends MaybeStream<string> ? T : never;
    binaryData?: T extends MaybeStream<Uint8Array> ? T : never;
    stripTrailingSpaces?: T extends MaybeStream<string> ? boolean : never;
    detached?: boolean;
}

// No reuse from OpenPGP's equivalent
export interface EncryptResult<HasSessionKey extends boolean, M, S = undefined, E = undefined> {
    sessionKey: HasSessionKey extends true ? SessionKey : undefined;
    message: M;
    signature: S;
    encryptedSignature: E;
}

export function encryptMessage<
    T extends MaybeStream<Data>,
    F extends EncryptOptions['format'] = 'armored', // extends 'string' also works, but it gives unclear error if passed unexpected 'format' values
    D extends boolean = false,
    SK extends boolean = false
>(
    options: EncryptOptionsPmcrypto<T> & { format?: F; detached?: D; returnSessionKey?: SK }
): Promise<
    F extends 'armored' ?
        D extends true ?
            T extends WebStream<Data> ?
                EncryptResult<SK, WebStream<string>, WebStream<string>, WebStream<string>> :
                EncryptResult<SK, string, string, string> :
            T extends WebStream<Data> ?
                EncryptResult<SK, WebStream<string>> : EncryptResult<SK, string> :
    F extends 'binary' ?
        D extends true ?
            T extends WebStream<Data> ?
                EncryptResult<SK, WebStream<Uint8Array>, WebStream<Uint8Array>, WebStream<Uint8Array>> :
                EncryptResult<SK, Uint8Array, Uint8Array, Uint8Array> :
            T extends WebStream<Data> ?
                EncryptResult<SK, WebStream<Uint8Array>> : EncryptResult<SK, Uint8Array> :
    F extends 'object' ?
        D extends true ?
            never : // unsupported
            EncryptResult<SK, OpenPGPMessage> :
    never
>;

export function getMatchingKey(
    signature: OpenPGPSignature | OpenPGPMessage,
    publicKeys: OpenPGPKey[]
): OpenPGPKey | undefined;

export interface SignOptionsPmcrypto<T extends MaybeStream<Data>> extends Omit<SignOptions, 'message'> {
    textData?: T extends MaybeStream<string> ? T : never;
    binaryData?: T extends MaybeStream<Uint8Array> ? T : never;
    stripTrailingSpaces?: T extends MaybeStream<string> ? boolean : never;
}

export function signMessage<
    T extends MaybeStream<Data>,
    F extends SignOptions['format'] = 'armored',
    D extends boolean = false
>(
    options: SignOptionsPmcrypto<T> & { format?: F; detached?: D }
): Promise<
    F extends 'armored' ?
        T extends WebStream<Data> ? WebStream<string> : string :
    F extends 'binary' ?
        T extends WebStream<Data> ? WebStream<Uint8Array> : Uint8Array :
    F extends 'object' ?
        D extends true ? OpenPGPMessage : OpenPGPSignature :
    never
>;

export function getSignature(option: string | Uint8Array | OpenPGPSignature): Promise<OpenPGPSignature>;

export function getMessage(message: OpenPGPMessage | Uint8Array | string): Promise<OpenPGPMessage>;
export function getCleartextMessage(message: CleartextMessage | string): Promise<CleartextMessage>;

export function splitMessage(message: OpenPGPMessage | Uint8Array | string): Promise<{
    asymmetric: Uint8Array[];
    signature: Uint8Array[];
    symmetric: Uint8Array[];
    compressed: Uint8Array[];
    literal: Uint8Array[];
    encrypted: Uint8Array[];
    other: Uint8Array[];
}>;

export function armorBytes(value: Uint8Array | string): Promise<string>;

export interface AlgorithmInfo {
    algorithm: string;
    bits?: number; // if algorithm == 'rsaEncryptSign' | 'rsaEncrypt' | 'rsaSign'
    curve?: string; // if algorithm == 'ecdh' | 'eddsa' | 'ecdsa'
}

export function SHA256(arg: Uint8Array): Promise<Uint8Array>;
export function SHA512(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeMD5(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeSHA1(arg: Uint8Array): Promise<Uint8Array>;

// Streaming not supported when verifying detached signatures
export interface VerifyOptionsPmcrypto<T extends Data> extends Omit<VerifyOptions, 'message'> {
    textData?: T extends string ? T : never;
    binaryData?: T extends Uint8Array ? T : never;
    stripTrailingSpaces?: T extends string ? boolean : never;
}

export interface VerifyMessageResult<D extends openpgp_VerifyMessageResult['data'] = Data> {
    data: D;
    verified: VERIFICATION_STATUS;
    signatures: OpenPGPSignature[];
    signatureTimestamp: Date | null;
    errors?: Error[];
}
export function verifyMessage<T extends Data, F extends VerifyOptions['format'] = 'utf8'>(
    options: VerifyOptionsPmcrypto<T> & { format?: F }
): Promise<
    F extends 'utf8' ?
        VerifyMessageResult<string> :
    F extends 'binary' ?
        VerifyMessageResult<Uint8Array> :
    never
>;

export interface VerifyCleartextOptionsPmcrypto extends Omit<VerifyOptions, 'message' | 'signature' | 'format'> {
    cleartextMessage: CleartextMessage
}
// Cleartext message data is always of utf8 format
export function verifyCleartextMessage(
    options: VerifyCleartextOptionsPmcrypto
): Promise<VerifyMessageResult<string>>;

export interface ProcessMIMEOptions {
    data: string,
    verificationKeys?: PublicKey[],
    date?: Date,
    headerFilename?: string;
    sender?: string;
}

// TODO? this definition is copied as-is from the webapps; some fields declared as optional might actually always be present
export interface MIMEAttachment {
    checksum?: string;
    content: Uint8Array;
    contentDisposition?: string;
    contentId?: string;
    contentType?: string;
    fileName?: string;
    generatedFileName?: string;
    length?: number;
    transferEncoding?: string;
}

export interface ProcessMIMEResult {
    body?: string,
    attachments: MIMEAttachment[],
    verified: VERIFICATION_STATUS,
    encryptedSubject: string,
    mimetype?: 'text/html' | 'text/plain',
    signatures: Signature[]
}

export function processMIME(options: ProcessMIMEOptions): Promise<ProcessMIMEResult>;

export function serverTime(): Date;
export function updateServerTime(serverDate: Date): Date;

export function getSHA256Fingerprints(key: OpenPGPKey): Promise<string[]>;

export function canKeyEncrypt(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function checkKeyStrength(key: OpenPGPKey): void;
