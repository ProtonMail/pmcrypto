import {
    DecryptOptions,
    DecryptMessageResult,
    Message,
    Key,
    User,
    KeyID,
    Signature,
    SignOptions,
    EncryptOptions,
    UserID,
    CleartextMessage,
    VerifyOptions,
    VerifyMessageResult as openpgp_VerifyMessageResult,
    reformatKey,
    generateKey,
    PrivateKey,
    SessionKey
} from 'openpgp';

export type Data = Uint8Array | string;

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
export type OpenPGPMessage = Message<Data>;
export type OpenPGPSignature = Signature;

// TODO (?) these actually differ from 'openpgp' in that the passphrase is required
export { generateKey, reformatKey }

export interface DecryptLegacyOptions extends Omit<DecryptOptions, 'message'> {
    message: string;
    messageDate: Date;
}

export interface DecryptMimeOptions extends DecryptLegacyOptions {
    headerFilename?: string;
    sender?: string;
}

// No reuse from OpenPGP's equivalent
export interface EncryptResult<D = undefined, M = undefined, S = undefined, E = undefined> {
    data: D;
    message: M;
    signature: S;
    sessionKey: SessionKey;
    encryptedSignature: E;
}

export interface BinaryResult {
    data: Uint8Array;
    filename?: string;
    signatures?: {
        keyid: KeyID;
        verified: Promise<boolean>;
        valid: boolean;
    }[];
}

export function encryptPrivateKey(key: OpenPGPKey, password: string): Promise<string>;
export function decryptPrivateKey(armoredKey: string, password: string): Promise<PrivateKey>;

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

export function getKeys(serializedKeys: String | Uint8Array): Promise<OpenPGPKey[]>;
export function getKey(serializedKey: String | Uint8Array): Promise<OpenPGPKey>;

export function getFingerprint(key: OpenPGPKey): string;

export function isExpiredKey(key: OpenPGPKey, date?: Date): Promise<boolean>;
export function isRevokedKey(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function generateSessionKey(algo: string): Promise<Uint8Array>;

export function encryptSessionKey(options: {
    data: Uint8Array;
    algorithm: string;
    aeadAlgo?: string;
    publicKeys?: any[];
    passwords?: any[];
    wildcard?: boolean;
    date?: Date;
    userIDs?: any[];
}): Promise<{ message: OpenPGPMessage }>;

export function decryptSessionKey(options: {
    message: OpenPGPMessage;
    privateKeys?: OpenPGPKey | OpenPGPKey[];
    passwords?: string | string[];
}): Promise<SessionKey | undefined>;

export interface DecryptOptionsPmcrypto extends DecryptOptions {
    encryptedSignature?: OpenPGPMessage;
}

export type DecryptResultPmcrypto = Omit<DecryptMessageResult, 'signatures'> & {
    signatures: (OpenPGPSignature)[];
    verified: VERIFICATION_STATUS;
    errors?: Error[];
}

export function decryptMessage(
    options: DecryptOptionsPmcrypto & { format: 'utf8' }
): Promise<DecryptResultPmcrypto & { data: string | ReadableStream<String> }>;
export function decryptMessage(
    options: DecryptOptionsPmcrypto & { format: 'binary' }
): Promise<DecryptResultPmcrypto & { data: Uint8Array | ReadableStream<Uint8Array> }>;
export function decryptMessage(options: DecryptOptionsPmcrypto): Promise<DecryptResultPmcrypto>;

export function decryptMessageLegacy(options: DecryptLegacyOptions): Promise<DecryptResultPmcrypto>;

export function decryptMIMEMessage(
    options: DecryptMimeOptions
): Promise<{
    getBody: () => Promise<{ body: string; mimetype: string } | undefined>;
    getAttachments: () => Promise<any>;
    getEncryptedSubject: () => Promise<string>;
    verify: () => Promise<number>;
    errors: () => Promise<Error[] | undefined>;
    signatures: OpenPGPSignature[];
}>;

export interface EncryptOptionsPmcryptoWithData extends Omit<EncryptOptions, 'message'> {
    data: Uint8Array | string;
    returnSessionKey?: boolean;
}
type EncryptOptionsPmcrypto = EncryptOptionsPmcryptoWithData | EncryptOptions;

export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor?: true; detached?: false }
): Promise<EncryptResult<string>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor?: true; detached: true }
): Promise<EncryptResult<string, undefined, string, string>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor: false; detached?: false }
): Promise<EncryptResult<undefined, OpenPGPMessage>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor: false; detached: true }
): Promise<EncryptResult<undefined, OpenPGPMessage, OpenPGPSignature, OpenPGPMessage>>;
export function encryptMessage( // TODO what is this for? redundant -- declare maybe streams above
    options: EncryptOptionsPmcrypto
): Promise<
    EncryptResult<
        string | ReadableStream<String>,
        OpenPGPMessage,
        string | ReadableStream<String> | OpenPGPSignature,
        string | ReadableStream<String> | OpenPGPMessage
    >
>;
export function getMatchingKey(
    signature: OpenPGPSignature,
    publicKeys: OpenPGPKey[]
): OpenPGPKey | undefined;

interface SignOptionsPmcryptoWithData extends Omit<SignOptions, 'message'> {
    data: string | Uint8Array;
}
type SignOptionsPmcrypto = SignOptionsPmcryptoWithData | SignOptions;

export function createMessage(
    data: string | ReadableStream<String> | Uint8Array,
    filename?: string,
    date?: Date,
    type?: any
): OpenPGPMessage;
export function createCleartextMessage(
    text: string | ReadableStream<String> | CleartextMessage,
    filename?: string,
    date?: Date,
    type?: any
): CleartextMessage;

export function signMessage(
    options: SignOptionsPmcrypto & { armor?: true; detached?: false }
): Promise<string>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor: false; detached?: false }
): Promise<Uint8Array>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor?: true; detached: true }
): Promise<string>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor: false; detached: true }
): Promise<Uint8Array>;

export function getSignature(option: string | Uint8Array | OpenPGPSignature): Promise<OpenPGPSignature>;

export function getMessage(message: OpenPGPMessage | Uint8Array | string): Promise<OpenPGPMessage>;

export function splitMessage(
    message: OpenPGPMessage | Uint8Array | string
): Promise<{
    asymmetric: Uint8Array[];
    signature: Uint8Array[];
    symmetric: Uint8Array[];
    compressed: Uint8Array[];
    literal: Uint8Array[];
    encrypted: Uint8Array[];
    other: Uint8Array[];
}>;

export function armorBytes(value: Uint8Array | string): Promise<Uint8Array | string>;

export interface algorithmInfo {
    algorithm: string;
    bits?: number;
    curve?: string;
}

export function SHA256(arg: Uint8Array): Promise<Uint8Array>;
export function SHA512(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeMD5(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeSHA1(arg: Uint8Array): Promise<Uint8Array>;

export interface VerifyMessageResult {
    data: openpgp_VerifyMessageResult['data'];
    verified: VERIFICATION_STATUS;
    signatures: OpenPGPSignature[];
    signatureTimestamp: Date|null,
    errors?: Error[];
}
export interface VerifyMessageOptions extends VerifyOptions {
    detached?: boolean;
}
export function verifyMessage(options: VerifyMessageOptions): Promise<VerifyMessageResult>;

export function serverTime(): Date;

export function getPreferredAlgorithm(key: OpenPGPKey[], date?: Date): Promise<string>

export function getSHA256Fingerprints(key: OpenPGPKey): Promise<string[]>

export function canKeyEncrypt(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function checkKeyStrength(key: OpenPGPKey): void;
