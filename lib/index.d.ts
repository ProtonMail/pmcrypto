import {
    DecryptOptions,
    DecryptMessageResult,
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
    SessionKey,
    encryptSessionKey
} from 'openpgp/lightweight';

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

export function getKeys(serializedKeys: string | Uint8Array): Promise<OpenPGPKey[]>;
export function getKey(serializedKey: string | Uint8Array): Promise<OpenPGPKey>;

export function getFingerprint(key: OpenPGPKey): string;

export function isExpiredKey(key: OpenPGPKey, date?: Date): Promise<boolean>;
export function isRevokedKey(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function generateSessionKey(algo: string): Promise<Uint8Array>;
export function generateSessionKeyFromKeyPreferences(publicKeys: OpenPGPKey | OpenPGPKey[]): Promise<SessionKey>;

export { encryptSessionKey };

// This differs from `openpgp.decryptSessionKeys` in the return type
export function decryptSessionKey(options: {
    message: OpenPGPMessage;
    privateKeys?: OpenPGPKey | OpenPGPKey[];
    passwords?: string | string[];
}): Promise<SessionKey | undefined>;

export interface DecryptOptionsPmcrypto extends DecryptOptions {
    encryptedSignature?: OpenPGPMessage;
}

export type DecryptResultPmcrypto = Omit<DecryptMessageResult, 'signatures'> & {
    signatures: (OpenPGPSignature)[]; // Promise if streamed input
    verified: VERIFICATION_STATUS; // Promise if streamed input
    errors?: Error[]; // Promise if streamed input
}

export function decryptMessage(
    options: DecryptOptionsPmcrypto & { format: 'utf8' }
): Promise<DecryptResultPmcrypto & { data: string | ReadableStream<string> }>;
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

type MaybeStream<T extends Uint8Array | string> = T | ReadableStream<T>;
export interface EncryptOptionsPmcryptoWithTextData extends Omit<EncryptOptions, 'message'> {
    textData: MaybeStream<string>;
    binaryData?: undefined;
    stripTrailingSpaces?: boolean;
}
export interface EncryptOptionsPmcryptoWithBinaryData extends Omit<EncryptOptions, 'message'> {
    textData?: undefined;
    binaryData: MaybeStream<Uint8Array>;
    stripTrailingSpaces?: undefined;
}
type EncryptOptionsPmcrypto = (EncryptOptionsPmcryptoWithBinaryData | EncryptOptionsPmcryptoWithTextData) & {
    returnSessionKey?: boolean;
    detached?: boolean;
};

export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor?: true; format?: 'armored'; detached?: false }
): Promise<EncryptResult<string>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor?: true; format?: 'armored'; detached: true }
): Promise<EncryptResult<string, undefined, string, string>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor: false; format?: 'object'; detached?: false }
): Promise<EncryptResult<undefined, OpenPGPMessage>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor: false; format?: 'object'; detached: true }
): Promise<EncryptResult<undefined, OpenPGPMessage, OpenPGPSignature, OpenPGPMessage>>;
export function encryptMessage( // TODO what is this for? redundant -- declare maybe streams above
    options: EncryptOptionsPmcrypto
): Promise<
    EncryptResult<
        string | ReadableStream<string>,
        OpenPGPMessage,
        string | ReadableStream<string> | OpenPGPSignature,
        string | ReadableStream<string> | OpenPGPMessage
    >
>;
export function getMatchingKey(
    signature: OpenPGPSignature | OpenPGPMessage,
    publicKeys: OpenPGPKey[]
): OpenPGPKey | undefined;

interface SignOptionsPmcryptoWithTextData extends Omit<SignOptions, 'message'> {
    textData: MaybeStream<string>;
    binaryData?: undefined;
    stripTrailingSpaces?: boolean;
}
interface SignOptionsPmcryptoWithBinaryData extends Omit<SignOptions, 'message'> {
    textData?: undefined;
    binaryData: MaybeStream<Uint8Array>;
    stripTrailingSpaces?: undefined;
}
type SignOptionsPmcrypto = SignOptionsPmcryptoWithTextData | SignOptionsPmcryptoWithBinaryData

export function signMessage(
    options: SignOptionsPmcrypto & { armor?: true; detached?: false }
): Promise<string>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor: false; detached?: false }
): Promise<OpenPGPMessage>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor?: true; detached: true }
): Promise<string>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor: false; detached: true }
): Promise<OpenPGPSignature>;

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
    bits?: number; // if algorithm == 'rsaEncryptSign' | 'rsaEncrypt' | 'rsaSign'
    curve?: string; // if algorithm == 'ecdh' | 'eddsa' | 'ecdsa'
}

export function SHA256(arg: Uint8Array): Promise<Uint8Array>;
export function SHA512(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeMD5(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeSHA1(arg: Uint8Array): Promise<Uint8Array>;

export interface VerifyOptionsPmcryptoWithTextData extends Omit<VerifyOptions, 'message'> {
    textData: string; // streaming not supported when verifying detached signatures
    binaryData?: undefined;
    stripTrailingSpaces?: boolean;
}
export interface VerifyOptionsPmcryptoWithBinaryData extends Omit<VerifyOptions, 'message'> {
    textData?: undefined;
    binaryData: Uint8Array; // streaming not supported when verifying detached signatures
    stripTrailingSpaces?: undefined;
}
type VerifyOptionsPmcrypto = VerifyOptionsPmcryptoWithTextData | VerifyOptionsPmcryptoWithBinaryData;
export interface VerifyMessageResult {
    data: openpgp_VerifyMessageResult['data'];
    verified: VERIFICATION_STATUS;
    signatures: OpenPGPSignature[];
    signatureTimestamp: Date|null,
    errors?: Error[];
}
export function verifyMessage(options: VerifyOptionsPmcrypto): Promise<VerifyMessageResult>;

export function serverTime(): Date;

export function getSHA256Fingerprints(key: OpenPGPKey): Promise<string[]>

export function canKeyEncrypt(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function checkKeyStrength(key: OpenPGPKey): void;
