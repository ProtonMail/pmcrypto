import {
    DecryptOptions,
    DecryptResult,
    message,
    key,
    type,
    signature,
    SignOptions,
    SignResult,
    EncryptOptions,
    UserID,
    cleartext,
    VerifyOptions,
    VerifyResult
} from 'openpgp';

export enum VERIFICATION_STATUS {
    NOT_SIGNED = 0,
    SIGNED_AND_VALID = 1,
    SIGNED_AND_INVALID = 2
}

export enum SIGNATURE_TYPES {
    BINARY = 0,
    CANONICAL_TEXT = 1
}

// type defined in OpenPGP is not complete
export interface OpenPGPKey extends key.Key {
    users?: { userId?: { userid?: string } }[];
}

export type OpenPGPMessage = message.Message;
export type OpenPGPSignature = signature.Signature;

export interface SessionKey {
    data: Uint8Array;
    algorithm: string;
}

export { generateKey } from 'openpgp';

export interface ReformatKeyOptions {
    privateKey: OpenPGPKey;
    userIds: UserID[];
    passphrase: string;
    keyExpirationTime?: number;
    date?: Date;
}
export function reformatKey(
    option: ReformatKeyOptions
): Promise<{ key: key.Key; privateKeyArmored: string; publicKeyArmored: string; revocationCertificate: string }>;

export interface DecryptLegacyOptions extends DecryptOptions {
    messageDate?: Date;
}

export interface DecryptMimeOptions extends DecryptLegacyOptions {
    headerFilename?: string;
    sender?: string;
}

// No reuse from OpenPGP's equivalent
export interface EncryptResult<D = undefined, M = undefined, S = undefined> {
    data: D;
    message: M;
    signature: S;
    sessionKey: SessionKey;
}

export interface BinaryResult {
    data: Uint8Array;
    filename?: string;
    signatures?: {
        keyid: type.keyid.Keyid;
        verified: Promise<boolean>;
        valid: boolean;
    }[];
}

export function encryptPrivateKey(key: OpenPGPKey, password: string): Promise<string>;
export function decryptPrivateKey(armoredKey: string, password: string): Promise<OpenPGPKey>;

export function encodeUtf8(str: string): string;
export function encodeUtf8(str: undefined): undefined;

export function encodeBase64(str: string): string;
export function encodeBase64(str: undefined): undefined;

export function decodeBase64(str: string): string;
export function decodeBase64(str: undefined): undefined;

export function encodeUtf8Base64(str: string): string;
export function encodeUtf8Base64(str: undefined): string;

export function decodeUtf8Base64(str: string): string;
export function decodeUtf8Base64(str: undefined): undefined;

export function binaryStringToArray(str: string): Uint8Array;

export function arrayToBinaryString(bytes: Uint8Array): string;

export function arrayToHexString(bytes: Uint8Array): string;

export function concatArrays(data: Uint8Array[]): Uint8Array;

export function getKeys(key: Uint8Array | string): Promise<OpenPGPKey[]>;

export function getFingerprint(key: OpenPGPKey): string;

export function isExpiredKey(key: OpenPGPKey): Promise<boolean>;

export function generateSessionKey(algo: string): Uint8Array;

export function encryptSessionKey(options: {
    data: Uint8Array;
    algorithm: string;
    aeadAlgo?: string;
    publicKeys?: any[];
    passwords?: any[];
    wildcard?: boolean;
    date?: Date;
    userIds?: any[];
}): Promise<{ message: message.Message }>;

export function decryptSessionKey(options: {
    message: message.Message;
    privateKeys?: key.Key | key.Key[];
    passwords?: string | string[];
}): Promise<SessionKey | undefined>;

export type DecryptResultPmcrypto = Omit<DecryptResult, 'signatures'> & {
    signatures: (OpenPGPSignature)[];
    verified: VERIFICATION_STATUS;
}

export function decryptMessage(
    options: DecryptOptions & { format: 'utf8' }
): Promise<DecryptResultPmcrypto & { data: string | ReadableStream<String> }>;
export function decryptMessage(
    options: DecryptOptions & { format: 'binary' }
): Promise<DecryptResultPmcrypto & { data: Uint8Array | ReadableStream<Uint8Array> }>;
export function decryptMessage(options: DecryptOptions): Promise<DecryptResultPmcrypto>;

export function decryptMessageLegacy(options: DecryptLegacyOptions): Promise<DecryptResultPmcrypto>;

export function decryptMIMEMessage(
    options: DecryptMimeOptions
): {
    getBody: () => Promise<{ body: string; mimetype: string } | undefined>;
    getAttachments: () => Promise<any>;
    getEncryptedSubject: () => Promise<string>;
    verify: () => Promise<number>;
    errors: () => Promise<Error[] | undefined>;
    signatures: OpenPGPSignature[];
};

export interface EncryptOptionsPmcrypto extends Omit<EncryptOptions, 'message'> {
    data?: Uint8Array | string;
    message?: message.Message;
}

export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor?: true; detached?: false }
): Promise<EncryptResult<string>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor?: true; detached: true }
): Promise<EncryptResult<string, undefined, string>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor: false; detached?: false }
): Promise<EncryptResult<undefined, message.Message, undefined>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto & { armor: false; detached: true }
): Promise<EncryptResult<undefined, message.Message, OpenPGPSignature>>;
export function encryptMessage(
    options: EncryptOptionsPmcrypto
): Promise<
    EncryptResult<
        string | ReadableStream<String>,
        message.Message,
        string | ReadableStream<String> | OpenPGPSignature
    >
>;
export function getMatchingKeys(
    signature: OpenPGPSignature,
    publicKeys: OpenPGPKey[]
): OpenPGPKey | undefined;

interface SignOptionsPmcrypto extends Omit<SignOptions, 'message'> {
    data: string;
}

export function createMessage(
    text: string | ReadableStream<String> | message.Message,
    filename?: string,
    date?: Date,
    type?: any
): message.Message;
export function createCleartextMessage(
    text: string | ReadableStream<String> | cleartext.CleartextMessage,
    filename?: string,
    date?: Date,
    type?: any
): cleartext.CleartextMessage;

export function signMessage(
    options: SignOptionsPmcrypto & { armor?: true; detached?: false }
): Promise<{ data: string }>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor: false; detached?: false }
): Promise<{ message: message.Message }>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor?: true; detached: true }
): Promise<{ signature: string }>;
export function signMessage(
    options: SignOptionsPmcrypto & { armor: false; detached: true }
): Promise<{ signature: OpenPGPSignature }>;
export function signMessage(options: SignOptionsPmcrypto): Promise<SignResult>;

export function getSignature(option: string | Uint8Array | OpenPGPSignature): Promise<OpenPGPSignature>;

export function getMessage(message: message.Message | Uint8Array | string): Promise<message.Message>;

export function splitMessage(
    message: message.Message | Uint8Array | string
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
    rsaBits?: number;
    bits?: number;
    curve?: string;
}

export function SHA256(arg: Uint8Array): Promise<Uint8Array>;
export function SHA512(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeMD5(arg: Uint8Array): Promise<Uint8Array>;
export function unsafeSHA1(arg: Uint8Array): Promise<Uint8Array>;

export interface VerifyMessageResult extends VerifyResult {
    verified: VERIFICATION_STATUS;
}
export interface VerifyMessageOptions extends VerifyOptions {
    detached?: boolean;
}
export function verifyMessage(options: VerifyMessageOptions): Promise<VerifyMessageResult>;

export function serverTime(): Date;
