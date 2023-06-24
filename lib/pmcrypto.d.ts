/* eslint-disable @typescript-eslint/indent */
import {
    MaybeArray,
    DecryptOptions,
    DecryptMessageResult as openpgp_DecryptMessageResult,
    Message,
    Key,
    Signature,
    SignOptions,
    EncryptOptions,
    reformatKey,
    generateKey,
    generateSessionKey as openpgp_generateSessionKey,
    PrivateKey,
    PublicKey,
    SessionKey,
    EncryptSessionKeyOptions,
    decryptSessionKeys as openpgp_decryptSessionKeys,
    decryptKey,
    encryptKey,
    WebStream,
    KeyOptions as GenerateKeyOptions,
    UserID,
    readMessage, readSignature, readCleartextMessage,
    readKey, readKeys, readPrivateKey, readPrivateKeys,
    PartialConfig,
    KeyID
} from 'openpgp/lightweight';

import { VERIFICATION_STATUS, SIGNATURE_TYPES } from './constants';
import type { ContextSigningOptions, ContextVerificationOptions } from './message/context';

export function init(): void;

export { VERIFICATION_STATUS, SIGNATURE_TYPES, PartialConfig };
export { ContextError } from './message/context';

export type OpenPGPKey = Key;
export type OpenPGPMessage = Message<Uint8Array | string>; // TODO missing streaming support
export type OpenPGPSignature = Signature;

export {
    generateKey, reformatKey, decryptKey, encryptKey,
    readMessage, readSignature, readCleartextMessage,
    readKey, readKeys, readPrivateKey, readPrivateKeys
};
export type { PrivateKey, PublicKey, GenerateKeyOptions, Key, SessionKey };

export function generateForwardingMaterial(
    originalKey: PrivateKey,
    forwardingUserIDs: UserID[],
    subkeyID?: KeyID[]
): Promise<{ proxyParameter: Uint8Array, finalRecipientKey: PrivateKey }>;

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
    armoredMessage: string; // no streaming support for legacy messages
    messageDate: Date;
}

export interface DecryptMimeOptions extends DecryptLegacyOptions {
    headerFilename?: string;
    sender?: string;
}

export function getFingerprint(key: OpenPGPKey): string;

export function isExpiredKey(key: OpenPGPKey, date?: Date): Promise<boolean>;
export function isRevokedKey(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function generateSessionKeyForAlgorithm(algoName: 'aes128' | 'aes192' | 'aes256'): Promise<Uint8Array>;
type GenerateSessionKeyOptions = Parameters<typeof openpgp_generateSessionKey>[0];
export interface GenerateSessionKeyOptionsPmcrypto extends Omit<GenerateSessionKeyOptions, 'encryptionKeys'> {
    recipientKeys: MaybeArray<PublicKey>
}
export function generateSessionKey(options: GenerateSessionKeyOptionsPmcrypto): Promise<SessionKey>;

export interface EncryptSessionKeyOptionsPmcrypto extends EncryptSessionKeyOptions {}
export function encryptSessionKey<FormatType extends EncryptSessionKeyOptionsPmcrypto['format'] = 'armored'>(
    options: EncryptSessionKeyOptionsPmcrypto & { format?: FormatType }
): Promise<
    FormatType extends 'armored' ? string :
    FormatType extends 'binary' ? Uint8Array :
    FormatType extends 'object' ? OpenPGPMessage :
    never
>;

export type DecryptSessionKeyOptionsPmcrypto = Parameters<typeof openpgp_decryptSessionKeys>[0];
// This differs from `openpgp.decryptSessionKeys` in the return type
export function decryptSessionKey(options: DecryptSessionKeyOptionsPmcrypto): Promise<SessionKey | undefined>;

export interface DecryptOptionsPmcrypto<T extends MaybeStream<Data>> extends DecryptOptions {
    message: Message<T>;
    encryptedSignature?: Message<MaybeStream<Data>>;
    context?: ContextVerificationOptions
}

export interface DecryptResultPmcrypto<DataType extends openpgp_DecryptMessageResult['data'] = MaybeStream<Data>> {
    data: DataType;
    signatures: DataType extends WebStream<Data> ? Promise<OpenPGPSignature[]> : OpenPGPSignature[];
    filename: string;
    verified: DataType extends WebStream<Data> ? Promise<VERIFICATION_STATUS> : VERIFICATION_STATUS;
    verificationErrors?: DataType extends WebStream<Data> ? Promise<Error[]> : Error[];
}

export function decryptMessage<DataType extends MaybeStream<Data>, FormatType extends DecryptOptions['format'] = 'utf8'>(
    options: DecryptOptionsPmcrypto<DataType> & { format?: FormatType }
): Promise<
    FormatType extends 'utf8' ?
        DataType extends WebStream<Data> ?
            DecryptResultPmcrypto<WebStream<string>> :
            DecryptResultPmcrypto<string> :
    FormatType extends 'binary' ?
        DataType extends WebStream<Data> ?
            DecryptResultPmcrypto<WebStream<Uint8Array>> :
            DecryptResultPmcrypto<Uint8Array> :
    never
>;

export function decryptMessageLegacy<F extends DecryptLegacyOptions['format'] = 'utf8'>(
    options: DecryptLegacyOptions & { format?: F }
): Promise<
    // output type cannot be statically determined:
    // string for legacy messages, but either string or Uint8Array output for non-legacy ones (depending on options.format)
    F extends 'utf8' ? DecryptResultPmcrypto<string> :
    F extends 'binary' ? DecryptResultPmcrypto<Uint8Array | string> :
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

export interface EncryptOptionsPmcrypto<T extends MaybeStream<Data>> extends Omit<EncryptOptions, 'message' | 'signatureNotations'> {
    textData?: T extends MaybeStream<string> ? T : never;
    binaryData?: T extends MaybeStream<Uint8Array> ? T : never;
    stripTrailingSpaces?: T extends MaybeStream<string> ? boolean : never;
    detached?: boolean;
    context?: ContextSigningOptions;
}

// No reuse from OpenPGP's equivalent
export interface EncryptResult<
    MessageType,
    SignatureType = undefined,
    EncryptedSingatureType = undefined
> {
    message: MessageType;
    signature: SignatureType;
    encryptedSignature: EncryptedSingatureType;
}

export function encryptMessage<
    DataType extends MaybeStream<Data>,
    FormatType extends EncryptOptions['format'] = 'armored', // extends 'string' also works, but it gives unclear error if passed unexpected 'format' values
    DetachedType extends boolean = false
>(
    options: EncryptOptionsPmcrypto<DataType> & {
        format?: FormatType; detached?: DetachedType;
    }
): Promise<
    FormatType extends 'armored' ?
        DetachedType extends true ?
            DataType extends WebStream<Data> ?
                EncryptResult<WebStream<string>, WebStream<string>, WebStream<string>> :
                EncryptResult<string, string, string> :
            DataType extends WebStream<Data> ?
                EncryptResult<WebStream<string>> : EncryptResult<string> :
    FormatType extends 'binary' ?
        DetachedType extends true ?
            DataType extends WebStream<Data> ?
                EncryptResult<WebStream<Uint8Array>, WebStream<Uint8Array>, WebStream<Uint8Array>> :
                EncryptResult<Uint8Array, Uint8Array, Uint8Array> :
            DataType extends WebStream<Data> ?
                EncryptResult<WebStream<Uint8Array>> :
                EncryptResult<Uint8Array> :
    FormatType extends 'object' ?
        DetachedType extends true ?
            never : // unsupported
            EncryptResult<OpenPGPMessage> :
    never
>;

export function getMatchingKey(
    signature: OpenPGPSignature | OpenPGPMessage,
    publicKeys: OpenPGPKey[]
): OpenPGPKey | undefined;

export interface SignOptionsPmcrypto<T extends MaybeStream<Data>> extends Omit<SignOptions, 'message' | 'signatureNotations'> {
    textData?: T extends MaybeStream<string> ? T : never;
    binaryData?: T extends MaybeStream<Uint8Array> ? T : never;
    stripTrailingSpaces?: T extends MaybeStream<string> ? boolean : never;
    context?: ContextSigningOptions;
}

export function signMessage<
    DataType extends MaybeStream<Data>,
    FormatType extends SignOptions['format'] = 'armored',
    DetachedType extends boolean = false
>(
    options: SignOptionsPmcrypto<DataType> & { format?: FormatType; detached?: DetachedType }
): Promise<
    FormatType extends 'armored' ?
        DataType extends WebStream<Data> ? WebStream<string> : string :
    FormatType extends 'binary' ?
        DataType extends WebStream<Data> ? WebStream<Uint8Array> : Uint8Array :
    FormatType extends 'object' ?
        DetachedType extends true ? OpenPGPMessage : OpenPGPSignature :
    never
>;
export {
    splitMessage,
    armorBytes,
    stripArmor
} from './message/utils';

export interface AlgorithmInfo {
    algorithm: string;
    bits?: number; // if algorithm == 'rsaEncryptSign' | 'rsaEncrypt' | 'rsaSign'
    curve?: string; // if algorithm == 'ecdh' | 'eddsa' | 'ecdsa'
}

export { SHA256, SHA512, unsafeMD5, unsafeSHA1 } from './crypto/hash';

export { verifyMessage, verifyCleartextMessage } from './message/verify';
export type { VerifyCleartextOptionsPmcrypto, VerifyMessageResult, VerifyOptionsPmcrypto } from './message/verify';
export type { ContextSigningOptions, ContextVerificationOptions };

export { MIMEAttachment, ProcessMIMEOptions, default as processMIME, ProcessMIMEResult } from './message/processMIME';

export { serverTime, updateServerTime } from './serverTime';

export function getSHA256Fingerprints(key: OpenPGPKey): Promise<string[]>;

export function canKeyEncrypt(key: OpenPGPKey, date?: Date): Promise<boolean>;

export function checkKeyStrength(key: OpenPGPKey): void;
