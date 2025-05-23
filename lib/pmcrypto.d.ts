/* eslint-disable @typescript-eslint/indent */
import {
    type DecryptOptions,
    type DecryptMessageResult as openpgp_DecryptMessageResult,
    type Message,
    Key,
    type Signature,
    type SignOptions,
    type EncryptOptions,
    PublicKey,
    PrivateKey,
    type SessionKey,
    type EncryptSessionKeyOptions,
    type decryptSessionKeys as openpgp_decryptSessionKeys,
    decryptKey,
    encryptKey,
    type WebStream,
    readMessage, readSignature, readCleartextMessage,
    readKey, readKeys, readPrivateKey, readPrivateKeys,
    type PartialConfig,
    type AlgorithmInfo
} from 'openpgp/lightweight';

import { VERIFICATION_STATUS, SIGNATURE_TYPES } from './constants';
import type { ContextSigningOptions, ContextVerificationOptions } from './message/context';

export function init(): void;

export { VERIFICATION_STATUS, SIGNATURE_TYPES, type PartialConfig };
export { SignatureContextError } from './message/context';

export type OpenPGPKey = Key;
export type OpenPGPMessage = Message<Uint8Array | string>; // TODO missing streaming support
export type OpenPGPSignature = Signature;

export {
    generateKey, reformatKey,
    generateSessionKey, generateSessionKeyForAlgorithm,
    isExpiredKey, isRevokedKey, canKeyEncrypt,
    getSHA256Fingerprints,
    getMatchingKey
} from './key/utils';

export type { GenerateKeyOptions, ReformatKeyOptions, GenerateSessionKeyOptionsPmcrypto } from './key/utils';

export {
    decryptKey, encryptKey,
    readMessage, readSignature, readCleartextMessage,
    readKey, readKeys, readPrivateKey, readPrivateKeys,
    PrivateKey, PublicKey, Key, type SessionKey,
    type AlgorithmInfo
};

export { generateForwardingMaterial, doesKeySupportForwarding, isForwardingKey } from './key/forwarding';

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

export interface DecryptOptionsPmcrypto<T extends MaybeWebStream<Data>> extends DecryptOptions {
    message: Message<T>;
    encryptedSignature?: Message<MaybeWebStream<Data>>;
    signatureContext?: ContextVerificationOptions
}

export interface DecryptResultPmcrypto<DataType extends openpgp_DecryptMessageResult['data'] = MaybeWebStream<Data>> {
    data: DataType;
    signatures: DataType extends WebStream<Data> ? Promise<OpenPGPSignature[]> : OpenPGPSignature[];
    filename: string;
    verificationStatus: DataType extends WebStream<Data> ? Promise<VERIFICATION_STATUS> : VERIFICATION_STATUS;
    verificationErrors?: DataType extends WebStream<Data> ? Promise<Error[]> : Error[];
}

export function decryptMessage<DataType extends MaybeWebStream<Data>, FormatType extends DecryptOptions['format'] = 'utf8'>(
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

export type Data = string | Uint8Array;
export type MaybeWebStream<T extends Data> = T | WebStream<T>;
export type { WebStream };

export interface EncryptOptionsPmcrypto<T extends MaybeWebStream<Data>> extends Omit<EncryptOptions, 'message' | 'signatureNotations'> {
    textData?: T extends MaybeWebStream<string> ? T : never;
    binaryData?: T extends MaybeWebStream<Uint8Array> ? T : never;
    stripTrailingSpaces?: T extends MaybeWebStream<string> ? boolean : never;
    detached?: boolean;
    signatureContext?: ContextSigningOptions;
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
    DataType extends MaybeWebStream<Data>,
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

export interface SignOptionsPmcrypto<T extends MaybeWebStream<Data>> extends Omit<SignOptions, 'message' | 'signatureNotations'> {
    textData?: T extends MaybeWebStream<string> ? T : never;
    binaryData?: T extends MaybeWebStream<Uint8Array> ? T : never;
    stripTrailingSpaces?: T extends MaybeWebStream<string> ? boolean : never;
    signatureContext?: ContextSigningOptions;
}

export function signMessage<
    DataType extends MaybeWebStream<Data>,
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

export { SHA256, SHA512, unsafeMD5, unsafeSHA1 } from './crypto/hash';
export { argon2, type Argon2Options } from './crypto/argon2';

export { verifyMessage, verifyCleartextMessage } from './message/verify';
export type { VerifyCleartextOptionsPmcrypto, VerifyMessageResult, VerifyOptionsPmcrypto } from './message/verify';
export type { ContextSigningOptions, ContextVerificationOptions };

export { type MIMEAttachment, type ProcessMIMEOptions, default as processMIME, type ProcessMIMEResult } from './message/processMIME';

export { serverTime, updateServerTime } from './serverTime';
export { checkKeyStrength, checkKeyCompatibility } from './key/check';
