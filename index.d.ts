declare module 'pmcrypto' {
    import {
        DecryptOptions,
        DecryptResult,
        message,
        key,
        type,
        signature,
        packet,
        enums,
        SignOptions,
        SignResult,
        EncryptOptions
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

    export type OpenPGPKey = key.Key;

    export interface SessionKey {
        data: Uint8Array;
        algorithm: string;
    }

    export interface DecryptLecacyOptions extends DecryptOptions {
        messageDate?: Date;
    }

    export interface DecryptMimeOptions extends DecryptLecacyOptions {
        headerFilename?: string;
        sender?: string;
    }

    // No reuse from OpenPGP's equivalent
    export interface EncryptResult {
        data: string;
        message: message.Message;
        signature: signature.Signature;
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

    export function encryptPrivateKey(key: OpenPGPKey, password: string): string;
    export function decryptPrivateKey(armoredKey: string, password: string): OpenPGPKey;

    export function encodeUtf8(str: string | undefined): string | undefined;
    export function encodeBase64(str: string | undefined): string | undefined;
    export function decodeBase64(str: string | undefined): string | undefined;
    export function encodeUtf8Base64(str: string | undefined): string | undefined;
    export function decodeUtf8Base64(str: string | undefined): string | undefined;

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
    }): Promise<{ data: Uint8Array; algorithm: string } | undefined>;

    interface DecryptResultPmcrypto extends DecryptResult {
        verified: VERIFICATION_STATUS;
    }
    export function decryptMessage(options: DecryptOptions): DecryptResultPmcrypto;
    export function decryptMessageLegacy(options: DecryptLecacyOptions): DecryptResult;
    export function decryptMIMEMessage(
        options: DecryptMimeOptions
    ): {
        getBody: () => Promise<{ body: string; mimetype: string } | undefined>;
        getAttachments: () => Promise<any>;
        getEncryptedSubject: () => Promise<string>;
        verify: () => Promise<number>;
    };

    export interface EncryptOptionsPmcrypto extends Omit<EncryptOptions, 'message'> {
        data: Uint8Array | string;
    }
    export function encryptMessage(options: EncryptOptionsPmcrypto): Promise<EncryptResult>;

    interface SignOptionsPmcrypto extends Omit<SignOptions, 'message'> {
        data: string;
    }
    export function signMessage(options: SignOptionsPmcrypto): Promise<SignResult>;

    export function getMessage(
        message: message.Message | Uint8Array | string
    ): message.Message | Promise<message.Message>;

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
}
