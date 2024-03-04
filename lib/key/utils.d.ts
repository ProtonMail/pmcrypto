import {
    generateKey,
    reformatKey,
    generateSessionKey as openpgp_generateSessionKey,
    PrivateKey,
    PublicKey,
    Key,
    SessionKey,
    KeyOptions as GenerateKeyOptions,
    UserID,
    PartialConfig,
    Signature,
    Message
} from '../openpgp';
import { MaybeArray } from '../utils';

export { generateKey, reformatKey, GenerateKeyOptions };

export interface ReformatKeyOptions {
    privateKey: PrivateKey;
    userIDs?: MaybeArray<UserID>;
    passphrase?: string;
    keyExpirationTime?: number;
    date?: Date,
    format?: GenerateKeyOptions['format'],
    config?: PartialConfig
}

export function generateSessionKeyForAlgorithm(algoName: 'aes128' | 'aes192' | 'aes256'): Promise<Uint8Array>;
type GenerateSessionKeyOptions = Parameters<typeof openpgp_generateSessionKey>[0];
export interface GenerateSessionKeyOptionsPmcrypto extends Omit<GenerateSessionKeyOptions, 'encryptionKeys'> {
    recipientKeys: MaybeArray<PublicKey>
}
export function generateSessionKey(options: GenerateSessionKeyOptionsPmcrypto): Promise<SessionKey>;

export function getFingerprint(key: Key): string;

export function isExpiredKey(key: Key, date?: Date): Promise<boolean>;
export function isRevokedKey(key: Key, date?: Date): Promise<boolean>;

export function getSHA256Fingerprints(key: Key): Promise<string[]>;

export function canKeyEncrypt(key: Key, date?: Date): Promise<boolean>;

export function getMatchingKey(
    signature: Signature | Message<Uint8Array | string>,
    publicKeys: PublicKey[]
): Key | undefined;
