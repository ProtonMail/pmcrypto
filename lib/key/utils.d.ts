import {
    generateKey,
    reformatKey,
    type generateSessionKey as openpgp_generateSessionKey,
    type PrivateKey,
    type PublicKey,
    type Key,
    type SessionKey,
    type KeyOptions as GenerateKeyOptions,
    type UserID,
    type PartialConfig,
    type Signature,
    type Message
} from '../openpgp';
import type { MaybeArray } from '../utils';

export { generateKey, reformatKey, type GenerateKeyOptions };

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

export function isExpiredKey(key: Key, date?: Date): Promise<boolean>;
export function isRevokedKey(key: Key, date?: Date): Promise<boolean>;

export function getSHA256Fingerprints(key: Key): Promise<string[]>;

export function canKeyEncrypt(key: Key, date?: Date): Promise<boolean>;

export function getMatchingKey(
    signature: Signature | Message<Uint8Array | string>,
    publicKeys: PublicKey[]
): Key | undefined;
