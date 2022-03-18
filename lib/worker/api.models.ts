import type {
  DecryptOptionsPmcrypto,
  DecryptResultPmcrypto,
  SignOptionsPmcrypto,
  EncryptOptionsPmcrypto,
  Data,
  VerifyOptionsPmcrypto,
  VerifyMessageResult,
  AlgorithmInfo,
  KeyOptions,
  EncryptSessionKeyOptionsPmcrypto,
  DecryptSessionKeyOptionsPmcrypto,
  DecryptLegacyOptions,
  ProcessMIMEOptions,
  ProcessMIMEResult,
  SessionKey
} from '../pmcrypto';

type MaybeArray<T> = T[] | T;
export type { SessionKey };

// TODO TS: do not allow mutually exclusive properties
export interface WorkerDecryptionOptions
    extends Omit<DecryptOptionsPmcrypto<Data>, 'message' | 'signature' | 'encryptedSignature' | 'verificationKeys' | 'decryptionKeys'> {
    armoredSignature?: string;
    binarySignature?: Uint8Array;
    armoredMessage?: string;
    binaryMessage?: Uint8Array;
    armoredEncryptedSignature?: string;
    binaryEncryptedSignature?: Uint8Array;
    verificationKeys?: MaybeArray<PublicKeyReference>;
    decryptionKeys?: MaybeArray<PrivateKeyReference>;
}
export interface WorkerDecryptionResult<T extends Data> extends Omit<DecryptResultPmcrypto<T>, 'signatures'> {
    signatures: Uint8Array[]
}

export interface WorkerDecryptLegacyOptions
    extends Omit<DecryptLegacyOptions, 'message' | 'signature' | 'encryptedSignature' | 'verificationKeys' | 'decryptionKeys'> {
    armoredMessage: string;
    armoredSignature?: string;
    binarySignature?: Uint8Array;
    verificationKeys?: MaybeArray<PublicKeyReference>;
    decryptionKeys?: MaybeArray<PrivateKeyReference>;
}

// TODO to make Option interfaces easy to use for the user, might be best to set default param types (e.g. T extends Data = Data).
export interface WorkerVerifyOptions<T extends Data> extends Omit<VerifyOptionsPmcrypto<T>, 'signature' | 'verificationKeys'> {
    armoredSignature?: string;
    binarySignature?: Uint8Array;
    verificationKeys: MaybeArray<PublicKeyReference>;
}
export interface WorkerVerificationResult<D extends Data = Data> extends Omit<VerifyMessageResult<D>, 'signatures'> {
    signatures: Uint8Array[]
}

export interface WorkerSignOptions<T extends Data> extends Omit<SignOptionsPmcrypto<T>, 'signingKeys'> {
    format?: 'armored' | 'binary',
    signingKeys?: MaybeArray<PrivateKeyReference>
};
export interface WorkerEncryptOptions<T extends Data> extends Omit<EncryptOptionsPmcrypto<T>, 'signature' | 'signingKeys' | 'encryptionKeys'> {
    format?: 'armored' | 'binary'
    armoredSignature?: string,
    binarySignature?: Uint8Array,
    encryptionKeys?: MaybeArray<PublicKeyReference>,
    signingKeys?: MaybeArray<PrivateKeyReference>
};

export interface WorkerProcessMIMEOptions extends Omit<ProcessMIMEOptions, 'verificationKeys'> {
    verificationKeys?: MaybeArray<PublicKeyReference>
}

export interface WorkerProcessMIMEResult extends Omit<ProcessMIMEResult, 'signatures'> {
    signatures: Uint8Array[]
}

export type WorkerExportedKey<F extends 'armored' | 'binary' | undefined = 'armored'> = F extends 'armored' ? string : Uint8Array;

export interface WorkerImportDecryptedPrivateKeyOptions<T extends Data> {
    armoredKey?: T extends string ? T : never,
    binaryKey?: T extends Uint8Array ? T : never,
}

export interface WorkerImportEncryptedPrivateKeyOptions<T extends Data> {
    armoredKey?: T extends string ? T : never,
    binaryKey?: T extends Uint8Array ? T : never,
    passphrase: string
}

export interface WorkerImportPrivateKeyOptions<T extends Data> {
    armoredKey?: T extends string ? T : never,
    binaryKey?: T extends Uint8Array ? T : never,
    /**
     * null if the key is expected to be already decrypted, e.g. when user uploads a new private key that is unencrypted
     */
    passphrase: string | null
}

export interface WorkerExportPublicKeyOptions {
    keyReference: KeyReference,
    format?: 'armored' | 'binary'
}

export interface WorkerExportEncryptedPrivateKeyOptions {
    keyReference: PrivateKeyReference,
    format?: 'armored' | 'binary',
    passphrase: string
}

export interface WorkerExportDecryptedPrivateKeyOptions {
    keyReference: PrivateKeyReference,
    format?: 'armored' | 'binary',
}

export interface WorkerGenerateKeyOptions extends Omit<KeyOptions, 'format' | 'passphrase'> {
    // passphrase: string; the key can be encrypted on export, no need/reason to do so on generation (based on current key store API)
}

export interface WorkerEncryptSessionKeyOptions extends Omit<EncryptSessionKeyOptionsPmcrypto, 'encryptionKeys'> {
    format?: 'armored' | 'binary',
    encryptionKeys?: MaybeArray<PublicKeyReference>
};

export interface WorkerDecryptSessionKeyOptions extends Omit<DecryptSessionKeyOptionsPmcrypto, 'message' | 'decryptionKeys'> {
    armoredMessage?: string;
    binaryMessage?: Uint8Array;
    decryptionKeys?: MaybeArray<PrivateKeyReference>;
};

export interface WorkerGetMessageInfoOptions<T extends Data> {
    armoredMessage?: T extends string ? T : never,
    binaryMessage?: T extends Uint8Array ? T : never
}

export interface MessageInfo {
    signingKeyIDs: KeyID[],
    encryptionKeyIDs: KeyID[]
}

export interface WorkerGetSignatureInfoOptions<T extends Data> {
    armoredSignature?: T extends string ? T : never,
    binarySignature?: T extends Uint8Array ? T : never
}

export interface SignatureInfo {
    signingKeyIDs: KeyID[],
}

export type WorkerPublicKeyImport = { armoredKey?: string, binaryKey?: Uint8Array };
export type KeyID = string;

export interface KeyReference {
    /** Internal unique key identifier for the key store */
    readonly _idx: any,
    /** (Internal) key content identifier to determine equality */
    readonly _keyContentHash: string,
    getFingerprint(): string,
    getKeyID(): KeyID,
    getKeyIDs(): KeyID[],
    getAlgorithmInfo(): AlgorithmInfo,
    getCreationTime(): Date,
    isPrivate: () => this is PrivateKeyReference,
    getExpirationTime(): Date | number | null,
    getUserIDs(): string[],
    /**
     * Compare public key content. Keys are considered equal if they have same key and subkey material,
     * as well as same certification signatures, namely same expiration time, capabilities, algorithm preferences etc.
     */
    equals(otherKey: KeyReference): boolean,
    subkeys: {
        getAlgorithmInfo(): AlgorithmInfo,
        getKeyID(): KeyID
    }[],
    // readonly armor: () => string
}
export interface PublicKeyReference extends KeyReference {
    // isPrivate: () => false
}
export interface PrivateKeyReference extends KeyReference {
    isPrivate: () => true;
    // TODO add isStoredEncrypted? to allow importing encrypted keys without passphrase
}
