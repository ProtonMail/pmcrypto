/* eslint-disable no-underscore-dangle */
import {
    generateKey,
    encryptMessage,
    signMessage,
    decryptMessage,
    decryptMessageLegacy,
    getSignature,
    getMessage,
    encryptSessionKey,
    generateSessionKey,
    generateSessionKeyFromKeyPreferences,
    verifyMessage,
    getKey,
    serverTime,
    updateServerTime,
    decryptSessionKey
} from '../pmcrypto';
import type {
    DecryptOptionsPmcrypto,
    DecryptResultPmcrypto,
    SignOptionsPmcrypto,
    EncryptOptionsPmcrypto,
    Data,
    VerifyOptionsPmcrypto,
    VerifyMessageResult,
    PrivateKey,
    AlgorithmInfo,
    PublicKey,
    KeyOptions,
    Key,
    EncryptSessionKeyOptionsPmcrypto,
    DecryptSessionKeyOptionsPmcrypto,
    DecryptLegacyOptions
} from '../pmcrypto';
import { decryptKey, encryptKey, MaybeArray, readPrivateKey } from '../openpgp';

const test = new Uint8Array(19)
// Note:
// - streams are currently not supported since they are not Transferable (not in all browsers).
// - when returning binary data, the values are always transferred.

const getSignatureIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getSignature(serializedData) : undefined;

const getMessageIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getMessage(serializedData) : undefined;

const toArray = <T>(maybeArray: MaybeArray<T>) => (Array.isArray(maybeArray) ? maybeArray : [maybeArray]);

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

export type WorkerPublicKeyImport = { armoredKey?: string, binaryKey?: Uint8Array };

export interface KeyReference {
    /** Internal unique key identifier for the key store */
    readonly _idx: any,
    readonly fingerprint: string,
    readonly keyID: string,
    readonly algorithmInfo: AlgorithmInfo,
    readonly creationTime: Date,
    readonly isPrivate: () => this is PrivateKeyReference,
    readonly expirationTime: Date | number | null,
    readonly userIDs: string[],
    readonly subkeys: {
        algorithmInfo: AlgorithmInfo
    }[]
    // readonly armor: () => string
}
export interface PublicKeyReference extends KeyReference {
    // isPrivate: () => false
}
export interface PrivateKeyReference extends KeyReference {
    isPrivate: () => true;
    // TODO add isStoredEncrypted? to allow importing encrypted keys without passphrase
}

const getPublicKeyReference = async (key: PublicKey, keyStoreID: number): Promise<PublicKeyReference> => {
    const publicKey = key.isPrivate() ? key.toPublic() : key; // We don't throw on private key since we allow importing an (encrypted) private key using 'importPublicKey'

    return {
        _idx: keyStoreID,
        isPrivate: () => false,
        fingerprint: publicKey.getFingerprint(),
        keyID: publicKey.getKeyID().toHex(),
        algorithmInfo: publicKey.getAlgorithmInfo(),
        creationTime: publicKey.getCreationTime(),
        expirationTime: await publicKey.getExpirationTime(),
        userIDs: publicKey.getUserIDs(),
        subkeys: publicKey.getSubkeys().map((subkey) => ({ algorithmInfo: subkey.getAlgorithmInfo() }))
        // armor: () => armoredKey
    };
};

const getPrivateKeyReference = async (privateKey: PrivateKey, keyStoreID: number): Promise<PrivateKeyReference> => {
    // if (encryptedKey.isDecrypted()) throw new Error('Encrypted key expected');
    const publicKeyReference = await getPublicKeyReference(privateKey.toPublic(), keyStoreID);
    // const encryptedArmoredKey = encryptedKey.armor(); // we want to keep decrypted material inside the worker
    return {
        ...publicKeyReference,
        isPrivate: () => true
    };
};

class KeyStore {
    private store = new Map<number, Key>();

    /**
     * Monotonic counter keeping track of the next unique identifier to index a newly added key.
     * The starting counter value is picked at random to minimize the changes of collisions between different keys during a user session.
     * NB: key references may be stored by webapps even after the worker has been destroyed (e.g. after closing the browser window),
     * hence we want to keep using different identifiers even after restarting the worker, to also invalidate those stale key references.
     */
    private nextIdx = Math.floor(Math.random() * (Number.MAX_SAFE_INTEGER / 2));

    add(key: Key) {
        const idx = this.nextIdx;
        this.store.set(idx, key);
        this.nextIdx++;
        return idx;
    }

    get(idx: number) {
        const key = this.store.get(idx);
        if (!key) throw new Error('Key not found');
        return key;
    }

    clearAll() {
        this.store.forEach((key) => {
            // @ts-ignore missing definition for clearPrivateParams()
            if (key.isPrivate()) key.clearPrivateParams();
        });
        this.store.clear();
        // no need to reset index
    }

    clear(idx: number) {
        const keyToClear = this.get(idx);
        // @ts-ignore missing definition for clearPrivateParams()
        if (keyToClear.isPrivate()) keyToClear.clearPrivateParams();
        this.store.delete(idx);
    }
}

type SerialisedOutputFormat = 'armored' | 'binary' | undefined;
type SerialisedOutputTypeFromFormat<F extends SerialisedOutputFormat> = F extends 'armored' ? string : F extends 'binary' ? Uint8Array : never;

const keyStore = new KeyStore();
const KeyManagementApi = {
    clearKeyStore: async () => {
        keyStore.clearAll();
    },
    clearKey: async (keyReference: KeyReference) => {
        keyStore.clear(keyReference._idx);
    },
    generateKey: async (options: WorkerGenerateKeyOptions) => {
        // TODO is passphrase needed?
        const { privateKey } = await generateKey({ ...options, format: 'object' });
        // Typescript guards against a passphrase input, but it's best to ensure the option wasn't given since for API simplicity we assume any PrivateKeyReference points to a decrypted key.
        if (!privateKey.isDecrypted()) throw new Error('Unexpected "passphrase" option on key generation. Use "exportPrivateKey" after key generation to obtain a transferable encrypted key.')
        const keyStoreID = keyStore.add(privateKey);

        return getPrivateKeyReference(privateKey, keyStoreID);
    },

    /**
     * Import a private key, which is either already decrypted, or that can be decrypted with the given passphrase.
     * If a passphrase is given, but the key is already decrypted, importing fails.
     * Either `armoredKey` or `binaryKey` must be provided.
     * Note: if the passphrase to decrypt the key is unknown, the key shuld be imported using `importPublicKey` instead.
     * @param options.passphrase - key passphrase if the input key is encrypted, or `null` if the input key is expected to be already decrypted
     * @returns reference to imported private key
     * @throws {Error} if the key cannot be decrypted or importing fails
     */
    importPrivateKey: async <T extends Data>({
        armoredKey,
        binaryKey,
        passphrase
    }: WorkerImportPrivateKeyOptions<T>) => {
        const expectDecrypted = passphrase === null;
        const maybeEncryptedKey = binaryKey ?
            await readPrivateKey({ binaryKey }) :
            await readPrivateKey({ armoredKey: armoredKey! });
        if (expectDecrypted && !maybeEncryptedKey.isDecrypted()) throw new Error('Provide passphrase to import an encrypted private key');
        const decryptedKey = expectDecrypted ?
            maybeEncryptedKey :
            await decryptKey({ privateKey: maybeEncryptedKey, passphrase });
        const keyStoreID = keyStore.add(decryptedKey);

        return getPrivateKeyReference(decryptedKey, keyStoreID);
    },

    importPublicKey: async ({ armoredKey, binaryKey }: WorkerPublicKeyImport) => {
        const publicKey = await getKey(binaryKey || armoredKey!);
        const keyStoreID = keyStore.add(publicKey);

        return getPublicKeyReference(publicKey, keyStoreID);
    },

    exportPublicKey: async <F extends SerialisedOutputFormat = 'armored'>({
        format = 'armored',
        keyReference
    }: {
        keyReference: KeyReference;
        format?: F;
    }): Promise<SerialisedOutputTypeFromFormat<F>> => {
        const maybePrivateKey = keyStore.get(keyReference._idx);
        const publicKey = maybePrivateKey.isPrivate() ? maybePrivateKey.toPublic() : maybePrivateKey;
        const serializedKey = format === 'binary' ? publicKey.write() : publicKey.armor();
        return serializedKey as SerialisedOutputTypeFromFormat<F>;
    },

    exportPrivateKey: async <F extends SerialisedOutputFormat = 'armored'>({
        format = 'armored',
        ...options
    }: {
        keyReference: PrivateKeyReference;
        passphrase: string;
        format?: F;
    }): Promise<SerialisedOutputTypeFromFormat<F>> => {
        const { keyReference, passphrase } = options;
        const privateKey = keyStore.get(keyReference._idx) as PrivateKey;
        const encryptedKey = await encryptKey({ privateKey, passphrase });

        const serializedKey = format === 'binary' ? encryptedKey.write() : encryptedKey.armor();
        return serializedKey as SerialisedOutputTypeFromFormat<F>;
    }
};

export const WorkerApi = {
    ...KeyManagementApi, // TODO split to separate worker?

    // these are declared async so that exported type is a Promise and can be directly exposed by async proxy
    serverTime: async () => serverTime(),
    updateServerTime: async (serverDate: Date) => updateServerTime(serverDate),

    encryptMessage: async <
        T extends Data,
        F extends WorkerEncryptOptions<T>['format'] = 'armored',
        D extends boolean = false,
        SK extends boolean = false
    >({
        encryptionKeys: encryptionKeyRefs = [],
        signingKeys: signingKeyRefs = [],
        armoredSignature,
        binarySignature,
        ...options
    }: WorkerEncryptOptions<T> & { format?: F; detached?: D; returnSessionKey?: SK }) => {
        const signingKeys = await Promise.all(
            toArray(signingKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PrivateKey)
        );
        const encryptionKeys = await Promise.all(
            toArray(encryptionKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PublicKey)
        );
        const inputSignature = await getSignatureIfDefined(binarySignature || armoredSignature);

        const encryptionResult = await encryptMessage<T, F, D, SK>({
            ...options,
            encryptionKeys,
            signingKeys,
            signature: inputSignature
        });

        return encryptionResult;
    },
    signMessage: async <
        T extends Data,
        F extends WorkerSignOptions<T>['format'] = 'armored'
        // inferring D (detached signature type) is unnecessary since the result type does not depend on it for format !== 'object'
    >({
        signingKeys: signingKeyRefs = [],
        ...options
    }: WorkerSignOptions<T> & { format?: F }) => {
        const signingKeys = await Promise.all(
            toArray(signingKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PrivateKey)
        );
        const signResult = await signMessage<T, F, boolean>({
            ...options,
            signingKeys
        });

        return signResult;
    },
    verifyMessage: async <
        T extends Data,
        F extends WorkerVerifyOptions<T>['format'] = 'utf8'
    >({
        armoredSignature,
        binarySignature,
        verificationKeys: verificationKeyRefs = [],
        ...options
    }: WorkerVerifyOptions<T> & { format?: F }) => {
        const verificationKeys = await Promise.all(
            toArray(verificationKeyRefs).map((keyReference) => keyStore.get(keyReference._idx))
        );
        const signature = await getSignature(binarySignature || armoredSignature!);
        const {
            signatures: signatureObjects, // extracting this is needed for proper type inference of `serialisedResult.signatures`
            ...verificationResultWithoutSignatures
        } = await verifyMessage<T, F>({ signature, verificationKeys, ...options });

        const serialisedResult = {
            ...verificationResultWithoutSignatures,
            signatures: signatureObjects.map((sig) => sig.write() as Uint8Array) // no support for streamed input for now
        };

        return serialisedResult;
    },
    decryptMessage: async <F extends WorkerDecryptionOptions['format'] = 'utf8'>({
        decryptionKeys: decryptionKeyRefs = [],
        verificationKeys: verificationKeyRefs = [],
        binaryEncryptedSignature,
        armoredMessage,
        binaryMessage,
        armoredSignature,
        binarySignature,
        armoredEncryptedSignature,
        ...options
    }: WorkerDecryptionOptions & { format?: F }) => {
        const decryptionKeys = await Promise.all(
            toArray(decryptionKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PrivateKey)
        );
        const verificationKeys = await Promise.all(
            toArray(verificationKeyRefs).map((keyReference) => keyStore.get(keyReference._idx))
        );

        const message = await getMessage(binaryMessage || armoredMessage!); // TODO check if defined too?
        const signature = await getSignatureIfDefined(binarySignature || armoredSignature);
        const encryptedSignature = await getMessageIfDefined(binaryEncryptedSignature || armoredEncryptedSignature);

        const {
            signatures: signatureObjects,
            ...decryptionResultWithoutSignatures
        } = await decryptMessage<Data, F>({
            ...options,
            message,
            signature,
            encryptedSignature,
            decryptionKeys,
            verificationKeys
        });

        const serialisedResult = {
            ...decryptionResultWithoutSignatures,
            signatures: signatureObjects.map((sig) => sig.write() as Uint8Array) // no support for streamed input for now
        };

        return serialisedResult;

        // TODO: once we have support for the intendedRecipient verification, we should add the
        // a `verify(publicKeys)` function to the decryption result, that allows verifying
        // the decrypted signatures after decryption.
        // Note: asking the apps to call `verifyMessage` separately is not an option, since
        // the verification result is to be considered invalid outside of the encryption context if the intended recipient is present, see: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-5.2.3.32
    },
    /**
     * Backwards-compatible decrypt message function, to be only used for email messages that might be of legacy format.
     * For all other cases, use `decryptMessage`.
     */
    decryptMessageLegacy: async <F extends WorkerDecryptLegacyOptions['format'] = 'utf8'>({
        decryptionKeys: decryptionKeyRefs = [],
        verificationKeys: verificationKeyRefs = [],
        armoredMessage,
        armoredSignature,
        binarySignature,
        ...options
    }: WorkerDecryptLegacyOptions & { format?: F }) => {
        const decryptionKeys = await Promise.all(
            toArray(decryptionKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PrivateKey)
        );
        const verificationKeys = await Promise.all(
            toArray(verificationKeyRefs).map((keyReference) => keyStore.get(keyReference._idx))
        );

        const signature = await getSignatureIfDefined(binarySignature || armoredSignature);

        const {
            signatures: signatureObjects,
            ...decryptionResultWithoutSignatures
        } = await decryptMessageLegacy<Data, F>({
            ...options,
            message: armoredMessage,
            signature,
            decryptionKeys,
            verificationKeys
        });

        const serialisedResult = {
            ...decryptionResultWithoutSignatures,
            signatures: signatureObjects.map((sig) => sig.write() as Uint8Array) // no support for streamed input for now
        };
        return serialisedResult;
    },
    /**
     * Generating a session key for the specified symmetric algorithm.
     * To generate a session key based on some recipient's public key preferences,
     * use `generateSessionKeyFromKeyPreferences()` instead.
     */
    generateSessionKey: async (algoName: Parameters<typeof generateSessionKey>[0]) => {
        const sessionKeyBytes = await generateSessionKey(algoName);
        return sessionKeyBytes;
    },
    /**
     * Generate a session key compatible with the given recipient keys.
     * To get a session key for a specific symmetric algorithm, use `generateSessionKey` instead.
     */
    generateSessionKeyFromKeyPreferences: async ({ targetKeys: targetKeyRefs = [] }: {
        targetKeys: MaybeArray<PublicKeyReference>;
    }) => {
        const targetKeys = await Promise.all(
            toArray(targetKeyRefs).map((keyReference) => keyStore.get(keyReference._idx))
        );
        const sessionKey = await generateSessionKeyFromKeyPreferences(targetKeys);
        return sessionKey;
    },

    encryptSessionKey: async <F extends WorkerEncryptSessionKeyOptions['format'] = 'armored'>({
        encryptionKeys: encryptionKeyRefs = [],
        ...options
    }: WorkerEncryptSessionKeyOptions & { format?: F }): Promise<SerialisedOutputTypeFromFormat<F>> => {
        const encryptionKeys = await Promise.all(
            toArray(encryptionKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PublicKey)
        );
        const encryptedData = await encryptSessionKey<F>({
            ...options,
            encryptionKeys
        })

        return encryptedData as SerialisedOutputTypeFromFormat<F>;
    },

    decryptSessionKey: async ({
        decryptionKeys: decryptionKeyRefs = [],
        armoredMessage,
        binaryMessage,
        ...options
    }: WorkerDecryptionOptions) => {
        const decryptionKeys = await Promise.all(
            toArray(decryptionKeyRefs).map((keyReference) => keyStore.get(keyReference._idx) as PrivateKey)
        );

        const message = await getMessage(binaryMessage || armoredMessage!); // TODO check if defined?

        const sessionKey = await decryptSessionKey({
            ...options,
            message,
            decryptionKeys
        });

        return sessionKey;
    }
};
