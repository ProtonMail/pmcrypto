/* eslint-disable class-methods-use-this */
/* eslint-disable max-classes-per-file */
/* eslint-disable no-underscore-dangle */
import {
    generateKey,
    reformatKey,
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
    decryptSessionKey,
    processMIME,
    SHA256,
    arrayToHexString,
    isRevokedKey,
    isExpiredKey,
    canKeyEncrypt,
    checkKeyStrength
} from '../pmcrypto';
import type {
    Data,
    PrivateKey,
    PublicKey,
    Key
} from '../pmcrypto';
import { decryptKey, encryptKey, MaybeArray, readPrivateKey } from '../openpgp';

import {
    PublicKeyReference,
    PrivateKeyReference,
    KeyReference,
    WorkerGenerateKeyOptions,
    WorkerReformatKeyOptions,
    WorkerImportPrivateKeyOptions,
    WorkerPublicKeyImport,
    WorkerEncryptOptions,
    WorkerSignOptions,
    WorkerVerifyOptions,
    WorkerDecryptionOptions,
    WorkerDecryptLegacyOptions,
    WorkerEncryptSessionKeyOptions,
    WorkerProcessMIMEOptions,
    WorkerGetMessageInfoOptions,
    MessageInfo,
    SignatureInfo,
    WorkerGetSignatureInfoOptions,
    WorkerGetKeyInfoOptions,
    KeyInfo
} from './api.models';
// Note:
// - streams are currently not supported since they are not Transferable (not in all browsers).
// - when returning binary data, the values are always transferred.

const getSignatureIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getSignature(serializedData) : undefined;

const getMessageIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getMessage(serializedData) : undefined;

const toArray = <T>(maybeArray: MaybeArray<T>) => (Array.isArray(maybeArray) ? maybeArray : [maybeArray]);

const getPublicKeyReference = async (key: PublicKey, keyStoreID: number): Promise<PublicKeyReference> => {
    const publicKey = key.isPrivate() ? key.toPublic() : key; // We don't throw on private key since we allow importing an (encrypted) private key using 'importPublicKey'

    const fingerprint = publicKey.getFingerprint();
    const hexKeyID = publicKey.getKeyID().toHex();
    const hexKeyIDs = publicKey.getKeyIDs().map((id) => id.toHex());
    const algorithmInfo = publicKey.getAlgorithmInfo();
    const creationTime = publicKey.getCreationTime();
    const expirationTime = await publicKey.getExpirationTime();
    const userIDs = publicKey.getUserIDs();
    const keyContentHash = await SHA256(publicKey.write()).then(arrayToHexString);
    let isWeak: boolean; try { checkKeyStrength(publicKey); isWeak = false } catch { isWeak = true };
    return {
        _idx: keyStoreID,
        _keyContentHash: keyContentHash,
        isPrivate: () => false,
        getFingerprint: () => fingerprint,
        getKeyID: () => hexKeyID,
        getKeyIDs: () => hexKeyIDs,
        getAlgorithmInfo: () => algorithmInfo,
        getCreationTime: () => creationTime,
        getExpirationTime: () => expirationTime,
        getUserIDs: () => userIDs,
        isWeak: () => isWeak,
        equals: (otherKey: KeyReference) => (otherKey._keyContentHash === keyContentHash),
        subkeys: publicKey.getSubkeys().map((subkey) => {
            const subkeyAlgoInfo = subkey.getAlgorithmInfo();
            const subkeyKeyID = subkey.getKeyID().toHex();
            return {
                getAlgorithmInfo: () => subkeyAlgoInfo,
                getKeyID: () => subkeyKeyID
            };
        })
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
     * The starting counter value is picked at random to minimize the changes of collisions between keys during different user sessions.
     * NB: key references may be stored by webapps even after the worker has been destroyed (e.g. after closing the browser window),
     * hence we want to keep using different identifiers even after restarting the worker, to also invalidate those stale key references.
     */
    private nextIdx = Math.floor(Math.random() * (Number.MAX_SAFE_INTEGER / 2));

    /**
     * Add a key to the key store.
     * @param key - key to add
     * @param customIdx - custom identifier to use to store the key, instead of the internally generated one.
     *                    This argument is primarily intended for when key store identifiers need to be synchronised across different workers.
     *                    This value must be unique for each key, even across different sessions.
     * @returns key identifier to retrieve the key from the store
     */
    add(key: Key, customIdx?: number) {
        const idx = customIdx !== undefined ? customIdx : this.nextIdx;
        if (this.store.has(idx)) throw new Error('Idx already in use');
        this.store.set(idx, key);
        this.nextIdx++; // increment regardless of customIdx, for code simplicity
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

class KeyManagementApi {
    protected keyStore = new KeyStore();

    async clearKeyStore() {
        this.keyStore.clearAll();
    }

    async clearKey({ keyReference }: { keyReference: KeyReference }) {
        this.keyStore.clear(keyReference._idx);
    }

    async generateKey(options: WorkerGenerateKeyOptions) {
        // TODO is passphrase needed?
        const { privateKey } = await generateKey({ ...options, format: 'object' });
        // Typescript guards against a passphrase input, but it's best to ensure the option wasn't given since for API simplicity we assume any PrivateKeyReference points to a decrypted key.
        if (!privateKey.isDecrypted()) throw new Error('Unexpected "passphrase" option on key generation. Use "exportPrivateKey" after key generation to obtain a transferable encrypted key.')
        const keyStoreID = this.keyStore.add(privateKey);

        return getPrivateKeyReference(privateKey, keyStoreID);
    }

    async reformatKey({ keyReference, ...options }: WorkerReformatKeyOptions) {
        const originalKey = this.keyStore.get(keyReference._idx) as PrivateKey;
        // we have to deep clone before reformatting, since privateParams of reformatted key point to the ones of the given privateKey, and
        // we do not want reformatted key to be affected if the original key reference is cleared/deleted.
        // @ts-ignore - missing .clone() definition
        const keyToReformat = originalKey.clone(true);
        const { privateKey } = await reformatKey({ ...options, privateKey: keyToReformat, format: 'object' });
        // Typescript guards against a passphrase input, but it's best to ensure the option wasn't given since for API simplicity we assume any PrivateKeyReference points to a decrypted key.
        if (!privateKey.isDecrypted()) throw new Error('Unexpected "passphrase" option on key reformat. Use "exportPrivateKey" after key reformatting to obtain a transferable encrypted key.')
        const keyStoreID = this.keyStore.add(privateKey);

        return getPrivateKeyReference(privateKey, keyStoreID);
    }

    /**
     * Import a private key, which is either already decrypted, or that can be decrypted with the given passphrase.
     * If a passphrase is given, but the key is already decrypted, importing fails.
     * Either `armoredKey` or `binaryKey` must be provided.
     * Note: if the passphrase to decrypt the key is unknown, the key shuld be imported using `importPublicKey` instead.
     * @param options.passphrase - key passphrase if the input key is encrypted, or `null` if the input key is expected to be already decrypted
     * @returns reference to imported private key
     * @throws {Error} if the key cannot be decrypted or importing fails
     */
    async importPrivateKey<T extends Data>({
        armoredKey,
        binaryKey,
        passphrase
    }: WorkerImportPrivateKeyOptions<T>) {
        const expectDecrypted = passphrase === null;
        const maybeEncryptedKey = binaryKey ?
            await readPrivateKey({ binaryKey }) :
            await readPrivateKey({ armoredKey: armoredKey! });
        let decryptedKey;
        if (expectDecrypted) {
            if (!maybeEncryptedKey.isDecrypted()) throw new Error('Provide passphrase to import an encrypted private key');
            decryptedKey = maybeEncryptedKey;
            // @ts-ignore missing .validate() types
            await decryptedKey.validate();
        } else {
            decryptedKey = await decryptKey({ privateKey: maybeEncryptedKey, passphrase });
        }

        const keyStoreID = this.keyStore.add(decryptedKey);

        return getPrivateKeyReference(decryptedKey, keyStoreID);
    }

    async importPublicKey({ armoredKey, binaryKey }: WorkerPublicKeyImport) {
        const publicKey = await getKey(binaryKey || armoredKey!);
        const keyStoreID = this.keyStore.add(publicKey);

        return getPublicKeyReference(publicKey, keyStoreID);
    }

    async exportPublicKey<F extends SerialisedOutputFormat = 'armored'>({
        format = 'armored',
        keyReference
    }: {
        keyReference: KeyReference;
        format?: F;
    }): Promise<SerialisedOutputTypeFromFormat<F>> {
        const maybePrivateKey = this.keyStore.get(keyReference._idx);
        const publicKey = maybePrivateKey.isPrivate() ? maybePrivateKey.toPublic() : maybePrivateKey;
        const serializedKey = format === 'binary' ? publicKey.write() : publicKey.armor();
        return serializedKey as SerialisedOutputTypeFromFormat<F>;
    }

    /**
     * Get the serialized private key, encrypted with the given `passphrase`.
     * Exporting a key does not invalidate the corresponding `keyReference`, nor does it remove the key from internal storage (use `clearKey()` for that).
     * @param options.passphrase - passphrase to encrypt the key with (non-empty string), or `null` to export an unencrypted key (not recommended).
     * @param options.format - `'binary'` or `'armored'` format of serialized key
     * @returns serialized encrypted key
     */
    async exportPrivateKey<F extends SerialisedOutputFormat = 'armored'>({
        format = 'armored',
        ...options
    }: {
        keyReference: PrivateKeyReference;
        passphrase: string | null;
        format?: F;
    }): Promise<SerialisedOutputTypeFromFormat<F>> {
        const { keyReference, passphrase } = options;
        const privateKey = this.keyStore.get(keyReference._idx) as PrivateKey;
        const doNotEncrypt = passphrase === null;
        const maybeEncryptedKey = doNotEncrypt ? privateKey : await encryptKey({ privateKey, passphrase });

        const serializedKey = format === 'binary' ? maybeEncryptedKey.write() : maybeEncryptedKey.armor();
        return serializedKey as SerialisedOutputTypeFromFormat<F>;
    }
};

export class WorkerApi extends KeyManagementApi {
    // these are declared async so that exported type is a Promise and can be directly exposed by async proxy
    async serverTime() { return serverTime() }

    async updateServerTime(serverDate: Date) { return updateServerTime(serverDate) }

    async encryptMessage<
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
    }: WorkerEncryptOptions<T> & { format?: F; detached?: D; returnSessionKey?: SK }) {
        const signingKeys = await Promise.all(
            toArray(signingKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PrivateKey)
        );
        const encryptionKeys = await Promise.all(
            toArray(encryptionKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PublicKey)
        );
        const inputSignature = await getSignatureIfDefined(binarySignature || armoredSignature);

        const encryptionResult = await encryptMessage<T, F, D, SK>({
            ...options,
            encryptionKeys,
            signingKeys,
            signature: inputSignature
        });

        return encryptionResult;
    }

    async signMessage<
        T extends Data,
        F extends WorkerSignOptions<T>['format'] = 'armored'
        // inferring D (detached signature type) is unnecessary since the result type does not depend on it for format !== 'object'
    >({
        signingKeys: signingKeyRefs = [],
        ...options
    }: WorkerSignOptions<T> & { format?: F }) {
        const signingKeys = await Promise.all(
            toArray(signingKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PrivateKey)
        );
        const signResult = await signMessage<T, F, boolean>({
            ...options,
            signingKeys
        });

        return signResult;
    }

    async verifyMessage<
        T extends Data,
        F extends WorkerVerifyOptions<T>['format'] = 'utf8'
    >({
        armoredSignature,
        binarySignature,
        verificationKeys: verificationKeyRefs = [],
        ...options
    }: WorkerVerifyOptions<T> & { format?: F }) {
        const verificationKeys = await Promise.all(
            toArray(verificationKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx))
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
    }

    async decryptMessage<F extends WorkerDecryptionOptions['format'] = 'utf8'>({
        decryptionKeys: decryptionKeyRefs = [],
        verificationKeys: verificationKeyRefs = [],
        binaryEncryptedSignature,
        armoredMessage,
        binaryMessage,
        armoredSignature,
        binarySignature,
        armoredEncryptedSignature,
        ...options
    }: WorkerDecryptionOptions & { format?: F }) {
        const decryptionKeys = await Promise.all(
            toArray(decryptionKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PrivateKey)
        );
        const verificationKeys = await Promise.all(
            toArray(verificationKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx))
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
    }

    /**
     * Backwards-compatible decrypt message function, to be only used for email messages that might be of legacy format.
     * For all other cases, use `decryptMessage`.
     */
    async decryptMessageLegacy<F extends WorkerDecryptLegacyOptions['format'] = 'utf8'>({
        decryptionKeys: decryptionKeyRefs = [],
        verificationKeys: verificationKeyRefs = [],
        armoredMessage,
        armoredSignature,
        binarySignature,
        ...options
    }: WorkerDecryptLegacyOptions & { format?: F }) {
        const decryptionKeys = await Promise.all(
            toArray(decryptionKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PrivateKey)
        );
        const verificationKeys = await Promise.all(
            toArray(verificationKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx))
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
    }

    /**
     * Generating a session key for the specified symmetric algorithm.
     * To generate a session key based on some recipient's public key preferences,
     * use `generateSessionKeyFromKeyPreferences()` instead.
     */
    async generateSessionKey(algoName: Parameters<typeof generateSessionKey>[0]) {
        const sessionKeyBytes = await generateSessionKey(algoName);
        return sessionKeyBytes;
    }

    /**
     * Generate a session key compatible with the given recipient keys.
     * To get a session key for a specific symmetric algorithm, use `generateSessionKey` instead.
     */
    async generateSessionKeyFromKeyPreferences({ targetKeys: targetKeyRefs = [] }: {
        targetKeys: MaybeArray<PublicKeyReference>;
    }) {
        const targetKeys = await Promise.all(
            toArray(targetKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx))
        );
        const sessionKey = await generateSessionKeyFromKeyPreferences(targetKeys);
        return sessionKey;
    }

    async encryptSessionKey<F extends WorkerEncryptSessionKeyOptions['format'] = 'armored'>({
        encryptionKeys: encryptionKeyRefs = [],
        ...options
    }: WorkerEncryptSessionKeyOptions & { format?: F }): Promise<SerialisedOutputTypeFromFormat<F>> {
        const encryptionKeys = await Promise.all(
            toArray(encryptionKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PublicKey)
        );
        const encryptedData = await encryptSessionKey<F>({
            ...options,
            encryptionKeys
        })

        return encryptedData as SerialisedOutputTypeFromFormat<F>;
    }

    async decryptSessionKey({
        decryptionKeys: decryptionKeyRefs = [],
        armoredMessage,
        binaryMessage,
        ...options
    }: WorkerDecryptionOptions) {
        const decryptionKeys = await Promise.all(
            toArray(decryptionKeyRefs).map((keyReference) => this.keyStore.get(keyReference._idx) as PrivateKey)
        );

        const message = await getMessage(binaryMessage || armoredMessage!); // TODO check if defined?

        const sessionKey = await decryptSessionKey({
            ...options,
            message,
            decryptionKeys
        });

        return sessionKey;
    }

    async processMIME({
        verificationKeys: verificationKeyRefs = [],
        ...options
    }: WorkerProcessMIMEOptions) {
        const verificationKeys = toArray(verificationKeyRefs).map(
            (keyReference) => this.keyStore.get(keyReference._idx)
        );

        const {
            signatures: signatureObjects,
            ...resultWithoutSignature
        } = await processMIME({
            ...options,
            verificationKeys
        });

        const serialisedResult = {
            ...resultWithoutSignature,
            signatures: signatureObjects.map((sig) => sig.write() as Uint8Array)
        };
        return serialisedResult;
    }

    async getMessageInfo<T extends Data>({
        armoredMessage,
        binaryMessage
    }: WorkerGetMessageInfoOptions<T>): Promise<MessageInfo> {
        const message = await getMessage(binaryMessage || armoredMessage!);
        const signingKeyIDs = message.getSigningKeyIDs().map((keyID) => keyID.toHex());
        const encryptionKeyIDs = message.getEncryptionKeyIDs().map((keyID) => keyID.toHex());

        return { signingKeyIDs, encryptionKeyIDs };
    }

    async getSignatureInfo<T extends Data>({
        armoredSignature,
        binarySignature
    }: WorkerGetSignatureInfoOptions<T>): Promise<SignatureInfo> {
        const signature = await getSignature(binarySignature || armoredSignature!);
        const signingKeyIDs = signature.getSigningKeyIDs().map((keyID) => keyID.toHex());

        return { signingKeyIDs };
    }

    /**
     * Get basic info about a serialied key without importing it in the key store.
     * E.g. determine whether the given key is private, and whether it is decrypted.
     */
    async getKeyInfo<T extends Data>({
        armoredKey,
        binaryKey
    }: WorkerGetKeyInfoOptions<T>): Promise<KeyInfo> {
        const key = await getKey(binaryKey || armoredKey!);
        const isPrivate = key.isPrivate();
        const isDecrypted = isPrivate ? key.isDecrypted() : null;

        return {
            isPrivate: () => isPrivate,
            isDecrypted: () => isDecrypted
         };
    }

    async getArmoredSignature({ binarySignature }: { binarySignature: Uint8Array }) {
        const signature = await getSignature(binarySignature);
        return signature.armor();
    }

    async isRevokedKey({ keyReference, date }: { keyReference: KeyReference, date?: Date }) {
        const key = this.keyStore.get(keyReference._idx);
        const isRevoked = await isRevokedKey(key, date);
        return isRevoked;
    }

    /**
     * Returns whether the primary key is expired, or its creation time is in the future.
     */
    async isExpiredKey({ keyReference, date }: { keyReference: KeyReference, date?: Date }) {
        const key = this.keyStore.get(keyReference._idx);
        const isExpired = await isExpiredKey(key, date);
        return isExpired;
    }

    /**
     * Check whether a key can successfully encrypt a message.
     * This confirms that the key has encryption capabilities, it is neither expired nor revoked, and that its key material is valid.
     */
    async canKeyEncrypt({ keyReference, date }: { keyReference: KeyReference, date?: Date }) {
        const key = this.keyStore.get(keyReference._idx);
        const canEncrypt = await canKeyEncrypt(key, date);
        return canEncrypt;
    }
};
