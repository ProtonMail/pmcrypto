import type { TransferHandler } from 'comlink';
import type { KeyReference, KeyInfo } from './api.models';

// return interface with same non-function fields as T, and with function fields type converted to their return type
// e.g. ExtractFunctionReturnTypes<{ foo: () => string, bar: 3 }> returns { foo: string, bar: 3 }
type ExtractFunctionReturnTypes<T> = {
    [I in keyof T]: T[I] extends (...args: any) => any ?
        ReturnType<T[I]> :
        T[I] extends Array<infer A> ? ExtractFunctionReturnTypes<A>[] : T[I] // recurse on array fields
};

type SerializedKeyReference = ExtractFunctionReturnTypes<KeyReference>;
const KeyReferenceSerializer = {
    canHandle: (obj: any): obj is KeyReference => (typeof obj === 'object') && obj._idx !== undefined && obj.isPrivate !== undefined, // NB: careful not to confuse with KeyInfo object
    serialize: (keyReference: KeyReference): SerializedKeyReference => ({  // store values directly, convert back to function when deserialising
        ...keyReference,
        isPrivate: keyReference.isPrivate(),
        getFingerprint: keyReference.getFingerprint(),
        getKeyID: keyReference.getKeyID(),
        getKeyIDs: keyReference.getKeyIDs(),
        getAlgorithmInfo: keyReference.getAlgorithmInfo(),
        getCreationTime: keyReference.getCreationTime(),
        getExpirationTime: keyReference.getExpirationTime(),
        getUserIDs: keyReference.getUserIDs(),
        isWeak: keyReference.isWeak(),
        equals: false, // unused, function will be reconstructed based on ._keyContentHash
        subkeys: keyReference.subkeys.map((subkey) => ({
            getAlgorithmInfo: subkey.getAlgorithmInfo(),
            getKeyID: subkey.getKeyID()
        }))
    }),

    deserialize: (serialized: SerializedKeyReference): KeyReference => ({
        ...serialized,
        isPrivate: () => serialized.isPrivate,
        getFingerprint: () => serialized.getFingerprint,
        getKeyID: () => serialized.getKeyID,
        getKeyIDs: () => serialized.getKeyIDs,
        getAlgorithmInfo: () => serialized.getAlgorithmInfo,
        getCreationTime: () => serialized.getCreationTime,
        getExpirationTime: () => serialized.getExpirationTime,
        getUserIDs: () => serialized.getUserIDs,
        isWeak: () => serialized.isWeak,
        equals: (otherKey) => otherKey._keyContentHash === serialized._keyContentHash,
        subkeys: serialized.subkeys.map((subkey) => ({
            getAlgorithmInfo: () => subkey.getAlgorithmInfo,
            getKeyID: () => subkey.getKeyID
        }))
    })
};

type SerializedKeyInfo = ExtractFunctionReturnTypes<KeyInfo>;
const KeyInfoSerializer = {
    canHandle: (obj: any): obj is KeyInfo => (typeof obj === 'object') && obj.isDecrypted !== undefined && obj.isPrivate !== undefined, // NB: careful not to confuse with KeyReference object
    serialize: (keyInfo: KeyInfo): SerializedKeyInfo => ({ // store values directly, convert back to function when deserialising
        isPrivate: keyInfo.isPrivate(),
        isDecrypted: keyInfo.isDecrypted()
    }),
    deserialize: (serialized: SerializedKeyInfo): KeyInfo => ({
        isPrivate: () => serialized.isPrivate,
        isDecrypted: () => serialized.isDecrypted
    })
}

const KeyOptionsSerializer = {
    _optionNames: ['verificationKeys', 'signingKeys', 'encryptionKeys', 'decryptionKeys', 'keyReference', 'targetKeys'],
    canHandle: (options: any): options is KeyReference | KeyReference[] => {
        if (typeof options !== 'object') return false;
        return KeyOptionsSerializer._optionNames.some((name) => options[name]);
    },

    serialize: (options: any) => {
        const serializedOptions = { ...options };
        KeyOptionsSerializer._optionNames.forEach((name) => {
            if (name in options) {
                serializedOptions[name] = Array.isArray(options[name]) ?
                    options[name].map(KeyReferenceSerializer.serialize) :
                    KeyReferenceSerializer.serialize(options[name]);
            }
        });
        return serializedOptions;
    },

    deserialize: (serializedOptions: any) => {
        const options = { ...serializedOptions };
        KeyOptionsSerializer._optionNames.forEach((name) => {
            if (name in serializedOptions) {
                options[name] = Array.isArray(options[name]) ?
                    serializedOptions[name].map(KeyReferenceSerializer.deserialize) :
                    KeyReferenceSerializer.deserialize(serializedOptions[name]);
            }
        });

        return options;
    }
};

const ResultTranferer = {
    _binaryFieldNames: ['message', 'signature', 'signatures', 'encryptedSignature', 'sessionKey'],
    canHandle: (result: any): result is any => {
        if (typeof result !== 'object') return false;
        return ResultTranferer._binaryFieldNames.some((name) => result[name]);
    },

    getTransferables: (result: any) => {
        const transferables = ResultTranferer._binaryFieldNames
            .filter((name) => (name in result && result[name] instanceof Uint8Array))
            .map((name) => result[name].buffer);
        // 'signatures' are always in binary form
        return transferables.concat(result.signatures ? result.signatures.map((sig: Uint8Array) => sig.buffer) : []);
    }
};

type OneWayTransferHandler = {
    name: string,
    workerHandler: TransferHandler<any, any>,
    mainThreadHandler: TransferHandler<any, any>
};
type ExportedTransferHandler = { name: string, handler: TransferHandler<any, any> };

/**
 * Transfer handlers for data that needs to be transferred only in one direction (e.g. from the worker to the main thread).
 * NB: serializer still needs to be declared for recipient side too (comlink does not support implementing only the deserializer)
 */
const oneWayTransferHanders: OneWayTransferHandler[] = [
    {
        name: 'Uint8Array', // automatically transfer Uint8Arrays from worker (but not vice versa)
        workerHandler: {
            canHandle: (input: any): input is Uint8Array => input instanceof Uint8Array,
            serialize: (bytes: Uint8Array) => [
                bytes,
                [bytes.buffer] // transferables
            ],
            deserialize: (bytes) => bytes
        },
        mainThreadHandler: {
            canHandle: (input: any): input is Uint8Array => input instanceof Uint8Array,
            serialize: (bytes: Uint8Array) => [
               bytes,
               [] // transferables: no transferring from main thread
            ],
            deserialize: (bytes) => bytes
        }
    },
    {
        name: 'encrypt/decrypt/sign/verifyResult', // result objects are already serialised, but we need to transfer all Uint8Arrays fields from worker
        workerHandler: {
            canHandle: ResultTranferer.canHandle,
            serialize: (result: any) => [
                result,
                ResultTranferer.getTransferables(result) // transferables
            ],
            deserialize: (result) => result // unused
        },
        mainThreadHandler: {
            canHandle: ResultTranferer.canHandle,
            serialize: (result: any) => [result, []], // unused
            deserialize: (result) => result
        }
    }
]

/**
 * These transferHandles are needed to transfer some objects from and to the worker (either as returned data, or as arguments).
 * They are meant to be set both inside the worker and in the main thread.
 */
const sharedTransferHandlers: ExportedTransferHandler[] = [
    {
        name: 'KeyReference',
        handler: {
            canHandle: KeyReferenceSerializer.canHandle,
            serialize: (keyReference: KeyReference) => [
                KeyReferenceSerializer.serialize(keyReference),
                [] // transferables
            ],
            deserialize: KeyReferenceSerializer.deserialize
        }
    },
    {
        name: 'KeyOptions', // only passed by the main thread, but it's harmless to declare the same handler on both sides
        handler: {
            canHandle: KeyOptionsSerializer.canHandle,
            serialize: (options: object) => [
                KeyOptionsSerializer.serialize(options),
                [] // transferables
            ],
            deserialize: KeyOptionsSerializer.deserialize
        }
    },
    {
        name: 'KeyInfo', // only returned by the worker, but it's harmless to declare the same handler on both sides
        handler: {
            canHandle: KeyInfoSerializer.canHandle,
            serialize: (keyInfo: KeyInfo) => [
                KeyInfoSerializer.serialize(keyInfo),
                [] // transferables
            ],
            deserialize: KeyInfoSerializer.deserialize
        }
    }
];

// Handlers to be set by the worker
export const workerTransferHandlers: ExportedTransferHandler[] = [
    ...sharedTransferHandlers,
    ...oneWayTransferHanders.map(({ name, workerHandler }) => ({ name, handler: workerHandler }))
];

// Handlers to be set by the main thread
export const mainThreadTransferHandlers: ExportedTransferHandler[] = [
    ...sharedTransferHandlers,
    ...oneWayTransferHanders.map(({ name, mainThreadHandler }) => ({ name, handler: mainThreadHandler }))
];
