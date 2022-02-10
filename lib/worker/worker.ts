import { expose, transfer } from 'comlink';
import {
    generateKey,
    utf8ArrayToString,
    encryptMessage,
    signMessage,
    decryptMessage,
    getSignature,
    getMessage,
    splitMessage,
    EncryptResult,
    verifyMessage
} from '../pmcrypto';
import type { DecryptOptionsPmcrypto, DecryptResultPmcrypto, SignOptionsPmcrypto, EncryptOptionsPmcrypto, Data, MaybeStream, VerifyOptionsPmcrypto, VerifyMessageResult } from '../pmcrypto';
import { readPrivateKey } from '../openpgp';
import { VerificationResult, WebStream } from 'openpgp';

export type { MaybeStream, Data };
const armoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYgQEWRYJKwYBBAHaRw8BAQdAhR6qir63dgL1bSt19bLFQfCIhvYnrk6f
OmvFwcYNf4wAAQCV4uj6Pg+08r+ztuloyzTDAV7eC/jenjm7AdYikQ0MZxFC
zQDCjAQQFgoAHQUCYgQEWQQLCQcIAxUICgQWAAIBAhkBAhsDAh4BACEJENDb
nirC49EHFiEEDgVXCWrFg3oEwWgN0NueKsLj0QdayAD+O1Qq4UrAn1Tz67d7
O3uWdpRWmbgfUr7XygeyWr57crYA/0/37SvtPoI6MHyrVYijXspJlVo0ZABb
dueO4TQCpPkAx10EYgQEWRIKKwYBBAGXVQEFAQEHQCVlPjHtTH0KaiZmgAeQ
f1tglgIeoZuT1fYWQMR5s0QkAwEIBwAA/1T9jghk9P2FAzix+Fst0go8OQ6l
clnLKMx9jFlqLmqAD57CeAQYFggACQUCYgQEWQIbDAAhCRDQ254qwuPRBxYh
BA4FVwlqxYN6BMFoDdDbnirC49EHobgA/R/1yGmo8/xrdipXIWTbL38sApGf
XU0oD7GPQhGsaxZjAQCmjVBDdt+CgmU9NFYwtTIWNHxxJtyf7TX7DY9RH1t2
DQ==
=2Lb6
-----END PGP PRIVATE KEY BLOCK-----`;

// Note:
// - streams are currently not supported since they are not Transferable (not in all browsers).
// - when returning binary data, the values are always transferred. TODO: check that there is no (time) performance regression due to this
//      if large binary data is transferred.

const getSignatureIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getSignature(serializedData) : undefined;

const getMessageIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getMessage(serializedData) : undefined;

// TODO TS: do not allow mutually exclusive properties
export interface WorkerDecryptionOptions
    extends Omit<DecryptOptionsPmcrypto<Data>, 'message' | 'signature' | 'encryptedSignature'> {
    armoredSignature?: string;
    binarySignature?: Uint8Array;
    armoredMessage?: string;
    binaryMessage?: Uint8Array;
    armoredEncryptedSignature?: string;
    binaryEncryptedSignature?: Uint8Array;
}
export interface WorkerDecryptionResult<T extends Data> extends Omit<DecryptResultPmcrypto<T>, 'signatures'> {
    signatures: Uint8Array[]
}
// TODO to make Option interfaces easy to use for the user, might be best to set default param types (e.g. T extends Data = Data).
export interface WorkerVerifyOptions<T extends Data> extends Omit<VerifyOptionsPmcrypto<T>, 'signature'> {
    armoredSignature?: string;
    binarySignature?: Uint8Array;
}
export interface WorkerVerificationResult<D extends Data = Data> extends Omit<VerifyMessageResult<D>, 'signatures'> {
    signatures: Uint8Array[]
}

export interface WorkerSignOptions<T extends Data> extends SignOptionsPmcrypto<T> {
    format?: 'armored' | 'binary'
};
export interface WorkerEncryptOptions<T extends Data> extends Omit<EncryptOptionsPmcrypto<T>, 'signature'> {
    format?: 'armored' | 'binary'
    armoredSignature?: string,
    binarySignature?: Uint8Array
};
export const WorkerApi = {
    encryptMessage: async <
        T extends Data,
        F extends WorkerEncryptOptions<T>['format'] = 'armored',
        D extends boolean = false,
        SK extends boolean = false
    >({
        armoredSignature,
        binarySignature,
        ...options
    }: WorkerEncryptOptions<T> & { format?: F; detached?: D; returnSessionKey?: SK }) => {
        const inputSignature = await getSignatureIfDefined(binarySignature || armoredSignature);

        const encryptionResult = await encryptMessage<T, F, D, SK>({ signature: inputSignature, ...options });

        const buffers = [];
        if (options.format === 'binary') {
            const {
                message, signature, encryptedSignature
            } = encryptionResult as EncryptResult<SK, Uint8Array, Uint8Array | undefined, Uint8Array | undefined>;

            buffers.push(message.buffer);
            // if options.detached
            signature && buffers.push(signature.buffer);
            encryptedSignature && buffers.push(encryptedSignature.buffer);
            // TODO transfer session keys? probably not worth it, since they are short
        }

        return transfer(encryptionResult, buffers);
    },
    signMessage: async <
        T extends Data,
        F extends WorkerSignOptions<T>['format'] = 'armored'
        // inferring D is unnecessary since the result type does not depend on it for format !== 'object'
    >(options: WorkerSignOptions<T> & { format?: F; }) => {
        options.signingKeys = await readPrivateKey({ armoredKey }); // TODO remove once there is a way to pass keys
        const signResult = await signMessage<T, F, boolean>(options);

        const buffers = [];
        if (options.format === 'binary') {
            const binaryData = signResult as Uint8Array;
            buffers.push(binaryData.buffer);
        }

        return transfer(signResult, buffers);
    },
    verifyMessage: async <
        T extends Data,
        F extends WorkerVerifyOptions<T>['format'] = 'utf8'
    >({
        armoredSignature,
        binarySignature,
        ...options
    }: WorkerVerifyOptions<T> & { format?: F }) => {
        options.verificationKeys = await readPrivateKey({ armoredKey }); // TODO remove once there is a way to pass keys

        const signature = await getSignature(binarySignature || armoredSignature!);
        const {
            signatures: signatureObjects, // extracting this is needed for proper type inference of `serialisedResult.signatures`
            ...verificationResultWithoutSignatures
        } = await verifyMessage<T, F>({ signature, ...options });

        const serialisedResult = {
            ...verificationResultWithoutSignatures,
            signatures: signatureObjects.map((sig) => sig.write() as Uint8Array) // no support for streamed input for now
        };

        const buffers = serialisedResult.signatures.map((sig) => sig.buffer);
        if (options.format === 'binary') {
            const data = serialisedResult.data as Uint8Array; // no support for streamed input for now
            buffers.push(data.buffer);
        }

        return transfer(serialisedResult, buffers)
    },
    splitMessage,
    decryptMessage: async <F extends WorkerDecryptionOptions['format'] = 'utf8'>({
        armoredMessage,
        binaryMessage,
        armoredSignature,
        binarySignature,
        armoredEncryptedSignature,
        binaryEncryptedSignature,
        ...options
    }: WorkerDecryptionOptions & { format?: F }) => {
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
            encryptedSignature
        });

        const serialisedResult = {
            ...decryptionResultWithoutSignatures,
            signatures: signatureObjects.map((sig) => sig.write() as Uint8Array) // no support for streamed input for now
        };

        const buffers = serialisedResult.signatures.map((sig) => sig.buffer);
        if (options.format === 'binary') {
            const decryptedData = serialisedResult.data as Uint8Array; // no support for streamed input for now
            buffers.push(decryptedData.buffer);
        }

        return transfer(serialisedResult, buffers)

        // TODO: once we have support for the intendedRecipient verification, we should add the
        // a `verify(publicKeys)` function to the decryption result, that allows verifying
        // the decrypted signatures after decryption.
        // Note: asking the apps to call `verifyMessage` separately is not an option, since
        // the verification result is to be considered invalid outside of the encryption context if the intended recipient is present, see: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-5.2.3.32
    },

    // TODO key store and management here
    generateKey
};

expose(WorkerApi);
