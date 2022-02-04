import { expose, transfer } from 'comlink';
import {
    generateKey,
    utf8ArrayToString,
    encryptMessage,
    signMessage,
    decryptMessage,
    getSignature,
    getMessage
} from '../pmcrypto';
import type { DecryptOptionsPmcrypto } from '../pmcrypto';

// Note:
// - streams are currently not supported since they are not Transferable (not in all browsers).
// - when returning binary data, the values are always transferred. TODO: check that there is no (time) performance regression due to this
//      if large binary data is transferred.

// type EncryptOptionsPmcrypto = Parameters<typeof encryptMessage>
// interface WorkerEncryptionOptions extends Omit<EncryptOptionsPmcrypto, 'signature'> {
//     armoredSignature: string
// }

// TODO TS: do not allow mutually exclusive properties
export interface WorkerDecryptionOptions
    extends Omit<DecryptOptionsPmcrypto, 'message' | 'signature' | 'encryptedSignature'> {
    armoredSignature?: string;
    binarySignature?: Uint8Array;
    armoredMessage?: string;
    binaryMessage?: Uint8Array;
    armoredEncryptedSignature?: string;
    binaryEncryptedSignature?: Uint8Array;
}

const getSignatureIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getSignature(serializedData) : undefined;

const getMessageIfDefined = (serializedData?: string | Uint8Array) =>
    serializedData !== undefined ? getMessage(serializedData) : undefined;

export const WorkerApi = {
    utf8ArrayToString, // need utilities?
    encryptMessage, // transfer data (zero-copy)?
    signMessage,
    decryptMessage: async ({
        armoredMessage,
        binaryMessage,
        armoredSignature,
        binarySignature,
        armoredEncryptedSignature,
        binaryEncryptedSignature,
        ...options
    }: WorkerDecryptionOptions) => {
        const message = await getMessage(binaryMessage || armoredMessage!);
        const signature = await getSignatureIfDefined(binarySignature || armoredSignature);
        const encryptedSignature = await getMessageIfDefined(binaryEncryptedSignature || armoredEncryptedSignature);

        const decryptionResult = await decryptMessage({
            ...options, // TODO transfer `data` if format == binary
            message,
            signature,
            encryptedSignature
        });

        if (options.format === 'binary') {
            const decryptedData = decryptionResult.data as Uint8Array;
            return transfer(decryptionResult, [decryptedData.buffer]);
        }
        // TODO transfer signatures too (once decryptMessage returns them serialised)
        return decryptionResult;

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
