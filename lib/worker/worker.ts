import { expose } from 'comlink';
import { generateKey, utf8ArrayToString, encryptMessage, signMessage, decryptMessage, getSignature, getMessage } from '../pmcrypto';
import type { MaybeStream, DecryptOptionsPmcrypto, EncryptOptionsPmcrypto } from '../pmcrypto';
import { readMessage } from '../openpgp';

// Note: streams are currently not supported since they are not Transferable (not in all browsers).

interface WorkerDecryptionOptions extends Omit<DecryptOptionsPmcrypto, 'message' | 'signature' | 'encryptedSignature'> {
    armoredSignature?: string,
    binarySignature?: Uint8Array,
    armoredMessage?: string,
    binaryMessage?: Uint8Array,
    armoredEncryptedSignature?: string,
    binaryEncryptedSignature?: Uint8Array
}

const getSignatureIfDefined = (serializedData?: string | Uint8Array) => (
    serializedData !== undefined ? getSignature(serializedData) : undefined
);

const getMessageIfDefined = (serializedData?: string | Uint8Array) => (
    serializedData !== undefined ? getMessage(serializedData) : undefined
);

export const WorkerApi = {
    inc: () => {
        return 1;
    },
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

        return decryptMessage({
            ...options,
            message,
            signature,
            encryptedSignature
        });

        // TODO: once we have support for the intendedRecipient verification, we should add the
        // a `verify(publicKeys)` function to the decryption result, that allows verifying
        // the decrypted signatures after decryption.
        // Note: asking the apps to call `verifyMessage` separately is not an option, since
        // the verification result is to be considered invalid outside of the encryption context if the intended recipient is present, see: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-5.2.3.32
    },
    testTransfer: (stream: unknown) => { console.log(stream) },

    // remove?
    readMessage: () => 3,

    // key store and management also here (not in proxy)
    generateKey
};

expose(WorkerApi);


