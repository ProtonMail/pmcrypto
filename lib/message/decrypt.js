import { isStream, readToEnd } from '@openpgp/web-stream-tools';
import { decrypt, readSignature } from '../openpgp';
import { serverTime } from '../serverTime';
import { getConfigForContextVerification } from './context';
import { handleVerificationResult } from './verify';
import { DEFAULT_SIGNATURE_VERIFICATION_OFFSET } from '../constants';

export default async function decryptMessage({
    date = new Date(+serverTime() + DEFAULT_SIGNATURE_VERIFICATION_OFFSET),
    encryptedSignature,
    signatureContext,
    config = {},
    ...options
}) {
    if (signatureContext &&
        (options.verificationKeys === undefined ||
            (options.verificationKeys instanceof Array && options.verificationKeys.length === 0))) {
        // sanity check to catch mistakes in case library users wrongly consider the `context` to be
        // applied into e.g. the AEAD associated data
        throw new Error('Unexpected `signatureContext` input without any `verificationKeys` provided');
    }

    const sanitizedOptions = {
        ...options,
        date,
        config: signatureContext ? getConfigForContextVerification(config) : config
    };

    // If encryptedSignature exists, decrypt and use it
    if (encryptedSignature) {
        const { data: decryptedSignature } = await decrypt({
            ...sanitizedOptions,
            message: encryptedSignature,
            format: 'binary'
        });
        sanitizedOptions.signature = await readSignature({ binarySignature: await readToEnd(decryptedSignature) });
    }

    const decryptionResult = await decrypt(sanitizedOptions);
    const verificationResult = handleVerificationResult(decryptionResult, signatureContext, options.expectSigned);

    let verificationStatus = verificationResult.then((result) => result.verificationStatus);
    let verifiedSignatures = verificationResult.then((result) => result.signatures);
    let verificationErrors = verificationResult.then((result) => result.errors);

    if (!isStream(decryptionResult.data)) {
        verificationStatus = await verificationStatus;
        verifiedSignatures = await verifiedSignatures;
        verificationErrors = await verificationErrors;
    }

    return {
        data: decryptionResult.data,
        filename: decryptionResult.filename,
        verificationStatus,
        signatures: verifiedSignatures,
        verificationErrors
    };
}
