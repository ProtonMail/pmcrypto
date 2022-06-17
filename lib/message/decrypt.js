import { isStream, readToEnd } from '@openpgp/web-stream-tools';
import { decrypt, readSignature } from '../openpgp';
import { serverTime } from '../serverTime';
import { handleVerificationResult } from './verify';

export default async function decryptMessage({ date = serverTime(), encryptedSignature, ...options }) {
    const sanitizedOptions = { ...options, date };

    try {
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
        const verificationResult = handleVerificationResult(decryptionResult);

        let verified = verificationResult.then((result) => result.verified);
        let verifiedSignatures = verificationResult.then((result) => result.signatures);
        let verificationErrors = verificationResult.then((result) => result.errors);

        if (!isStream(decryptionResult.data)) {
            verified = await verified;
            verifiedSignatures = await verifiedSignatures;
            verificationErrors = await verificationErrors;
        }

        return {
            data: decryptionResult.data,
            filename: decryptionResult.filename,
            verified,
            signatures: verifiedSignatures,
            verificationErrors
        };
    } catch (err) {
        return Promise.reject(err);
    }
}
