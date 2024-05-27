import { createMessage, verify, CleartextMessage } from '../openpgp';
import { DEFAULT_SIGNATURE_VERIFICATION_OFFSET, VERIFICATION_STATUS } from '../constants';
import { serverTime } from '../serverTime';
import { removeTrailingSpaces } from './utils';
import { ContextError, getConfigForContextVerification, isValidSignatureContext } from './context';

const { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } = VERIFICATION_STATUS;

/**
 * Extract information from the result of openpgp.verify
 * @param {Object} verificationResult return value of openpgp.verify
 * @param {Uint8Array|String|
 *          ReadableStream|NodeStream} verificationResult.data message data
 * @param {String} verificationResult.filename
 * @param {Object[]} verificationResult.signatures verification information per signature: {
 *           keyid: module:type/keyid,
 *           verified: Promise<Boolean>,
 *           signature: Promise<openpgp.signature.Signature>
 *         }
 * @param {Object} context - context verification options
 * @returns {{
 *     data: Uint8Array|string|ReadableStream|NodeStream - message data,
 *     verified: constants.VERIFICATION_STATUS - message verification status,
 *     signatures: openpgp.signature.Signature[] - message signatures,
 *     signatureTimestamp: Date|null - creation date of the first valid message signature, or null if all signatures are missing or invalid,
 *     errors: Error[]|undefined - verification errors if all signatures are invalid
 * }}
 */
export async function handleVerificationResult(verificationResult, context) {
    const { data, signatures: sigsInfo } = verificationResult;
    const signatures = [];
    const errors = [];
    let verificationStatus = NOT_SIGNED;
    let signatureTimestamp = null;

    if (sigsInfo && sigsInfo.length) {
        verificationStatus = SIGNED_AND_INVALID;
        for (let i = 0; i < sigsInfo.length; i++) {
            const { signature: signaturePromise, verified: verifiedPromise } = sigsInfo[i];
            const signature = await signaturePromise;
            const verified = await verifiedPromise.catch((err) => {
                errors.push(err);
                return false;
            });
            if (verified) {
                // In the context of message verification, signatures can only hold a single
                // packet. Thus we do not need to iterate over the packets and find the one
                // that verified the message. We can just use the single packet in the
                // signature.
                const verifiedSigPacket = signature.packets[0];

                if (!context || isValidSignatureContext(context, verifiedSigPacket)) {
                    verificationStatus = SIGNED_AND_VALID;
                } else {
                    errors.push(new ContextError());
                }

                if (!signatureTimestamp) {
                    signatureTimestamp = verifiedSigPacket.created;
                }
            }
            signatures.push(signature);
        }
    }

    return {
        data,
        verified: verificationStatus,
        signatures,
        signatureTimestamp,
        errors: verificationStatus === SIGNED_AND_INVALID ? errors : undefined
    };
}

/**
 * Verify the given message data against the signature
 * @param  {Object}                        options - input for openpgp.verify
 * @param  {String|ReadableStream<String>}  textData - sgined text data
 * @param  {Uint8Array|ReadableStream<Uint8Array>} binaryData - signed binary data
 * @param  {Date}                        [options.date] date to use for verification instead of the server time
 *
 * @returns {Promise<Object>}  Verification result in the form: {
 *     data: Uint8Array|string|ReadableStream - message data,
 *     verified: constants.VERIFICATION_STATUS - message verification status,
 *     signatures: openpgp.Signature[] - message signatures,
 *     signatureTimestamp: Date|null - creation date of the first valid message signature, or null if all signatures are missing or invalid,
 *     errors: Error[]|undefined - verification errors if all signatures are invalid
 * }
 */
export async function verifyMessage({
    textData,
    binaryData,
    stripTrailingSpaces,
    context,
    config = {},
    date = new Date(+serverTime() + DEFAULT_SIGNATURE_VERIFICATION_OFFSET),
    ...options
}) {
    const dataType = binaryData ? 'binary' : 'text';
    const dataToVerify = binaryData || (stripTrailingSpaces ? removeTrailingSpaces(textData) : textData); // throw if streamed text and stripTrailingSpaces enabled
    const sanitizedOptions = {
        ...options,
        date,
        message: await createMessage({ [dataType]: dataToVerify, date }),
        config: context ? getConfigForContextVerification(config) : config
    };

    const verificationResult = await verify(sanitizedOptions);
    return handleVerificationResult(verificationResult, context);
}

/**
 * Verify the given Cleartext message, which includes both the data to verify and the corresponding signature.
 * To verify a detached signature over some data, see `verifyMessage` instead.
 * @param  {Object}                      options - input for openpgp.verify
 * @param  {openpgp.CleartextMessage}    cleartextMessage - signed armored cleartext message
 * @param  {Date}                        [options.date] date to use for verification instead of the server time
 *
 * @returns {Promise<Object>}  Verification result in the form: {
 *     data: Uint8Array|string|ReadableStream - message data,
 *     verified: constants.VERIFICATION_STATUS - message verification status,
 *     signatures: openpgp.Signature[] - message signatures,
 *     signatureTimestamp: Date|null - creation date of the first valid message signature, or null if all signatures are missing or invalid,
 *     errors: Error[]|undefined - verification errors if all signatures are invalid
 * }
 */
export async function verifyCleartextMessage({ cleartextMessage, date = serverTime(), ...options }) {
    if (!(cleartextMessage instanceof CleartextMessage)) {
        throw new Error('CleartextMessage expected.');
    }
    const sanitizedOptions = { ...options, date, message: cleartextMessage };

    const verificationResult = await verify(sanitizedOptions);
    return handleVerificationResult(verificationResult);
}
