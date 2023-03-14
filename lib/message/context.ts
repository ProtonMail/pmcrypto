/**
 * The context is an abstraction we use to add domain separation to OpenPGP signatures.
 * It's implemented by adding notation data to signatures, which may be marked as critical, so that
 * the resulting signature can only be verified by a verifier who expects the context to be present.
 */
import type { SignaturePacket, RawNotation, PartialConfig } from '../openpgp';
import { normalizeDate } from '../utils';

// Different contexts will affect the notation's value, not the name
const CONTEXT_NOTATION_NAME = 'context@proton.ch';

export interface ContextSigningOptions {
    /** context identifier */
    value: string,
    /**
     * Whether verification must fail unless the verifier is context-aware:
     * if `true`, the signature cannot be verified unless the verifier expects the same context.
     * If `false`, the signature will verify successfully even if the verifier does not expect any context.
     * This should be set to `true` as long as all clients verifying the signature are able to process contexts.
     */
    critical: boolean
}

export type ContextVerificationOptions = {
    value: string,
    /**
     * Whether the signature must include context info for verification to succeed:
     * if `true`, a signature with no context won't verify. If `false`, it will.
     * Note: if the context is not required, but a different context is found in the signature, verification will always fail.
     */
    required: boolean,
    requiredAfter?: undefined
} | {
    value: string,
    required?: undefined
    /**
     * Signatures created after this date must include context info for verification to succeed (same as `required: true`).
     * For signatures created before the given date, the verification behavior is equivalent to `required: false`
     * */
    requiredAfter: Date,
};

/**
 * Translate a `contextID` string into an OpenPGP notation object, which can be signed as part of the message
 * @param contextValue - context identifier
 * @param critical - whether the notation should be critical (if so, verification will fail if in the wrong context,
 *  i.e. if the caller did not declare the notation as known)
 */
export const getNotationForContext = (contextValue: string, critical: boolean): RawNotation => ({
    name: CONTEXT_NOTATION_NAME,
    value: new TextEncoder().encode(contextValue),
    humanReadable: true,
    critical
});

/**
 * Confirm context validity by finding the corresponding signature notation.
 * NB: signature validity is not checked.
 */
export const isValidSignatureContext = (contextOptions: ContextVerificationOptions, signature: SignaturePacket) => {
    const { value: expectedValue, required, requiredAfter } = contextOptions;
    const isContextRequired = requiredAfter ? signature.created! >= normalizeDate(requiredAfter) : !!required;

    // `rawNotations` are always hashed (i.e. signed), otherwise OpenPGP's ignores them on parsing
    const contextNotations = signature.rawNotations.filter(({ name }) => (name === CONTEXT_NOTATION_NAME));
    const matchingContext = contextNotations.find(({ value }) => (new TextDecoder().decode(value) === expectedValue));

    if (matchingContext) {
        return true;
    } else if (contextNotations.length > 0) {
        // mismatching context is present
        return false;
    }

    // no context info found
    return !isContextRequired;

};

/**
 * Signatures with critical context data can only be verified with a config that declares the context notation data as known
 */
export const getConfigForContextVerification = (config: PartialConfig) => ({
    ...config,
    knownNotations: [CONTEXT_NOTATION_NAME] // we can overwrite the field as we currently don't use any other known notations
});

/**
 * Context verification error.
 * Thrown if e.g. context information is not present in the signature, or it does not match the expected context.
 */
export class ContextError extends Error {
    constructor(message: string) {
        super(message);

        this.name = 'ContextError';
    }
}
