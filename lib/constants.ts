export enum VERIFICATION_STATUS {
    NOT_SIGNED = 0,
    SIGNED_AND_VALID = 1,
    SIGNED_AND_INVALID = 2
}

export enum SIGNATURE_TYPES {
    BINARY = 0,
    CANONICAL_TEXT = 1
}

export const MAX_ENC_HEADER_LENGTH = 1024;

/**
 * Offset needed for key generation to ensure key (incl. certification signatures) validity
 * across different servers, which might have slightly mismatching server time
 */
export const DEFAULT_OFFSET = -60000;

export const ARGON2_PARAMS = { // from https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
    RECOMMENDED: { passes: 1, parallelism: 4, memoryExponent: 19, tagLength: 32 },
    MINIMUM: { passes: 3, parallelism: 4, memoryExponent: 16, tagLength: 32 }
};
