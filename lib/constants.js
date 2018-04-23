const constants = {
    VERIFICATION_STATUS: {
        NOT_SIGNED: 0,
        SIGNED_AND_VALID: 1,
        SIGNED_AND_INVALID: 2,
    },
    SIGNATURE_TYPES: {
        BINARY: 0,
        CANONICAL_TEXT: 1
    }
};

module.exports = constants;
