/* eslint-disable no-prototype-builtins */
import { openpgp } from '../openpgp';
import { VERIFICATION_STATUS } from '../constants';
import { serverTime } from '../serverTime';

const { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } = VERIFICATION_STATUS;

/**
 * Prepare message
 * @param {Object|Uint8Array|String} message
 * @return {Promise<Object>}
 */
export async function getMessage(message) {
    if (openpgp.message.Message.prototype.isPrototypeOf(message)) {
        return message;
    }
    if (Uint8Array.prototype.isPrototypeOf(message)) {
        return openpgp.message.read(message);
    }
    return openpgp.message.readArmored(message.trim());
}

/**
 * Prepare signature
 * @param {String|Uint8Array|openpgp.signature.Signature} signature
 * @return {Promise<openpgp.signature.Signature>}
 */
export async function getSignature(signature) {
    if (openpgp.signature.Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    }
    if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return openpgp.signature.read(signature);
    }
    return openpgp.signature.readArmored(signature.trim());
}

/**
 * Read a cleartext message from an armored message.
 * @param {String|openpgp.cleartext.CleartextMessage} message
 * @return {Promise<openpgp.cleartext.CleartextMessage>}
 */
export async function getCleartextMessage(message) {
    if (openpgp.cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return openpgp.cleartext.readArmored(message.trim());
}

/**
 * Create a cleartext message from a text.
 * @param {String|openpgp.cleartext.CleartextMessage} message
 * @return {openpgp.cleartext.CleartextMessage}
 */
export function createCleartextMessage(message) {
    if (openpgp.cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return openpgp.cleartext.fromText(message);
}

export function createMessage(source, filename, date = serverTime()) {
    if (Uint8Array.prototype.isPrototypeOf(source)) {
        return openpgp.message.fromBinary(source, filename, date);
    }
    return openpgp.message.fromText(source, filename, date);
}

export function signMessage(options) {
    if (typeof options.data === 'string') {
        options.message = createCleartextMessage(options.data);
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp.sign(options).catch((err) => {
        console.error(err);
        return Promise.reject(err);
    });
}

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
 * @returns {{
 *     data: Uint8Array|string|ReadableStream|NodeStream - message data,
 *     filename: String,
 *     verified: constants.VERIFICATION_STATUS - message verification status,
 *     signatures: openpgp.signature.Signature[] - message signatures,
 *     signatureTimestamp: Date|null - creation date of the first valid message signature, or null if all signatures are missing or invalid,
 *     errors: Error[]|undefined - verification errors if all signatures are invalid
 * }}
 */
export async function handleVerificationResult({ data, filename = 'msg.txt', signatures: sigsInfo }) {
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
                verificationStatus = SIGNED_AND_VALID;

                const verifiedSigPacket = signature.packets.find((signaturePacket) => signaturePacket.verified);
                if (verifiedSigPacket && !signatureTimestamp) {
                    signatureTimestamp = verifiedSigPacket.created;
                }
            }
            signatures.push(signature);
        }
    }

    return {
        data,
        verified: verificationStatus,
        filename,
        signatures,
        signatureTimestamp,
        errors: verificationStatus === SIGNED_AND_INVALID ? errors : undefined
    };
}

/**
 * Verify a message
 * @param  {Object}                      options input for openpgp.verify
 * @param  {openpgp.Key|openpgp.Key[]}   options.publicKeys keys to verify signatures
 * @param  {openpgp.cleartext.CleartextMessage|
 *          openpgp.message.Message}     options.message message object with signatures
 * @param  {openpgp.signature.Signature} [options.signature] detached signature
 * @param  {Date}                        [options.date] date to use for verification instead of the server time
 *
 * @returns {Promise<Object>}  Verification result in the form: {
 *     data: Uint8Array|string|ReadableStream|NodeStream - message data,
 *     verified: constants.VERIFICATION_STATUS - message verification status,
 *     signatures: openpgp.signature.Signature[] - message signatures,
 *     signatureTimestamp: Date|null - creation date of the first valid message signature, or null if all signatures are missing or invalid,
 *     errors: Error[]|undefined - verification errors if all signatures are invalid
 * }
 */
export function verifyMessage(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp
        .verify(options)
        .then((result) => handleVerificationResult(result))
        .then(({ data, verified, signatureTimestamp, signatures, errors }) => ({
            data,
            verified,
            signatureTimestamp,
            signatures,
            errors
        }))
        .catch((err) => {
            console.error(err);
            return Promise.reject(err);
        });
}

export async function splitMessage(message) {
    const msg = await getMessage(message);

    const keyFilter = (packet) => {
        return (
            packet.tag !== openpgp.enums.packet.publicKeyEncryptedSessionKey &&
            packet.tag !== openpgp.enums.packet.signature &&
            packet.tag !== openpgp.enums.packet.symEncryptedSessionKey &&
            packet.tag !== openpgp.enums.packet.compressed &&
            packet.tag !== openpgp.enums.packet.literal &&
            packet.tag !== openpgp.enums.packet.symmetricallyEncrypted &&
            packet.tag !== openpgp.enums.packet.symEncryptedIntegrityProtected &&
            packet.tag !== openpgp.enums.packet.symEncryptedAEADProtected
        );
    };

    const splitPackets = (packetList) => {
        return Promise.all(
            packetList.map((pack) => {
                const newList = new openpgp.packet.List();
                newList.push(pack);
                const data = newList.write(); // Uint8Array / String (ReadableStream)

                // readToEnd is async and accepts Uint8Array/String
                return openpgp.stream.readToEnd(data);
            })
        );
    };

    const asymmetric = await splitPackets(msg.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey));
    const signature = await splitPackets(msg.packets.filterByTag(openpgp.enums.packet.signature));
    const symmetric = await splitPackets(msg.packets.filterByTag(openpgp.enums.packet.symEncryptedSessionKey));
    const compressed = await splitPackets(msg.packets.filterByTag(openpgp.enums.packet.compressed));
    const literal = await splitPackets(msg.packets.filterByTag(openpgp.enums.packet.literal));
    const encrypted = await splitPackets(
        msg.packets.filterByTag(
            openpgp.enums.packet.symmetricallyEncrypted,
            openpgp.enums.packet.symEncryptedIntegrityProtected,
            openpgp.enums.packet.symEncryptedAEADProtected
        )
    );
    const other = await splitPackets(msg.packets.filter(keyFilter));

    return {
        asymmetric,
        signature,
        symmetric,
        compressed,
        literal,
        encrypted,
        other
    };
}

/**
 *  Prepare message body
 * @param {String} value
 * @return {Promise<String>}
 */
export async function armorBytes(value) {
    const bodyMessage = await getMessage(value);
    return openpgp.stream.readToEnd(bodyMessage.armor());
}
