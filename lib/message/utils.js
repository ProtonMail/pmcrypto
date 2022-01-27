/* eslint-disable no-prototype-builtins */
import { readToEnd } from '@openpgp/web-stream-tools';
import {
    createMessage,
    PacketList,
    verify,
    sign,
    enums,
    readCleartextMessage,
    Message,
    CleartextMessage,
    readMessage,
    Signature,
    readSignature
} from '../openpgp';
import { VERIFICATION_STATUS } from '../constants';
import { serverTime } from '../serverTime';

const { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } = VERIFICATION_STATUS;

/**
 * Remove trailing spaces and tabs from each line (separated by \n characters)
 */
 export const removeTrailingSpaces = (text) => {
    return text
        .split('\n')
        .map((line) => {
            let i = line.length - 1;
            for (; i >= 0 && (line[i] === ' ' || line[i] === '\t'); i--);
            return line.substr(0, i + 1);
        })
        .join('\n');
};

/**
 * Prepare message
 * @param {Object|Uint8Array|String} message
 * @return {Promise<Object>}
 */
export async function getMessage(message) {
    if (Message.prototype.isPrototypeOf(message)) {
        return message;
    }
    if (Uint8Array.prototype.isPrototypeOf(message)) {
        return readMessage({ binaryMessage: message });
    }
    return readMessage({ armoredMessage: message.trim() });
}

/**
 * Prepare signature
 * @param {String|Uint8Array|openpgp.signature.Signature} signature
 * @return {Promise<openpgp.signature.Signature>}
 */
export async function getSignature(signature) {
    if (Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    }
    if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return readSignature({ binarySignature: signature });
    }
    return readSignature({ armoredSignature: signature.trim() });
}

/**
 * Read a cleartext message from an armored message.
 * @param {String|openpgp.cleartext.CleartextMessage} message
 * @return {Promise<openpgp.cleartext.CleartextMessage>}
 */
export async function getCleartextMessage(message) {
    if (CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return readCleartextMessage({ cleartextMessage: message.trim() });
}

/**
 * Get a signed message from the given data.
 * Either `textData` or `binaryData` must be specified.
 * @param {Object} options - input for openpgp.sign
 * @param {String|ReadableStream<String>} textData - text data to sign
 * @param {Uint8Array|ReadableStream<Uint8Array>} binaryData - binary data to sign
 * @param {Boolean} stripTrailingSpaces - whether trailing spaces should be removed from `textData`
 * @returns Promise<{Message|Signature|String|ReadableStream<String>}> signed message object, signature object, or their corresponding armored data
 * @throws on signing error
 */
export async function signMessage({
    textData,
    binaryData,
    stripTrailingSpaces,
    date = serverTime(),
    armor = true,
    ...options
}) {
    const dataType = binaryData ? 'binary' : 'text';
    const data = binaryData || (stripTrailingSpaces ? removeTrailingSpaces(textData) : textData); // throw if streamed text and stripTrailingSpaces enabled
    const sanitizedOptions = {
        ...options,
        date,
        message: await createMessage({ [dataType]: data })
    }

    if (!options.format) {
        sanitizedOptions.format = armor ? 'armored' : 'object'; // TODO change, remove `armor` param?
    }

    return sign(sanitizedOptions).catch((err) => {
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

                // In the context of message verification, signatures can only hold a single
                // packet. Thus we do not need to iterate over the packets and find the one
                // that verified the message. We can just use the single packet in the
                // signature.
                const verifiedSigPacket = signature.packets[0];
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
        filename,
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
 * @param  {openpgp.Signature} options.signature - detached signature to verify
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
export async function verifyMessage({ textData, binaryData, stripTrailingSpaces, date = serverTime(), ...options }) {
    const dataType = binaryData ? 'binary' : 'text';
    const dataToVerify = binaryData || (stripTrailingSpaces ? removeTrailingSpaces(textData) : textData); // throw if streamed text and stripTrailingSpaces enabled
    const sanitizedOptions = {
        ...options,
        date,
        message: await createMessage({ [dataType]: dataToVerify })
    };

    return verify(sanitizedOptions)
        .then(handleVerificationResult)
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
            packet.constructor.tag !== enums.packet.publicKeyEncryptedSessionKey &&
            packet.constructor.tag !== enums.packet.signature &&
            packet.constructor.tag !== enums.packet.symEncryptedSessionKey &&
            packet.constructor.tag !== enums.packet.compressed &&
            packet.constructor.tag !== enums.packet.literal &&
            packet.constructor.tag !== enums.packet.symmetricallyEncrypted &&
            packet.constructor.tag !== enums.packet.symEncryptedIntegrityProtected &&
            packet.constructor.tag !== enums.packet.symEncryptedAEADProtected
        );
    };

    const splitPackets = (packetList) => {
        return Promise.all(
            packetList.map((pack) => {
                const newList = new PacketList();
                newList.push(pack);
                const data = newList.write(); // Uint8Array / String (ReadableStream)

                // readToEnd is async and accepts Uint8Array/String
                return readToEnd(data);
            })
        );
    };

    const asymmetric = await splitPackets(msg.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey));
    const signature = await splitPackets(msg.packets.filterByTag(enums.packet.signature));
    const symmetric = await splitPackets(msg.packets.filterByTag(enums.packet.symEncryptedSessionKey));
    const compressed = await splitPackets(msg.packets.filterByTag(enums.packet.compressed));
    const literal = await splitPackets(msg.packets.filterByTag(enums.packet.literal));
    const encrypted = await splitPackets(
        msg.packets.filterByTag(
            enums.packet.symmetricallyEncrypted,
            enums.packet.symEncryptedIntegrityProtected,
            enums.packet.symEncryptedAEADProtected
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
    return readToEnd(bodyMessage.armor());
}
