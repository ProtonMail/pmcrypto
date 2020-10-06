/* eslint-disable no-prototype-builtins */
import {
    sign,
    verify,
    Message as messageModule,
    readMessage,
    readArmoredMessage,
    Signature as signatureModule,
    readSignature,
    readArmoredSignature,
    CleartextMessage,
    readArmoredCleartextMessage,
    enums,
    stream,
    PacketList
} from 'openpgp';
import { VERIFICATION_STATUS, SIGNATURE_TYPES } from '../constants';
import { arrayToBinaryString } from '../utils';
import { serverTime } from '../serverTime';

const { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } = VERIFICATION_STATUS;
const { CANONICAL_TEXT } = SIGNATURE_TYPES;

/**
 * Prepare message
 * @param {Object|Uint8Array|String} message
 * @return {Promise<Object>}
 */
export async function getMessage(message) {
    if (messageModule.prototype.isPrototypeOf(message)) {
        return message;
    }
    if (Uint8Array.prototype.isPrototypeOf(message)) {
        return readMessage(message);
    }
    return readArmoredMessage(message.trim());
}

/**
 * Prepare signature
 * @param {String|Uint8Array|openpgp.signature.Signature} signature
 * @return {Promise<openpgp.signature.Signature>}
 */
export async function getSignature(signature) {
    if (signatureModule.prototype.isPrototypeOf(signature)) {
        return signature;
    }
    if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return readSignature(signature);
    }
    return readArmoredSignature(signature.trim());
}

/**
 * Read a cleartext message from an armored message.
 * @param {String|openpgp.CleartextMessage} message
 * @return {Promise<openpgp.CleartextMessage>}
 */
export async function getCleartextMessage(message) {
    if (CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return readArmoredCleartextMessage(message.trim());
}

/**
 * Create a cleartext message from a text.
 * @param {String|openpgp.CleartextMessage} message
 * @return {openpgp.CleartextMessage}
 */
export function createCleartextMessage(message) {
    if (CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return CleartextMessage.fromText(message);
}

export function createMessage(source, filename, date = serverTime()) {
    if (Uint8Array.prototype.isPrototypeOf(source)) {
        return messageModule.fromBinary(source, filename, date);
    }
    return messageModule.fromText(source, filename, date);
}

export function signMessage(options) {
    if (typeof options.data === 'string') {
        options.message = createCleartextMessage(options.data);
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = createMessage(options.data);
    }

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return sign(options).catch((err) => {
        console.error(err);
        return Promise.reject(err);
    });
}

function isCanonicalTextSignature({ packets }) {
    return Object.values(packets).some(({ signatureType = false }) => signatureType === CANONICAL_TEXT);
}

export async function handleVerificationResult({ data, signatures: sigs }, publicKeys, date) {
    let verified = NOT_SIGNED;
    const signatures = [];
    if (sigs && sigs.length) {
        verified = SIGNED_AND_INVALID;
        for (let i = 0; i < sigs.length; i++) {
            if (
                await sigs[i].verified.catch(() => {
                    return false;
                })
            ) {
                verified = SIGNED_AND_VALID;
            }
            signatures.push(await sigs[i].signature);
        }
    }

    if (verified === SIGNED_AND_INVALID) {
        // enter extended text mode: some mail clients change spaces into nonbreaking spaces, we'll try to verify by normalizing this too.
        const verifiableSigs = sigs
            .filter(({ valid }) => valid !== null)
            .map(({ signature }) => signature)
            .filter(isCanonicalTextSignature);
        const text = typeof data === 'string' ? data : arrayToBinaryString(data);
        const textMessage = createMessage(text.replace(/[\xa0]/g, ' '));

        const verificationPromises = verifiableSigs.map((signature) => {
            return verify({
                message: textMessage,
                publicKeys,
                signature,
                date
            }).then(({ data, signatures }) => ({
                data,
                // the variable signatures contain a single element here
                signatures: signatures[0].signature,
                verified: signatures[0].valid ? SIGNED_AND_VALID : SIGNED_AND_INVALID,
                error: signatures[0].error
            }));
        });
        const verificationResults = await Promise.all(verificationPromises);

        return verificationResults.reduceRight((acc, result) => {
            if (acc.verified === SIGNED_AND_INVALID && result.error) {
                acc.errors = acc.errors.concat(result.error);
            }
            return acc;
        });
    }

    return {
        data,
        verified,
        signatures
    };
}

export function verifyMessage(options) {
    const { publicKeys = [] } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return verify(options)
        .then((result) => handleVerificationResult(result, publicKeys, options.date))
        .then(({ data, verified, signatures }) => ({ data, verified, signatures }))
        .catch((err) => {
            console.error(err);
            return Promise.reject(err);
        });
}

export async function splitMessage(message) {
    const msg = await getMessage(message);

    const keyFilter = (packet) => {
        return (
            packet.tag !== enums.packet.publicKeyEncryptedSessionKey &&
            packet.tag !== enums.packet.signature &&
            packet.tag !== enums.packet.symEncryptedSessionKey &&
            packet.tag !== enums.packet.compressedData &&
            packet.tag !== enums.packet.literalData &&
            packet.tag !== enums.packet.symmetricallyEncryptedData &&
            packet.tag !== enums.packet.symEncryptedIntegrityProtectedData &&
            packet.tag !== enums.packet.symEncryptedAEADProtectedData
        );
    };

    const splitPackets = (packetList) => {
        return Promise.all(
            packetList.map((pack) => {
                const newList = new PacketList();
                newList.push(pack);
                const data = newList.write(); // Uint8Array / String (ReadableStream)

                // readToEnd is async and accepts Uint8Array/String
                return stream.readToEnd(data);
            })
        );
    };

    const asymmetric = await splitPackets(msg.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey));
    const signature = await splitPackets(msg.packets.filterByTag(enums.packet.signature));
    const symmetric = await splitPackets(msg.packets.filterByTag(enums.packet.symEncryptedSessionKey));
    const compressed = await splitPackets(msg.packets.filterByTag(enums.packet.compressedData));
    const literal = await splitPackets(msg.packets.filterByTag(enums.packet.literalData));
    const encrypted = await splitPackets(
        msg.packets.filterByTag(
            enums.packet.symmetricallyEncryptedData,
            enums.packet.symEncryptedIntegrityProtectedData,
            enums.packet.symEncryptedAEADProtectedData
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
    return stream.readToEnd(bodyMessage.armor());
}
