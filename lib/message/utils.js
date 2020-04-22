/* eslint-disable no-prototype-builtins */
import {
    sign,
    verify,
    message as messageModule,
    signature as signatureModule,
    cleartext,
    enums,
    packet,
    stream
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
    if (messageModule.Message.prototype.isPrototypeOf(message)) {
        return message;
    }
    if (Uint8Array.prototype.isPrototypeOf(message)) {
        return messageModule.read(message);
    }
    return messageModule.readArmored(message.trim());
}

/**
 * Prepare signature
 * @param {String|Uint8Array|openpgp.signature.Signature} signature
 * @return {Promise<openpgp.signature.Signature>}
 */
export async function getSignature(signature) {
    if (signatureModule.Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    }
    if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return signatureModule.read(signature);
    }
    return signatureModule.readArmored(signature.trim());
}

/**
 * Read a cleartext message from an armored message.
 * @param {String|openpgp.cleartext.CleartextMessage} message
 * @return {Promise<openpgp.cleartext.CleartextMessage>}
 */
export async function getCleartextMessage(message) {
    if (cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return cleartext.readArmored(message.trim());
}

/**
 * Create a cleartext message from a text.
 * @param {String|openpgp.cleartext.CleartextMessage} message
 * @return {openpgp.cleartext.CleartextMessage}
 */
export function createCleartextMessage(message) {
    if (cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    }
    return cleartext.fromText(message);
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

export async function handleVerificationResult({ data, filename = 'msg.txt', signatures: sigs }, publicKeys, date) {
    let verified = NOT_SIGNED;
    const signatures = [];
    if (sigs && sigs.length) {
        verified = SIGNED_AND_INVALID;
        for (let i = 0; i < sigs.length; i++) {
            if (sigs[i].valid) {
                verified = SIGNED_AND_VALID;
            }
            signatures.push(sigs[i].signature);
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

        return verificationResults.reduceRight(
            (acc, result) => {
                if (acc.verified === SIGNED_AND_INVALID && result.error) {
                    acc.errors = acc.errors.concat(result.error);
                }
                return acc;
            },
            {
                data,
                verified,
                filename,
                signatures,
                errors: []
            }
        );
    }

    return {
        data,
        verified,
        filename,
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
            packet.tag !== enums.packet.compressed &&
            packet.tag !== enums.packet.literal &&
            packet.tag !== enums.packet.symmetricallyEncrypted &&
            packet.tag !== enums.packet.symEncryptedIntegrityProtected &&
            packet.tag !== enums.packet.symEncryptedAEADProtected
        );
    };

    const splitPackets = (packetList) => {
        return Promise.all(
            packetList.map((pack) => {
                const newList = new packet.List();
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
    return stream.readToEnd(bodyMessage.armor());
}
