/* eslint-disable no-prototype-builtins */
import { openpgp } from '../openpgp';
import { VERIFICATION_STATUS, SIGNATURE_TYPES } from '../constants';
import { arrayToBinaryString } from '../utils';
import { serverTime } from '../serverTime';

const { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } = VERIFICATION_STATUS;
const { CANONICAL_TEXT } = SIGNATURE_TYPES;

/**
 * Prepare message
 * @param {Promise<Object>} message
 */
export async function getMessage(message) {
    if (openpgp.message.Message.prototype.isPrototypeOf(message)) {
        return message;
    } else if (Uint8Array.prototype.isPrototypeOf(message)) {
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
    } else if (Uint8Array.prototype.isPrototypeOf(signature)) {
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
            if (sigs[i].valid || !publicKeys.length) {
                signatures.push(sigs[i].signature);
            }
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
            return openpgp
                .verify({
                    message: textMessage,
                    publicKeys,
                    signature,
                    date
                })
                .then(({ data, signatures }) => ({
                    data,
                    signatures: signatures.map(({ signature }) => signature),
                    verified: signatures[0].valid ? SIGNED_AND_VALID : SIGNED_AND_INVALID
                }));
        });
        const verificationResults = await Promise.all(verificationPromises);

        return verificationResults.reduceRight(
            (acc, result) => {
                if (acc.verified === SIGNED_AND_VALID) {
                    acc.signatures = acc.signatures.concat(result.signature);
                }
                return acc;
            },
            {
                data,
                verified,
                filename,
                signatures
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

    return openpgp
        .verify(options)
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
