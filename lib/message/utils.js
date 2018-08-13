/* eslint-disable no-prototype-builtins */
import { VERIFICATION_STATUS, SIGNATURE_TYPES } from '../constants';
import { serverTime, arrayToBinaryString } from '../utils';
import openpgpjs from '../openpgp';

const { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } = VERIFICATION_STATUS;
const { CANONICAL_TEXT } = SIGNATURE_TYPES;

export function getMessage(message) {

    if (openpgpjs.message.Message.prototype.isPrototypeOf(message)) {
        return message;
    } else if (Uint8Array.prototype.isPrototypeOf(message)) {
        return openpgpjs.message.read(message);
    } else {
        return openpgpjs.message.readArmored(message.trim());
    }
}

export function getSignature(signature) {

    if (openpgpjs.signature.Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    } else if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return openpgpjs.signature.read(signature);
    }
    return openpgpjs.signature.readArmored(signature.trim());
}

export function getCleartextMessage(message) {

    if (openpgpjs.cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    } else {
        return new openpgpjs.cleartext.CleartextMessage(message);
    }
}

export function createMessage(source) {

    if (Uint8Array.prototype.isPrototypeOf(source)) {
        return openpgpjs.message.fromBinary(source);
    } else {
        return openpgpjs.message.fromText(source);
    }
}

export function signMessage(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgpjs.sign(options)
        .catch((err) => {
            console.error(err);
            return Promise.reject(err);
        });
}

function isCanonicalTextSignature({ packets }) {
    return Object.values(packets).some(({ signatureType = false }) => signatureType === CANONICAL_TEXT)
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
            if (sigs[i].valid || (!publicKeys.length)) {
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

        const verificationPromises = verifiableSigs.map((signature) => openpgpjs.verify({
            message: textMessage,
            publicKeys,
            signature,
            date
        }).then(({ data, signatures }) => ({
            data,
            signatures: signatures.map(({ signature }) => signature),
            verified: signatures[0].valid ? SIGNED_AND_VALID : SIGNED_AND_INVALID
        })));
        const verificationResults = await Promise.all(verificationPromises);

        return verificationResults
            .filter(({ verified }) => verified === SIGNED_AND_VALID)
            .reduceRight((acc, result) => {
                if (acc.verified !== SIGNED_AND_VALID) {
                    acc.verified = result.verified;
                    acc.data = arrayToBinaryString(result.data);
                }
                acc.signatures = acc.signatures.concat(result.signature);
                return acc;
            }, { data, verified, filename, signatures });
    }

    return { data, verified, filename, signatures };
}

export function verifyMessage(options) {
    const { publicKeys = [] } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgpjs.verify(options)
        .then((result) => handleVerificationResult(result, publicKeys, options.date))
        .then(({ data, verified, signatures }) => ({ data, verified, signatures }))
        .catch((err) => {
            console.error(err);
            return Promise.reject(err);
        });
}

export function splitMessage(message) {

    const msg = getMessage(message);

    const keyFilter = (packet) => {
        return packet.tag !== openpgpjs.enums.packet.publicKeyEncryptedSessionKey
            && packet.tag !== openpgpjs.enums.packet.signature
            && packet.tag !== openpgpjs.enums.packet.symEncryptedSessionKey
            && packet.tag !== openpgpjs.enums.packet.compressed
            && packet.tag !== openpgpjs.enums.packet.literal
            && packet.tag !== openpgpjs.enums.packet.symmetricallyEncrypted
            && packet.tag !== openpgpjs.enums.packet.symEncryptedIntegrityProtected
            && packet.tag !== openpgpjs.enums.packet.symEncryptedAEADProtected;
    };

    const splitPackets = (packetList) => {
        const packets = [];
        for (let i = 0; i < packetList.length; i++) {
            const newList = new openpgpjs.packet.List();
            newList.push(packetList[i]);
            packets.push(newList.write());
        }
        return packets;
    };

    const asymmetric = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.publicKeyEncryptedSessionKey));
    const signature = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.signature));
    const symmetric = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.symEncryptedSessionKey));
    const compressed = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.compressed));
    const literal = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.literal));
    const encrypted = splitPackets(msg.packets.filterByTag(openpgpjs.enums.packet.symmetricallyEncrypted, openpgpjs.enums.packet.symEncryptedIntegrityProtected, openpgpjs.enums.packet.symEncryptedAEADProtected));
    const other = splitPackets(msg.packets.filter(keyFilter));

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
