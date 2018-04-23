const { VERIFICATION_STATUS: { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID }, SIGNATURE_TYPES: { CANONICAL_TEXT } } = require('../constants.js');
const { serverTime, arrayToBinaryString } = require('../utils');

function getMessage(message) {

    if (openpgp.message.Message.prototype.isPrototypeOf(message)) {
        return message;
    } else if (Uint8Array.prototype.isPrototypeOf(message)) {
        return openpgp.message.read(message);
    } else {
        return openpgp.message.readArmored(message.trim());
    }
}

function getSignature(signature) {

    if (openpgp.signature.Signature.prototype.isPrototypeOf(signature)) {
        return signature;
    } else if (Uint8Array.prototype.isPrototypeOf(signature)) {
        return openpgp.signature.read(signature);
    } else {
        return openpgp.signature.readArmored(signature.trim());
    }
}

function getCleartextMessage(message) {

    if (openpgp.cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
        return message;
    } else {
        return new openpgp.cleartext.CleartextMessage(message);
    }
}

function createMessage(source) {

    if (Uint8Array.prototype.isPrototypeOf(source)) {
        return openpgp.message.fromBinary(source);
    } else {
        return openpgp.message.fromText(source);
    }
}

function signMessage(options) {
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp.sign(options)
    .catch((err) => {
        console.error(err);
        return Promise.reject(err);
    });
}

function isCanonicalTextSignature({ packets }) {
    return Object.values(packets).some(({ signatureType = false }) => signatureType === CANONICAL_TEXT)
}

async function handleVerificationResult({ data, filename = 'msg.txt', signatures: sigs }, publicKeys, date) {
    let verified = NOT_SIGNED;
    let signatures = [];
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
            .filter(({valid}) => valid !== null)
            .map(({signature}) => signature)
            .filter(isCanonicalTextSignature);
        const text = typeof data === 'string' ? data : arrayToBinaryString(data);
        const textMessage = createMessage(text.replace(/[\xa0]/g, ' '));

        const verificationPromises = verifiableSigs.map((signature) => openpgp.verify({
                message: textMessage,
                publicKeys,
                signature,
                date
            }).then(({ data, signatures }) => ({
                data,
                signatures: signatures.map(({ signature }) => signature),
                verified: signatures[0].valid ? SIGNED_AND_VALID : SIGNED_AND_INVALID
            }))
        );
        const verificationResults = await Promise.all(verificationPromises);

        return verificationResults
            .filter(({verified}) => verified === SIGNED_AND_VALID)
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

function verifyMessage(options) {
    const { publicKeys = [] } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp.verify(options)
        .then((result) => handleVerificationResult(result, publicKeys, options.date))
        .then(({ data, verified, signatures }) => ({ data, verified, signatures }))
        .catch(function(err) {
            console.error(err);
            return Promise.reject(err);
        });
}

function splitMessage(message) {

    const msg = getMessage(message);

    const keyFilter = (packet) => {
        return packet.tag !== openpgp.enums.packet.publicKeyEncryptedSessionKey
            && packet.tag !== openpgp.enums.packet.signature
            && packet.tag !== openpgp.enums.packet.symEncryptedSessionKey
            && packet.tag !== openpgp.enums.packet.compressed
            && packet.tag !== openpgp.enums.packet.literal
            && packet.tag !== openpgp.enums.packet.symmetricallyEncrypted
            && packet.tag !== openpgp.enums.packet.symEncryptedIntegrityProtected
            && packet.tag !== openpgp.enums.packet.symEncryptedAEADProtected;
    };

    const splitPackets = (packetList) => {
        const packets = [];
        for(let i = 0; i < packetList.length; i++) {
            let newList = new openpgp.packet.List();
            newList.push(packetList[i]);
            packets.push(newList.write());
        }
        return packets;
    };

    const asymmetric = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey));
    const signature = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.signature));
    const symmetric = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.symEncryptedSessionKey));
    const compressed = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.compressed));
    const literal = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.literal));
    const encrypted = splitPackets(msg.packets.filterByTag(openpgp.enums.packet.symmetricallyEncrypted, openpgp.enums.packet.symEncryptedIntegrityProtected, openpgp.enums.packet.symEncryptedAEADProtected));
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

module.exports = {
    signMessage,
    verifyMessage,
    splitMessage,
    getMessage,
    getSignature,
    getCleartextMessage,
    createMessage,
    handleVerificationResult
};
