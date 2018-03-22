const { VERIFICATION_STATUS: { NOT_SIGNED, SIGNED_AND_VALID, SIGNED_AND_INVALID } } = require('../constants.js');
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

async function verifyExpirationTime({ keyid }, publicKeys, verificationTime) {
    if (!verificationTime) {
        return true;
    }
    const publickey = publicKeys.find((pk) => pk.primaryKey.keyid.bytes === keyid.bytes);
    if (!publickey) {
        return false;
    }
    const expirationTime = await publickey.getExpirationTime();
    return expirationTime === null || +expirationTime > verificationTime * 1000;
}

function verifyMessage(options) {
    const { verificationTime = false, publicKeys = [], isInline = false } = options;
    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    return openpgp.verify(options)
    .then(({ data, signatures: sigs }) => {
        let verified = NOT_SIGNED;
        let signatures = [];
        if (sigs && sigs.length) {
            verified = SIGNED_AND_INVALID;
            for(let i = 0; i < sigs.length; i++) {
                sigs[i].valid = sigs[i].valid && verifyExpirationTime(sigs[i], publicKeys, verificationTime);

                if (sigs[i].valid) {
                    verified = SIGNED_AND_VALID;
                }
                if (sigs[i].valid || (!options.publicKeys || !options.publicKeys.length)) {
                    signatures.push(sigs[i].signature);
                }
            }
        }
        if (verified === SIGNED_AND_INVALID && isInline && options.publicKeys && options.publicKeys.length) {
            return verifyInlineMessage(sigs.map(({ signature }) => signature), publicKeys, arrayToBinaryString(data), options.date);
        }
        return {data, verified, signatures};
    })
    .catch(function(err) {
        console.error(err);
        return Promise.reject(err);
    });
}

function verifySignatures(signatures, publicKeys, cleartext, date) {
    return Promise.all(signatures.map((signature) =>
        verifyMessage({
            message: createMessage(cleartext),
            signature,
            date,
            publicKeys
        }).then(({ data, verified, signatures }) => ({ data: arrayToBinaryString(data), verified, signatures }))
    )).then((results) => {
        const [verifiedResult = false] = results.filter(({ verified }) => verified === SIGNED_AND_VALID);
        return verifiedResult || { data: cleartext, verified: SIGNED_AND_INVALID, signatures: []};
    });
}

function verifyInlineMessage(signatures, publicKeys, cleartext, date) {
    return verifySignatures(signatures, publicKeys, cleartext, date).then(({ data, verified, signatures: sigs }) => {
        if (verified !== SIGNED_AND_INVALID) {
            return { data, verified, signatures: sigs };
        }
        return verifySignatures(signatures, publicKeys, cleartext.replace(/[\xa0]/g, ' '), date);
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
    verifyInlineMessage,
    splitMessage,
    getMessage,
    verifyExpirationTime,
    getSignature,
    getCleartextMessage,
    createMessage
};
