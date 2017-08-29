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

function signMessage(options) {

    return openpgp.sign(options)
    .catch((err) => {
        console.log(err);
        return Promise.reject(new Error('Message signing failed'));
    });
}

function verifyMessage(options) {

    return openpgp.verify(options)
    .catch(function(err) {
        console.log(err);
        return Promise.reject(new Error('Message verification failed'));
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
    getSignature
};