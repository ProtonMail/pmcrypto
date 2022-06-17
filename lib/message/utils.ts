import { readToEnd } from '@openpgp/web-stream-tools';
import {
    PacketList,
    enums,
    readCleartextMessage,
    Message,
    CleartextMessage,
    readMessage,
    Signature,
    readSignature,
    unarmor,
    BasePacket as OpenPGPPacket,
    AnyPacket
} from '../openpgp';
import type { Data, OpenPGPMessage, OpenPGPSignature } from '../pmcrypto';

/**
 * Remove trailing spaces and tabs from each line (separated by \n characters)
 */
export const removeTrailingSpaces = (text: string) => {
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
 * @param message - serialized or parsed message object
 * @return OpenPGP message object
 */
export async function getMessage(message: OpenPGPMessage | Data) {
    if (message instanceof Message) {
        return message;
    }
    if (message instanceof Uint8Array) {
        return readMessage({ binaryMessage: message });
    }
    return readMessage({ armoredMessage: message.trim() });
}

/**
 * Prepare signature
 * @param signature - serialized or parsed signature object
 * @return OpenPGP signature object
 */
export async function getSignature(signature: OpenPGPSignature | Data) {
    if (signature instanceof Signature) {
        return signature;
    }
    if (signature instanceof Uint8Array) {
        return readSignature({ binarySignature: signature });
    }
    return readSignature({ armoredSignature: signature.trim() });
}

/**
 * Read a cleartext message from an armored message.
 * @param {String|openpgp.cleartext.CleartextMessage} message
 * @return {Promise<openpgp.cleartext.CleartextMessage>}
 */
export async function getCleartextMessage(message: CleartextMessage | string) {
    if (message instanceof CleartextMessage) {
        return message;
    }
    return readCleartextMessage({ cleartextMessage: message.trim() });
}

export async function splitMessage(message: OpenPGPMessage | Data) {
    const msg = await getMessage(message);

    const keyFilter = (packet: AnyPacket) => {
        const packetTag = (packet.constructor as typeof OpenPGPPacket).tag;
        return (
            packetTag !== enums.packet.publicKeyEncryptedSessionKey &&
            packetTag !== enums.packet.signature &&
            packetTag !== enums.packet.symEncryptedSessionKey &&
            packetTag !== enums.packet.compressedData &&
            packetTag !== enums.packet.literalData &&
            packetTag !== enums.packet.symmetricallyEncryptedData &&
            packetTag !== enums.packet.symEncryptedIntegrityProtectedData &&
            packetTag !== enums.packet.aeadEncryptedData
        );
    };

    const splitPackets = (packetList: AnyPacket[]) => {
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
    const compressed = await splitPackets(msg.packets.filterByTag(enums.packet.compressedData));
    const literal = await splitPackets(msg.packets.filterByTag(enums.packet.literalData));
    const encrypted = await splitPackets(
        msg.packets.filterByTag(
            enums.packet.symmetricallyEncryptedData,
            enums.packet.symEncryptedIntegrityProtectedData,
            enums.packet.aeadEncryptedData
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
 * Enarmor an OpenPGP message
 * @param value - binary message
 * @returns armored message
 */
export async function armorBytes(value: Uint8Array) {
    const bodyMessage = await getMessage(value);
    return readToEnd(bodyMessage.armor());
}

/**
 * Dearmor an OpenPGP message
 * @return binary message
 */
export const stripArmor = async (input: string) => {
    const { data } = await unarmor(input);
    const bytes = await readToEnd(data);
    return bytes;
};
