import { readToEnd } from '@openpgp/web-stream-tools';
import {
    PacketList,
    enums,
    unarmor,
    readMessage,
    BasePacket as OpenPGPPacket,
    AnyPacket
} from '../openpgp';
import type { OpenPGPMessage } from '../pmcrypto';

export async function splitMessage(message: OpenPGPMessage) {
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

    const asymmetric = await splitPackets(message.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey));
    const signature = await splitPackets(message.packets.filterByTag(enums.packet.signature));
    const symmetric = await splitPackets(message.packets.filterByTag(enums.packet.symEncryptedSessionKey));
    const compressed = await splitPackets(message.packets.filterByTag(enums.packet.compressedData));
    const literal = await splitPackets(message.packets.filterByTag(enums.packet.literalData));
    const encrypted = await splitPackets(
        message.packets.filterByTag(
            enums.packet.symmetricallyEncryptedData,
            enums.packet.symEncryptedIntegrityProtectedData,
            enums.packet.aeadEncryptedData
        )
    );
    const other = await splitPackets(message.packets.filter(keyFilter));

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
 * @returns armored message
 */
export async function armorBytes(binaryMessage: Uint8Array) {
    const bodyMessage = await readMessage({ binaryMessage });
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
