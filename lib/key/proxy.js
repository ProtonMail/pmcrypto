import elliptic from 'elliptic';
import { openpgp } from '../openpgp';

/**
 * Convert the ciphertext to allow the final recipient to decrypt it
 * @param   {Message} ciphertext              encrypted message to forward
 * @param   {Object}  proxyFactor             proxy factor for message transformation
 * @param   {String}  originalSubKeyId        ID of encryption subKey of original recipient
 * @param   {String}  finalRecipientSubKeyId  ID of encryption subKey of final recipient
 * @returns {Promise<Message>}                transformed encrypted message
 * @async
 */
export async function proxyTransform(ciphertext, proxyFactor, originalSubKeyId, finalRecipientSubKeyId) {
    // eslint-disable-next-line new-cap
    const curve = new elliptic.ec('curve25519');

    ciphertext.packets.forEach((packet) => {
        if (
            packet.tag === openpgp.enums.packet.publicKeyEncryptedSessionKey &&
            packet.publicKeyId.equals(originalSubKeyId)
        ) {
            const bG = packet.encrypted[0].data;
            const point = curve.curve.decodePoint(bG.subarray(1).reverse());
            const bkG = new Uint8Array(
                point
                    .mul(proxyFactor)
                    .getX()
                    .toArray('be', 32)
            );
            const encoded = openpgp.util.concatUint8Array([new Uint8Array([0x40]), bkG.reverse()]);
            packet.encrypted[0].data = encoded;
            packet.publicKeyId = finalRecipientSubKeyId;
        }
    });

    return ciphertext;
}
