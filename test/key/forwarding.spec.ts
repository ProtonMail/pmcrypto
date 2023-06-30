import { expect } from 'chai';
import { ec as EllipticCurve } from 'elliptic';
import BN from 'bn.js';

import { enums, KeyID, PacketList } from '../../lib/openpgp';
import { generateKey, generateForwardingMaterial, encryptMessage, decryptMessage, readMessage, readKey } from '../../lib';
import { computeProxyParameter } from '../../lib/key/forwarding';
import { hexStringToArray, concatArrays } from '../../lib/utils';

// this is only intended for testing purposes, due to BN.js dependency, which is huge
async function testProxyTransform(
    armoredCiphertext: string,
    proxyParameter: Uint8Array,
    originalSubkeyID: KeyID,
    finalRecipientSubkeyID: KeyID
) {
    const curve = new EllipticCurve('curve25519');

    const ciphertext = await readMessage({ armoredMessage: armoredCiphertext });
    for (
        // missing PublicKeyEncryptedSessionKeyPacket field declarations
        const packet of ciphertext.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey) as PacketList<any>
    ) {
        if (packet.publicKeyID.equals(originalSubkeyID)) {
            const bG = packet.encrypted.V;
            const point = curve.curve.decodePoint(bG.subarray(1).reverse());
            const bkG = new Uint8Array(
                point
                    .mul(new BN(proxyParameter, 'le'))
                    .getX()
                    .toArray('le', 32)
            );
            const encoded = concatArrays([new Uint8Array([0x40]), bkG]);
            packet.encrypted.V = encoded;
            packet.publicKeyID = finalRecipientSubkeyID;
        }
    }

    return ciphertext.armor();
}

describe('forwarding', () => {
    it('proxy parameter computation is correct', async () => {
        const secretBob = hexStringToArray('5989216365053dcf9e35a04b2a1fc19b83328426be6bb7d0a2ae78105e2e3188');
        const secretCharlie = hexStringToArray('684da6225bcd44d880168fc5bec7d2f746217f014c8019005f144cc148f16a00');

        const expectedProxyFactor = hexStringToArray('e89786987c3a3ec761a679bc372cd11a425eda72bd5265d78ad0f5f32ee64f02');
        const actualProxyFactor = await computeProxyParameter(secretBob, secretCharlie);

        expect(actualProxyFactor).to.deep.equal(expectedProxyFactor);
    });

    it('generate forwarding key', async () => {
        const { privateKey: bobKey } = await generateKey({ userIDs: [{ name: 'Bob', email: 'info@bob.com' }], format: 'object' });

        const { forwardeeKey } = await generateForwardingMaterial(bobKey, [{ name: 'Charlie', email: 'info@charlie.com' }]);
        const charlieKey = await readKey({ armoredKey: forwardeeKey.armor() }); // ensure key is correctly serialized and parsed

        // Check subkey differences
        const bobSubkey = await bobKey.getEncryptionKey();
        const charlieSubkey = await charlieKey.getEncryptionKey();
        // @ts-ignore oid field not defined
        expect(charlieSubkey.keyPacket.publicParams.oid).to.deep.equal(bobSubkey.keyPacket.publicParams.oid);
        // Check KDF params
        // @ts-ignore kdfParams field not defined
        expect(charlieSubkey.keyPacket.publicParams.kdfParams.version).to.equal(0xFF);
        expect(
            // @ts-ignore kdfParams field not defined
            charlieSubkey.keyPacket.publicParams.kdfParams.replacementFingerprint
        ).to.deep.equal(bobSubkey.keyPacket.getFingerprintBytes());
    });

    it('decryption with forwarding - v4 key', async () => {
        const { privateKey: bobKey } = await generateKey({
            userIDs: [{ name: 'Bob', email: 'info@bob.com' }], curve: 'curve25519', format: 'object'
        });
        const plaintext = 'Hello Bob, hello world';

        const { proxyParameter, forwardeeKey: charlieKey } = await generateForwardingMaterial(bobKey, [
            { name: 'Charlie', email: 'info@charlie.com', comment: 'Forwarded from Bob' }
        ]);

        const { message: originalCiphertext } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKey
        });

        const transformedCiphertext = await testProxyTransform(
            originalCiphertext,
            proxyParameter,
            bobKey.subkeys[0].getKeyID(),
            charlieKey.subkeys[0].getKeyID()
        );
        const { data: decryptedData } = await decryptMessage({
            message: await readMessage({ armoredMessage: transformedCiphertext }),
            decryptionKeys: charlieKey
        });
        expect(decryptedData).to.equal(plaintext);

        // Charlie cannot decrypt the original ciphertext
        const decryptionTrialPromise = decryptMessage({
            message: await readMessage({ armoredMessage: originalCiphertext }),
            decryptionKeys: charlieKey
        });
        expect(decryptionTrialPromise).to.be.rejectedWith(/Session key decryption failed/);
    });
});
