import { expect } from 'chai';
import { ec as EllipticCurve } from 'elliptic';
import BN from 'bn.js';

import { enums, KeyID, PacketList } from '../../lib/openpgp';
import { generateKey, generateForwardingMaterial, doesKeySupportForwarding, encryptMessage, decryptMessage, readMessage, readKey, readPrivateKey } from '../../lib';
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

    it('generate forwarding key - should throw for P256 encryption key', async () => {
        const keyWithP256Subkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEZNI7SRMIKoZIzj0DAQcCAwRNbEFVQ7/5dkZsMEObzf2bL6bYLg7UmbOL
nC8LG9BWIfEmTH3QNOO2IuJDRyF/WmqpoNXQBuO7Emophg+23x1WAAD+JRQA
cUMAXKtqmey7d06r7EHIYyE/dgZeGo/z0WKmmjcO5M0OPHRlc3RAdGVzdC5p
dD7CiQQQEwgAOwWCZNI7SQMLCQcJkLi5pXUe27CfAxUICgIWAAIZAQKbAwIe
ARYhBEJtG+YOG/wgLGeeOri5pXUe27CfAADxkAEA4dh2u60jIlRo5yMwSBeb
nDEuRrt4M1XNs78OgDkHv0QBALrQuKGEP7UVo5O6Vr0ah91O5VAcC9XxwjtY
xl1CersLx3sEZNI7SRIIKoZIzj0DAQcCAwQTk1ESj08ix1DHXGW4ZQ5KiQNi
KL3z6+KiYnjEDNjsPtH4o0FHS6d5zUmEXZ1xqbGcOmOKZ8YgKyNklYu3T5g1
AwEIBwABAKdySgrgktTT86zgFJRkxpPkNDhMRFpBj9APRJZE1NhlEIPCeAQY
EwgAKgWCZNI7SQmQuLmldR7bsJ8CmwwWIQRCbRvmDhv8ICxnnjq4uaV1Htuw
nwAAwa4BAPslluPut3qHU2h7PB+D93ttxCn/AhSgOc5lUOafZt2VAP91FuPa
8ziVOrUmQTj0eOBjfW0XYIlm7JTERrRlh5S8R8ddBGTSO0kSCisGAQQBl1UB
BQEBB0CrsfLaOT7JAcwc2vg36SSJ6YCXODfvudM9INHNA3kxcQMBCAcAAP9h
0r01q6Jz/KvfNkJXzkvfaAfXOe6GfrFs10QvTvjpwBL4wngEGBMIACoFgmTS
O0kJkLi5pXUe27CfApsMFiEEQm0b5g4b/CAsZ546uLmldR7bsJ8AAGnuAQCF
lAWga4MJBiFLbBiYD7248zu+xmvUAWBU7f/dkHenYAD+K8UCcwQrqeDhCl0q
z5FbOJXSHsoez1SZ7GKgoxC+X0w=
-----END PGP PRIVATE KEY BLOCK-----` });

        await expect(
            generateForwardingMaterial(keyWithP256Subkey, [{ name: 'Charlie', email: 'info@charlie.com' }])
        ).to.be.rejectedWith(/unsuitable for forwarding/);
    });

    it('decryption with forwarding - v4 key', async () => {
        const { privateKey: bobKey } = await generateKey({
            userIDs: [{ name: 'Bob', email: 'info@bob.com' }], curve: 'curve25519', format: 'object'
        });
        const plaintext = 'Hello Bob, hello world';

        const { proxyParameters, forwardeeKey: charlieKey } = await generateForwardingMaterial(bobKey, [
            { name: 'Charlie', email: 'info@charlie.com', comment: 'Forwarded from Bob' }
        ]);
        expect(proxyParameters).to.have.length(1);

        const { message: originalCiphertext } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKey
        });

        const transformedCiphertext = await testProxyTransform(
            originalCiphertext,
            proxyParameters[0],
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

    it('decryption with forwarding - v4 key with multiple subkeys', async () => {
        const { privateKey: bobKey } = await generateKey({
            curve: 'curve25519',
            userIDs: [{ name: 'Bob', email: 'info@bob.com' }],
            subkeys: [{}, { sign: true }, {}], // ensure that signing subkey creates no issues
            format: 'object'
        });
        const plaintext = 'Hello Bob, hello world';

        const { proxyParameters, forwardeeKey: charlieKey } = await generateForwardingMaterial(bobKey, [
            { name: 'Charlie', email: 'info@charlie.com', comment: 'Forwarded from Bob' }
        ]);
        expect(proxyParameters).to.have.length(2);

        // test first encryption subkey
        const { message: originalCiphertext1 } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKey
        });
        const transformedCiphertext1 = await testProxyTransform(
            originalCiphertext1,
            proxyParameters[0],
            bobKey.subkeys[0].getKeyID(),
            charlieKey.subkeys[0].getKeyID()
        );
        const { data: decryptedData1 } = await decryptMessage({
            message: await readMessage({ armoredMessage: transformedCiphertext1 }),
            decryptionKeys: charlieKey
        });
        expect(decryptedData1).to.equal(plaintext);

        // test second encryption subkey
        // @ts-ignore missing `clone` definition
        const bobKeySecondEncryptionKey = bobKey.clone();
        bobKeySecondEncryptionKey.subkeys = [bobKey.subkeys[2]]; // keep second encryption subkey only

        const { message: originalCiphertext2 } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKeySecondEncryptionKey
        });
        const transformedCiphertext2 = await testProxyTransform(
            originalCiphertext2,
            proxyParameters[1],
            bobKey.subkeys[2].getKeyID(),
            charlieKey.subkeys[1].getKeyID()
        );
        const { data: decryptedData2 } = await decryptMessage({
            message: await readMessage({ armoredMessage: transformedCiphertext2 }),
            decryptionKeys: charlieKey
        });
        expect(decryptedData2).to.equal(plaintext);
    });

    it('supports forwarding - should return false for key without encryption subkeys', async () => {
        // key one signing subkey (eddsa) and no encryption subkey
        const keyWithoutEncryptionSubkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEZNI7/RMIKoZIzj0DAQcCAwSNFSvjFVNYffbO5XUFvFJ5xESepuHQLQnh
W/tojHJokrXUDoJVAFsuY75WQazg+tijE9lwsqWoHfmx2+ON701pAAEAjlRL
J4b3p99h5PtitDhJ7oOsJ53/NBRnB9WEaWe/B3AQJM0OPHRlc3RAdGVzdC5p
dD7CiQQQEwgAOwWCZNI7/QMLCQcJkOysb71imEtxAxUICgIWAAIZAQKbAwIe
ARYhBDL/D8Jh/QrgN2oaheysb71imEtxAABgZgD/Y1SgPcpCNYjXE6Bl4W2p
VoGwWTQw5v4mfiHSK7qIBD8BAMJh3Yy4JLcOFrP1nHniSqTofzV7/WIhbC4S
4X6P0OJzx3cEZNI7/RMIKoZIzj0DAQcCAwTAEms2toyTFVJxVcVfaR1PTgXF
5b+NPxup3KIl76V0pVnj2MLo9ybrT9FmUtcPpnv0yPbupth574+cmjPuKUad
AAD/YqNbylQRJ1piWpcI49IuTM6ziVFDVYgEn0DnfwqmEI0OqsLALwQYEwgA
oQWCZNI7/QmQ7KxvvWKYS3ECmwJ2oAQZEwgAJwWCZNI7/QmQu8ngLvN7JUsW
IQSYVaNgBswfa0ijOye7yeAu83slSwAAnisA/35TkgN/YOzx7xmuyEB9gU3C
8QamMZYvYNSE3RcyS+fdAQCsrPkmzfOGiRoklhYfw/kVrePu8ZBkWYkv5t8M
tJ0UnxYhBDL/D8Jh/QrgN2oaheysb71imEtxAAASQQEA7Y/Kqi5PO0ippJWt
WVQQHpRSfwBq7E9MwabhzSONxcgA/iosiBLv2PRyLGLdr4Jv3U40c4UK/4vk
yhtWgu8zFVCg
-----END PGP PRIVATE KEY BLOCK-----` });
        expect(await doesKeySupportForwarding(keyWithoutEncryptionSubkey)).to.be.false;
    });

    it('supports forwarding - should return false for encryption subkey without private key material (gnu-dummy)', async () => {
        // key with two ecdh subkeys, one of which does not have private key material (gnu-dummy)
        const keyWithDummySubkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZNI5VxYJKwYBBAHaRw8BAQdAuT2PU1Ud1ouGL/M3IDL0T8Id7VCnJdli
W9kOy7uaYH8AAQC7PMst8kOBnhJr0zWjoKXBiACvWDoS7fy/4qbokPT3BxHn
zQ48dGVzdEB0ZXN0Lml0PsKJBBAWCgA7BYJk0jlXAwsJBwmQ0c3MqmerEnQD
FQgKAhYAAhkBApsDAh4BFiEEUAye1Mg4OC7HGN8X0c3MqmerEnQAADqMAP9f
8C71XjonSBjBX/itYIyzD7Hys6FvKukPwZLCg5bzaAEA9/6uSeuYaDLPzOpI
Cn4d/8Z7O8bDWD3dKKn7mNYNYgjHXQRk0jlXEgorBgEEAZdVAQUBAQdAFT64
s/Pg0veAEzjTmVJVC3qRG2tOLi55CZOeyhLXw20DAQgHAAD/RXHA/5cxbVUm
Y1+kAEgqbMni8ZNx0sKt4gBzoyI8M5gQasJ4BBgWCAAqBYJk0jlXCZDRzcyq
Z6sSdAKbDBYhBFAMntTIODguxxjfF9HNzKpnqxJ0AADD3wD/dC0/pPOOR4bW
n2L4G+VVB8Do/2vGvmlqsDBQEovc9hIBAMa0R31jAD+HaIMmlYGSitA3tfPF
Lo07Y7/piuY3Uh8Ox0AEZNI5VxIKKwYBBAGXVQEFAQEHQJ3zUcuB2xyrZ8gj
wD3yBLsmig1s+V3zNWJPET9C9YcjAwEIB/4JZQBHTlUBwngEGBYIACoFgmTS
OVcJkNHNzKpnqxJ0ApsMFiEEUAye1Mg4OC7HGN8X0c3MqmerEnQAACNMAP90
AxcnmfGjsJHMfjS4Bm7THR5NtVAdCsjjBnJKABbE/wEA5Rqdw2rwo14iIXR4
qEAteMrSvyBNSgSuY4BIpZJNygI=
-----END PGP PRIVATE KEY BLOCK-----` });
        expect(await doesKeySupportForwarding(keyWithDummySubkey)).to.be.false;
    });

    it('supports forwarding - should return false if an encryption subkey is NIST p256', async () => {
        // two ecdh subkeys: one curve25519, one p256
        const keyWithP256Subkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEZNI7SRMIKoZIzj0DAQcCAwRNbEFVQ7/5dkZsMEObzf2bL6bYLg7UmbOL
nC8LG9BWIfEmTH3QNOO2IuJDRyF/WmqpoNXQBuO7Emophg+23x1WAAD+JRQA
cUMAXKtqmey7d06r7EHIYyE/dgZeGo/z0WKmmjcO5M0OPHRlc3RAdGVzdC5p
dD7CiQQQEwgAOwWCZNI7SQMLCQcJkLi5pXUe27CfAxUICgIWAAIZAQKbAwIe
ARYhBEJtG+YOG/wgLGeeOri5pXUe27CfAADxkAEA4dh2u60jIlRo5yMwSBeb
nDEuRrt4M1XNs78OgDkHv0QBALrQuKGEP7UVo5O6Vr0ah91O5VAcC9XxwjtY
xl1CersLx3sEZNI7SRIIKoZIzj0DAQcCAwQTk1ESj08ix1DHXGW4ZQ5KiQNi
KL3z6+KiYnjEDNjsPtH4o0FHS6d5zUmEXZ1xqbGcOmOKZ8YgKyNklYu3T5g1
AwEIBwABAKdySgrgktTT86zgFJRkxpPkNDhMRFpBj9APRJZE1NhlEIPCeAQY
EwgAKgWCZNI7SQmQuLmldR7bsJ8CmwwWIQRCbRvmDhv8ICxnnjq4uaV1Htuw
nwAAwa4BAPslluPut3qHU2h7PB+D93ttxCn/AhSgOc5lUOafZt2VAP91FuPa
8ziVOrUmQTj0eOBjfW0XYIlm7JTERrRlh5S8R8ddBGTSO0kSCisGAQQBl1UB
BQEBB0CrsfLaOT7JAcwc2vg36SSJ6YCXODfvudM9INHNA3kxcQMBCAcAAP9h
0r01q6Jz/KvfNkJXzkvfaAfXOe6GfrFs10QvTvjpwBL4wngEGBMIACoFgmTS
O0kJkLi5pXUe27CfApsMFiEEQm0b5g4b/CAsZ546uLmldR7bsJ8AAGnuAQCF
lAWga4MJBiFLbBiYD7248zu+xmvUAWBU7f/dkHenYAD+K8UCcwQrqeDhCl0q
z5FbOJXSHsoez1SZ7GKgoxC+X0w=
-----END PGP PRIVATE KEY BLOCK-----` });
        expect(await doesKeySupportForwarding(keyWithP256Subkey)).to.be.false;
    });
});
